package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func formFuzzFixture(t *testing.T, target string) (Request, Config) {
	t.Helper()
	root := t.TempDir()
	fixtureDir := filepath.Join(root, "fixtures")
	os.MkdirAll(fixtureDir, 0700)
	body := "name=fixture&tag=one&other=two"
	sum := sha256.Sum256([]byte(body))
	ref := hex.EncodeToString(sum[:])
	os.WriteFile(filepath.Join(fixtureDir, ref+".body"), []byte(body), 0600)
	origin, _ := assessment.ParseApprovedOrigin("app", target)
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	approval := assessment.FuzzApproval{WriteApproval: assessment.WriteApproval{TargetID: "app", Method: "POST", Path: "/items", OperationID: "create", FixtureRef: ref, ContentType: "application/x-www-form-urlencoded", CleanupMethod: "DELETE", CleanupPath: "/items/fixture"}, Scanner: "wapiti", RequestLimit: 3, RepeatTestingApproved: true}
	req := Request{Target: target, WorkflowVersion: "unified-v1", TypedAssessment: true, TestEnvironment: true, Scope: "app:app", ScanDir: filepath.Join(root, "attempt"), WriteJournalDir: root, APIFixtureDir: fixtureDir, AppScope: &scope, WapitiPostApproval: &approval, APIOperationEndpoints: []APIEndpoint{{TargetID: "app", Method: "POST", Path: "/items", OperationID: "create", Source: "openapi"}}}
	return req, Config{APIFixtureDir: fixtureDir, WapitiPath: "wapiti"}
}

func TestFormFuzzGatewayNeedsJournalArmingAndEnforcesAtomicBudget(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	req, _ := formFuzzFixture(t, "https://app.test/")
	if err := prepareWapitiPostRequest(&req, nil); err != nil {
		t.Fatal(err)
	}
	gateway := &RecordingGateway{req: req}
	if gateway.admitFormFuzz(req.WapitiPostURL, req.WapitiPostApproval.ContentType, []byte(req.WapitiPostBody)) {
		t.Fatal("POST admitted before journal intent")
	}
	gateway.ArmFormFuzz()
	for _, tc := range []struct{ url, kind, body string }{{"https://alias.test/items", "application/x-www-form-urlencoded", req.WapitiPostBody}, {req.WapitiPostURL, "application/json", `{"name":"fixture"}`}, {req.WapitiPostURL, req.WapitiPostApproval.ContentType, "name=fixture&tag=one"}, {req.WapitiPostURL, req.WapitiPostApproval.ContentType, req.WapitiPostBody + "&new=field"}} {
		if gateway.admitFormFuzz(tc.url, tc.kind, []byte(tc.body)) {
			t.Fatal("unsupported POST admitted")
		}
	}
	admitted := 0
	var mu sync.Mutex
	var workers sync.WaitGroup
	for i := 0; i < 50; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if gateway.admitFormFuzz(req.WapitiPostURL, req.WapitiPostApproval.ContentType, []byte("name=payload&tag=one&other=two")) {
				mu.Lock()
				admitted++
				gateway.formFuzzInFlight.Done()
				mu.Unlock()
			}
		}()
	}
	workers.Wait()
	if admitted != 3 {
		t.Fatalf("concurrent budget bypass: %d", admitted)
	}
}

func TestApprovedFormFuzzHasReviewedPostModulesAndPrivateBodyManifest(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	req, cfg := formFuzzFixture(t, "https://app.test/")
	if err := prepareWapitiPostRequest(&req, nil); err != nil {
		t.Fatal(err)
	}
	spec := buildWapitiPost(req, cfg)
	args := strings.Join(spec.args, " ")
	if spec.notApp != "" || !strings.Contains(args, "--data name=fixture&tag=one&other=two") || !strings.Contains(args, wapitiPostModules) || strings.Contains(args, ":get") {
		t.Fatalf("unsupported native input: %+v", spec)
	}
	path, err := SaveScannerInputs(req, "wapiti")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "name=fixture") || !strings.Contains(string(data), `"method": "POST"`) || !strings.Contains(string(data), req.InputRequests[0].BodyDigest) {
		t.Fatalf("fixture exposed or exact input missing: %s", data)
	}
	req.WapitiPostApproval.RepeatTestingApproved = false
	if prepareWapitiPostRequest(&req, nil) == nil {
		t.Fatal("single-write consent treated as fuzz consent")
	}
}

func TestFormFuzzRefusesReplayAfterProcessAndCleanup(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	cleanup := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			cleanup++
		}
		w.WriteHeader(204)
	}))
	defer target.Close()
	req, cfg := formFuzzFixture(t, target.URL+"/")
	if err := prepareWapitiPostRequest(&req, nil); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(t.TempDir(), "wapiti")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nwhile [ \"$1\" != \"-o\" ]; do shift; done\nshift\nprintf '%s' '{\"vulnerabilities\":{},\"classifications\":{}}' > \"$1\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	cfg.WapitiPath = fake
	req.Gateway = &RecordingGateway{req: req}
	req.GatewayURL = "http://unused-fixture-proxy:1"
	first := runWapitiPost(context.Background(), req, cfg, nil)
	if first.Status != "completed" || first.Outcome != "PARTIAL" || cleanup != 1 {
		t.Fatalf("declared cleanup missing: %+v cleanup=%d", first, cleanup)
	}
	entries, err := LoadWriteJournal(req.WriteJournalDir)
	if err != nil || len(entries) != 1 || entries[0].State != WriteStateCleanupDone {
		t.Fatalf("campaign journal missing: %+v %v", entries, err)
	}
	second := runWapitiPost(context.Background(), req, cfg, nil)
	if second.Status != "failed" || !strings.Contains(second.Reason, "replay") || cleanup != 1 {
		t.Fatalf("fuzz consent replayed: %+v cleanup=%d", second, cleanup)
	}
	// Direct gateway admission stays method/path/content/shape-bound.
	parsed, _ := url.Parse(req.WapitiPostURL)
	if parsed.Path != "/items" {
		t.Fatal("path changed")
	}
}

func TestWapitiFormFixturePreservesNativeSemantics(t *testing.T) {
	for _, body := range []string{"name=a%20b", "tag=one&tag=two", "name=a+b", "name", "name=a=b"} {
		if wapitiPreservesFormFixture(body) {
			t.Fatalf("accepted altered native form: %s", body)
		}
	}
	if !wapitiPreservesFormFixture("name=fixture&tag=one&other=two") {
		t.Fatal("rejected exact native fixture")
	}
}

func TestFormFuzzPlanningKeepsApprovalOnDefaultIdentityAndWriteStage(t *testing.T) {
	req, _ := formFuzzFixture(t, "https://app.test/")
	cfg := assessment.AssessmentConfig{WorkflowVersion: "unified-v1", FuzzApprovals: []assessment.FuzzApproval{*req.WapitiPostApproval}, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: req.Target}}, Access: []assessment.AccessBinding{{TargetIDs: []string{"app"}, Kind: assessment.AccessBearerToken, Identity: "owner"}, {TargetIDs: []string{"app"}, Kind: assessment.AccessBearerToken, Identity: "reader"}}}
	jobs := appendFuzzJobs(cfg, nil, map[string]bool{"wapiti": true})
	jobs = expandIdentityJobs(cfg, jobs)
	assignStages(jobs)
	if len(jobs) != 1 || jobs[0].Stage != StageWrite || jobs[0].AuthContextID != "" || jobs[0].FuzzApprovalID == "" {
		t.Fatalf("approval expanded across roles or stages: %+v", jobs)
	}
	unavailable := appendFuzzJobs(cfg, nil, map[string]bool{"wapiti": false})
	if unavailable[0].State != PlanUnavailable {
		t.Fatal("missing binary counted as available")
	}
}

func TestFormFuzzRejectsIncompatibleSchemaAndNativeFixture(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	req, _ := formFuzzFixture(t, "https://app.test/")
	req.APIOperationEndpoints[0].RequestBodyContentTypes = []string{"application/json"}
	if prepareWapitiPostRequest(&req, nil) == nil {
		t.Fatal("JSON-only operation sent as form")
	}
	for _, body := range []string{"tag=one&tag=two", "name=a%20b", strings.Repeat("x", (64<<10)+1)} {
		if ValidateWapitiFormFixture([]byte(body)) == nil {
			t.Fatal("incompatible fixture accepted")
		}
	}
}
