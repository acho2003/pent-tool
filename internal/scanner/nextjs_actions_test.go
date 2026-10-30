package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/apifixture"
	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

type nextjsActionLab struct {
	mu                     sync.Mutex
	changed                bool
	identityBug, originBug bool
	mode                   string
	posts, cleanups, hits  int
}

func (lab *nextjsActionLab) handler(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	lab.mu.Lock()
	defer lab.mu.Unlock()
	if lab.mode == "fail-second-cleanup" && lab.posts >= 2 {
		lab.mode = "cleanup-fails"
	}
	lab.hits++
	auth := r.Header.Get("Authorization")
	if r.Header.Get("Cookie") != "" {
		t.Error("global cookie reached action lab")
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/fixture-state":
		if auth != "Bearer owner-test-secret" {
			t.Error("state verification used the acting identity")
		}
		w.Header().Set("Content-Type", "application/json")
		if lab.changed {
			w.Write([]byte(`{"state":"CONTROLLED_CHANGED_42"}`))
		} else {
			w.Write([]byte(`{"state":"CONTROLLED_READY_42"}`))
		}
	case r.Method == "POST" && r.URL.Path == "/account":
		lab.posts++
		body, _ := io.ReadAll(r.Body)
		if string(body) != `["CONTROLLED_INPUT_42"]` || r.Header.Get("Next-Action") != strings.Repeat("a", 40) || r.Header.Get("Accept") != "text/x-component" {
			t.Errorf("wrong observed action request: %s %v", body, r.Header)
		}
		if lab.mode == "redirect" {
			http.Redirect(w, r, "/unexpected", 302)
			return
		}
		allowed := auth == "Bearer owner-test-secret"
		if r.Header.Get("Origin") == nextjsForeignOrigin {
			allowed = lab.originBug
		} else if auth != "Bearer owner-test-secret" {
			allowed = lab.identityBug
		}
		if !allowed {
			http.Error(w, "denied", 403)
			return
		}
		if lab.mode != "baseline-noop" {
			lab.changed = true
		}
		if lab.mode == "action-network-fails" {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Fatal(err)
			}
			connection.Close()
			return
		}
		w.Header().Set("Content-Type", "text/x-component")
		w.Write([]byte("0:CONTROLLED_RESPONSE_WITH_NO_AUTHORITY"))
	case r.Method == "DELETE" && r.URL.Path == "/fixture-reset":
		lab.cleanups++
		if auth != "Bearer owner-test-secret" {
			t.Error("cleanup used the acting identity")
		}
		if lab.mode == "cleanup-fails" {
			http.Error(w, "reset unavailable", 500)
			return
		}
		if lab.mode != "cleanup-lies" {
			lab.changed = false
		}
		w.WriteHeader(204)
	default:
		t.Errorf("unexpected request or followed redirect: %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

// HTTP connection failure can wake the client before the handler returns.
// Establish a happens-before edge before inspecting fixture state.
func (lab *nextjsActionLab) wait() { lab.mu.Lock(); lab.mu.Unlock() }

func actionFixture(t *testing.T, base string) (Request, Config) {
	t.Helper()
	store := apifixture.Store{Dir: t.TempDir()}
	body, err := store.Put(strings.NewReader(`["CONTROLLED_INPUT_42"]`), "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	f := NextjsActionFixture{URL: base + "/account", ActionID: strings.Repeat("a", 40), BodyRef: body.Ref, ContentType: "text/plain;charset=UTF-8", VerificationURL: base + "/fixture-state", ReadyMarker: "CONTROLLED_READY_42", ChangedMarker: "CONTROLLED_CHANGED_42", CleanupURL: base + "/fixture-reset", CleanupMethod: "DELETE"}
	raw, _ := json.Marshal(f)
	manifest, err := store.Put(bytes.NewReader(raw), "application/json")
	if err != nil {
		t.Fatal(err)
	}
	req := nextjsTestRequest(t, base+"/")
	req.TargetID, req.WorkflowVersion, req.TestEnvironment = "app", "unified-v1", true
	req.APIFixtureDir, req.WriteJournalDir = store.Dir, t.TempDir()
	req.NextjsActionApprovals = []assessment.NextjsActionApproval{{ID: "controlled-action", TargetID: "app", FixtureRef: manifest.Ref, OwnerIdentity: "owner", Cases: []assessment.NextjsActionCase{
		{ID: "baseline", Identity: "owner", Expect: "allow"},
		{ID: "other-user", Identity: "reader", Expect: "deny"},
		{ID: "anonymous", Identity: "anonymous", Expect: "deny"},
		{ID: "foreign-origin", Identity: "owner", Expect: "deny", CrossOrigin: true},
	}}}
	for _, name := range []string{"owner", "reader"} {
		req.AuthContexts = append(req.AuthContexts, AuthContext{ID: AuthenticationContextID("app", name), TargetID: "app", Identity: name, Role: name, State: assessment.StateVerified, Headers: []string{"Authorization: Bearer " + name + "-test-secret"}, Refresh: func(_ context.Context, headers []string) ([]string, error) { return headers, nil }})
	}
	req.TargetAuth = "Authorization: PRIMARY_MUST_NOT_BE_USED"
	return req, Config{Budget: NewAssessmentBudget(0, 100, 0), ScanHeaders: []string{"Cookie: GLOBAL_MUST_NOT_BE_USED"}}
}

func TestNextjsActionControlledIdentityAndOriginFindings(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	for _, mode := range []string{"patched", "identity-bug", "origin-bug"} {
		t.Run(mode, func(t *testing.T) {
			lab := &nextjsActionLab{identityBug: mode == "identity-bug", originBug: mode == "origin-bug"}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { lab.handler(t, w, r) }))
			defer server.Close()
			req, cfg := actionFixture(t, server.URL)
			run := (nextjsActionsRunner{}).Run(t.Context(), req, cfg, nil)
			lab.wait()
			if run.Status != "completed" || len(run.AuthorizationResults) != 4 || lab.posts != 4 || lab.cleanups != 4 || lab.changed {
				t.Fatalf("run=%+v lab=%+v", run, lab)
			}
			findings, err := ParseRun(run)
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]int{"patched": 0, "identity-bug": 2, "origin-bug": 1}[mode]
			if len(findings) != want {
				t.Fatalf("findings=%+v want=%d", findings, want)
			}
			for _, f := range findings {
				if f.Confidence != "confirmed" || f.EvidenceRef == "" || f.Severity != "high" {
					t.Fatalf("finding lacks proof: %+v", f)
				}
			}
			events, err := ReadCoverageEvents(run.CoverageEventsPath)
			if err != nil {
				t.Fatal(err)
			}
			active := 0
			for _, event := range events {
				if event.Phase == "active_test" && event.Kind == "observed" {
					active++
					if len(event.EndpointIDs) != 1 || event.Method != "POST" {
						t.Fatalf("wrong active receipt: %+v", event)
					}
				}
			}
			if active != 4 {
				t.Fatalf("active cases=%d", active)
			}
			journal, err := LoadWriteJournal(req.WriteJournalDir)
			if err != nil || len(journal) != 4 {
				t.Fatalf("journal=%+v err=%v", journal, err)
			}
			for _, entry := range journal {
				if entry.State != WriteStateCleanupDone {
					t.Fatalf("unverified cleanup: %+v", entry)
				}
			}
			for _, path := range []string{run.ArtifactPath, run.CoverageEventsPath, filepath.Join(filepath.Dir(run.ArtifactPath), "action-results.jsonl"), WriteJournalPath(req.WriteJournalDir)} {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				for _, secret := range []string{"owner-test-secret", "reader-test-secret", "CONTROLLED_INPUT_42", "CONTROLLED_READY_42", "CONTROLLED_CHANGED_42", "PRIMARY_MUST_NOT_BE_USED", "GLOBAL_MUST_NOT_BE_USED"} {
					if strings.Contains(string(data), secret) {
						t.Fatalf("secret retained in %s", path)
					}
				}
			}
			req.ScanDir = t.TempDir()
			again := (nextjsActionsRunner{}).Run(t.Context(), req, cfg, nil)
			lab.wait()
			if again.Status != "failed" || lab.posts != 4 || lab.cleanups != 4 {
				t.Fatalf("campaign replayed: %+v %+v", again, lab)
			}
		})
	}
}

func TestNextjsActionStopsOnMissingBaselineAndUnverifiedCleanup(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	for _, mode := range []string{"baseline-noop", "cleanup-fails", "cleanup-lies", "redirect", "not-ready"} {
		t.Run(mode, func(t *testing.T) {
			lab := &nextjsActionLab{mode: mode, changed: mode == "not-ready"}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { lab.handler(t, w, r) }))
			defer server.Close()
			req, cfg := actionFixture(t, server.URL)
			run := (nextjsActionsRunner{}).Run(t.Context(), req, cfg, nil)
			lab.wait()
			if run.Status != "failed" || lab.posts > 1 || len(run.AuthorizationResults) != 1 {
				t.Fatalf("campaign did not stop: %+v lab=%+v", run, lab)
			}
			if mode == "not-ready" && lab.posts != 0 {
				t.Fatal("action sent against an unready resource")
			}
			findings, err := ParseRun(run)
			if err != nil || len(findings) != 0 {
				t.Fatalf("false finding: %+v %v", findings, err)
			}
		})
	}
}

func TestNextjsActionRefusesInvalidApprovalsBeforeNetwork(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	for _, mode := range []string{"not-typed", "not-test", "not-expanded", "wrong-target", "wrong-owner-target", "missing-cleanup-fixture", "missing-manifest", "excluded-cleanup", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			hits := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; t.Error("invalid campaign reached network") }))
			defer server.Close()
			req, cfg := actionFixture(t, server.URL)
			switch mode {
			case "not-typed":
				req.TypedAssessment = false
			case "not-test":
				req.TestEnvironment = false
			case "not-expanded":
				req.WorkflowVersion = ""
			case "wrong-target":
				req.TargetID = "other"
			case "wrong-owner-target":
				req.AuthContexts[0].TargetID = "other"
			case "missing-manifest":
				req.NextjsActionApprovals[0].FixtureRef = strings.Repeat("f", 64)
			case "missing-cleanup-fixture":
				raw, _ := readAPIFixture(req.APIFixtureDir, req.NextjsActionApprovals[0].FixtureRef)
				var f NextjsActionFixture
				json.Unmarshal(raw, &f)
				f.CleanupMethod, f.CleanupBodyRef, f.CleanupContentType = "PUT", strings.Repeat("f", 64), "application/json"
				updated, _ := json.Marshal(f)
				meta, err := (apifixture.Store{Dir: req.APIFixtureDir}).Put(bytes.NewReader(updated), "application/json")
				if err != nil {
					t.Fatal(err)
				}
				req.NextjsActionApprovals[0].FixtureRef = meta.Ref
			case "excluded-cleanup":
				scope := assessment.NewAppScope(req.AppScope.Origins(), assessment.Exclusion{Method: "DELETE", PathPattern: "/fixture-reset"})
				req.AppScope = &scope
			case "disabled":
				t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "0")
			}
			run := (nextjsActionsRunner{}).Run(t.Context(), req, cfg, nil)
			if hits != 0 || run.Status != "failed" {
				t.Fatalf("gate failure hits=%d run=%+v", hits, run)
			}
		})
	}
}

func TestNextjsActionCleanupFailureRetainsAlreadyConfirmedFinding(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	lab := &nextjsActionLab{identityBug: true, mode: "fail-second-cleanup"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { lab.handler(t, w, r) }))
	defer server.Close()
	req, cfg := actionFixture(t, server.URL)
	run := (nextjsActionsRunner{}).Run(t.Context(), req, cfg, nil)
	lab.wait()
	findings, err := ParseRun(run)
	if run.Status != "failed" || run.GapKind != GapInterruptedWrite || lab.posts != 2 || err != nil || len(findings) != 1 {
		t.Fatalf("lost partial confirmed evidence: run=%+v findings=%+v err=%v", run, findings, err)
	}
}

func TestNextjsActionManifestRefusesUnsupportedBodiesAndScopeExpansion(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	req, _ := actionFixture(t, "https://app.test")
	raw, err := readAPIFixture(req.APIFixtureDir, req.NextjsActionApprovals[0].FixtureRef)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"foreign-action", "foreign-cleanup", "userinfo", "fragment", "unsupported-type", "fake-id", "ambiguous-markers", "write-get", "missing-cleanup-body", "unknown-field"} {
		t.Run(mode, func(t *testing.T) {
			var f NextjsActionFixture
			json.Unmarshal(raw, &f)
			switch mode {
			case "foreign-action":
				f.URL = "https://other.test/account"
			case "foreign-cleanup":
				f.CleanupURL = "http://169.254.169.254/reset"
			case "userinfo":
				f.URL = "https://secret:secret@app.test/account"
			case "fragment":
				f.URL += "#state"
			case "unsupported-type":
				f.ContentType = "multipart/form-data"
			case "fake-id":
				f.ActionID = "guessed-action"
			case "ambiguous-markers":
				f.ChangedMarker = f.ReadyMarker + "_CHANGED"
			case "write-get":
				f.VerificationURL = "https://app.test/delete"
			case "missing-cleanup-body":
				f.CleanupMethod = "PUT"
			}
			data, _ := json.Marshal(f)
			if mode == "unknown-field" {
				data = append(data[:len(data)-1], []byte(`,"headers":{"Host":"other.test"}}`)...)
			}
			if _, err := ValidateNextjsActionManifest(data, req.Target, *req.AppScope); err == nil {
				t.Fatal("unsafe manifest accepted")
			}
		})
	}
}

func TestNextjsActionPlanOnlySchedulesExplicitApprovalsAndBindsCases(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	req, _ := actionFixture(t, "https://app.test")
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeGrayBox, TestEnvironment: true, WorkflowVersion: "unified-v1", Types: []assessment.Type{assessment.TypeWebApplication}, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: req.Target}}, NextjsActionApprovals: req.NextjsActionApprovals}
	for _, auth := range req.AuthContexts {
		cfg.Access = append(cfg.Access, assessment.AccessBinding{Identity: auth.Identity, TargetIDs: []string{"app"}, Kind: assessment.AccessBearerToken, CredentialID: auth.Identity})
	}
	plan := PlanAssessment(PlanInput{Config: cfg})
	if len(plan.Errors) > 0 {
		t.Fatalf("plan errors: %+v", plan.Errors)
	}
	found := false
	for _, job := range plan.Jobs {
		if job.Scanner == "nextjs-actions" {
			found = true
			if job.Stage != StageWrite || job.AuthContextID != "" {
				t.Fatalf("action cases were independently duplicated or mis-staged: %+v", job)
			}
		}
	}
	if !found {
		t.Fatal("explicit campaign was not scheduled")
	}
	cfg.NextjsActionApprovals[0].Cases[1].ID = "different-approved-case"
	changed := PlanAssessment(PlanInput{Config: cfg})
	if changed.Fingerprint == plan.Fingerprint {
		t.Fatal("approved cases were not fingerprinted")
	}
	cfg.NextjsActionApprovals = nil
	cfg.Profile = ProfileNextjsDeep
	automatic := PlanAssessment(PlanInput{Config: cfg})
	for _, job := range automatic.Jobs {
		if job.Scanner == "nextjs-actions" {
			t.Fatal("profile automatically authorized action writes")
		}
	}
}

func TestAssessmentExecutorRoutesServerActionCampaignWithoutInventedAPISchema(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	lab := &nextjsActionLab{identityBug: true}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { lab.handler(t, w, r) }))
	defer server.Close()
	req, cfg := actionFixture(t, server.URL)
	cfg.KatanaPath, cfg.WebBrowser = "/nonexistent/katana", false
	cfg.AssessmentAuthContexts, cfg.APIFixtureDir = req.AuthContexts, req.APIFixtureDir
	target := assessment.Target{ID: "app", Kind: assessment.KindURL, Value: req.Target}
	plan := AssessmentPlan{Fingerprint: "approved-nextjs-actions", Config: assessment.AssessmentConfig{WorkflowVersion: "unified-v1", TestEnvironment: true, Targets: []assessment.Target{target}, Types: []assessment.Type{assessment.TypeWebApplication}, NextjsActionApprovals: req.NextjsActionApprovals}, Jobs: []PlanJob{{ID: "actions", Scanner: "nextjs-actions", TargetID: "app", Target: req.Target, State: PlanSelected, Variant: "nextjs-actions", Stage: StageWrite}}}
	pipeline := Pipeline{Config: cfg}
	for _, run := range pipeline.RunAssessmentJobs(t.Context(), plan, t.TempDir(), nil, nil) {
		lab.wait()
		if run.Scanner != "nextjs-actions" {
			continue
		}
		if run.Status != "completed" || len(run.AuthorizationResults) != 4 || lab.posts != 4 {
			t.Fatalf("executor lost approvals or contexts: %+v", run)
		}
		manifest, err := os.ReadFile(run.InputManifestPath)
		if err != nil {
			t.Fatal(err)
		}
		var inputs ScannerInputManifest
		if err := json.Unmarshal(manifest, &inputs); err != nil || len(inputs.Requests) != 4 {
			t.Fatalf("approved action variants missing from input manifest: %s %v", manifest, err)
		}
		return
	}
	t.Fatal("action job was not executed")
}

func TestNextjsActionUnknownWriteOutcomeNeverRetriesOrClearsIntent(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	lab := &nextjsActionLab{mode: "action-network-fails"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { lab.handler(t, w, r) }))
	defer server.Close()
	req, cfg := actionFixture(t, server.URL)
	run := (nextjsActionsRunner{}).Run(t.Context(), req, cfg, nil)
	lab.wait()
	if run.Status != "failed" || run.GapKind != GapInterruptedWrite || lab.posts != 1 || lab.cleanups != 0 || !strings.Contains(run.Reason, "manual cleanup") {
		t.Fatalf("unsafe recovery: %+v lab=%+v", run, lab)
	}
	entries, err := LoadWriteJournal(req.WriteJournalDir)
	if err != nil || len(entries) != 1 || entries[0].State != WriteStateIntent {
		t.Fatalf("lost uncertain write: %+v %v", entries, err)
	}
	req.ScanDir = t.TempDir()
	again := (nextjsActionsRunner{}).Run(t.Context(), req, cfg, nil)
	lab.wait()
	if again.Status != "failed" || lab.posts != 1 {
		t.Fatal("unknown action was replayed")
	}
}

func TestNextjsActionBudgetOrCancellationStopsRemainingCases(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	for _, mode := range []string{"cancelled", "endpoint-cap", "expired"} {
		t.Run(mode, func(t *testing.T) {
			lab := &nextjsActionLab{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { lab.handler(t, w, r) }))
			defer server.Close()
			req, cfg := actionFixture(t, server.URL)
			ctx := t.Context()
			switch mode {
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "endpoint-cap":
				cfg.Budget = NewAssessmentBudget(0, 1, 0)
			case "expired":
				req.AuthContexts[0].Refresh = func(context.Context, []string) ([]string, error) { return nil, context.Canceled }
			}
			run := (nextjsActionsRunner{}).Run(ctx, req, cfg, nil)
			lab.wait()
			if run.Status != "failed" || lab.posts != 0 {
				t.Fatalf("action escaped gate: %+v lab=%+v", run, lab)
			}
		})
	}
}
