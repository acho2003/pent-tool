package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/credentials"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

func TestScannerStatusListsCatalog(t *testing.T) {
	s := newTestServer(t, nil)
	rr := httptest.NewRecorder()
	s.handleScannerStatus(rr, httptest.NewRequest(http.MethodGet, "/api/scanners/status", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	// The webui client parses JSON only when the response says so; without
	// this header the page silently receives a string and lists no tools.
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var body struct {
		Scanners []struct {
			Name       string `json:"name"`
			Phase      string `json:"phase"`
			Selectable bool   `json:"selectable"`
			Summary    string `json:"summary"`
			Available  *bool  `json:"available"`
		} `json:"scanners"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, sc := range body.Scanners {
		names = append(names, sc.Name)
		if sc.Phase == "" || sc.Summary == "" || sc.Available == nil {
			t.Errorf("%s missing phase/summary/available: %+v", sc.Name, sc)
		}
	}
	want := []string{"subfinder", "httpx", "nmap", "nuclei", "zap", "testssl", "openvas", "vuls", "trivy", "semgrep", "gitleaks", "osv"}
	if !slices.Equal(names, want) {
		t.Fatalf("names = %v, want %v", names, want)
	}
	if body.Scanners[0].Selectable || !body.Scanners[3].Selectable {
		t.Fatalf("recon must not be selectable, nuclei must be: %+v", body.Scanners[:4])
	}
}

func TestScannerRegistryReflectsConfiguredNiktoAvailability(t *testing.T) {
	s := newTestServer(t, nil)
	s.cfg.NiktoPath = "/usr/bin/true"
	rr := httptest.NewRecorder()
	s.handleScannerRegistry(rr, httptest.NewRequest(http.MethodGet, "/api/scanners/registry", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Scanners []struct {
			ID               string `json:"id"`
			Available        bool   `json:"available"`
			DefaultSelection string `json:"default_selection"`
		} `json:"scanners"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, definition := range body.Scanners {
		if definition.ID == "nikto" {
			if !definition.Available || definition.DefaultSelection != "optional" {
				t.Fatalf("Nikto registry definition = %+v", definition)
			}
			return
		}
	}
	t.Fatal("Nikto registry definition not returned")
}

func TestAssessmentPlanPreviewReturnsReasonsAndDoesNotStartScan(t *testing.T) {
	s := newTestServer(t, nil)
	body := `{"assessment_mode":"BLACK_BOX","assessment_types":["NETWORK"],"assessment_targets":[{"id":"host","type":"IP","value":"192.0.2.10"}]}`
	rr := httptest.NewRecorder()
	s.handleAssessmentPlan(rr, httptest.NewRequest(http.MethodPost, "/api/scans/plan", strings.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var plan struct {
		Fingerprint string `json:"fingerprint"`
		Decisions   []struct {
			Scanner string `json:"scanner"`
			State   string `json:"state"`
			Reason  string `json:"reason"`
		} `json:"decisions"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Fingerprint == "" || len(plan.Decisions) == 0 {
		t.Fatalf("incomplete plan: %+v", plan)
	}
	for _, d := range plan.Decisions {
		if d.Reason == "" {
			t.Errorf("decision has no reason: %+v", d)
		}
	}
	if len(s.instances) != 0 {
		t.Fatal("plan preview created a scan instance")
	}
}

func TestTypedPlanMarksLegacyReconStubsUnavailable(t *testing.T) {
	s := newTestServer(t, nil)
	plan := s.buildAssessmentPlan(assessment.AssessmentConfig{
		Mode: assessment.ModeBlackBox, Types: []assessment.Type{assessment.TypeNetwork},
		Targets: []assessment.Target{{ID: "host", Kind: assessment.KindIP, Value: "192.0.2.10"}},
	})
	// nmap has no scoped assessment adapter yet, so a typed plan must still
	// explain it as unavailable and never emit a non-executable job.
	if !slices.ContainsFunc(plan.Decisions, func(d scanner.PlanDecision) bool {
		return d.Scanner == "nmap" && d.State == scanner.PlanUnavailable && strings.Contains(d.Reason, "unavailable")
	}) {
		t.Fatalf("typed plan must explain missing direct nmap adapter: %+v", plan.Decisions)
	}
	// Discovery tools (subfinder/httpx/katana) run implicitly — recon and the
	// katana crawl stage — so they are excluded from coverage decisions entirely
	// (no false "unavailable" gap) and never emit a job.
	for _, id := range []string{"katana"} {
		if slices.ContainsFunc(plan.Decisions, func(d scanner.PlanDecision) bool { return d.Scanner == id }) {
			t.Errorf("discovery tool %s must not appear as a coverage decision: %+v", id, plan.Decisions)
		}
	}
	for _, id := range []string{"httpx", "nmap"} {
		if slices.ContainsFunc(plan.Jobs, func(job scanner.PlanJob) bool { return job.Scanner == id }) {
			t.Fatalf("typed plan emitted non-executable %s job", id)
		}
	}
}

func TestAssessmentPlanDoesNotTreatSharedZAPAsTypedCapability(t *testing.T) {
	s := newTestServer(t, nil)
	s.cfg.ZAPURL = "http://zap.internal:8080"
	s.cfg.ZAPDedicated = false
	body := `{"assessment_mode":"BLACK_BOX","assessment_types":["WEB_APPLICATION"],"assessment_targets":[{"id":"app","type":"URL","value":"https://app.example.test/"}]}`
	rr := httptest.NewRecorder()
	s.handleAssessmentPlan(rr, httptest.NewRequest(http.MethodPost, "/api/scans/plan", strings.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var plan struct {
		Decisions []struct {
			Scanner  string `json:"scanner"`
			TargetID string `json:"target_id"`
			State    string `json:"state"`
			Reason   string `json:"reason"`
		} `json:"decisions"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(plan.Decisions, func(d struct {
		Scanner  string `json:"scanner"`
		TargetID string `json:"target_id"`
		State    string `json:"state"`
		Reason   string `json:"reason"`
	}) bool {
		return d.Scanner == "zap" && d.TargetID == "app" && d.State == "unavailable" && strings.Contains(d.Reason, "unavailable")
	}) {
		t.Fatalf("shared ZAP daemon was advertised as a typed scanner: %+v", plan.Decisions)
	}
}

func TestAssessmentPlanRejectsInvalidConfiguration(t *testing.T) {
	s := newTestServer(t, nil)
	rr := httptest.NewRecorder()
	s.handleAssessmentPlan(rr, httptest.NewRequest(http.MethodPost, "/api/scans/plan", strings.NewReader(`{"assessment_mode":"BLACK_BOX"}`)))
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestAssessmentPlanBindsUploadedAPIEndpointsToExplicitTargetOrigin(t *testing.T) {
	s := newTestServer(t, nil)
	spec := `{"openapi":"3.0.0","servers":[{"url":"https://other.example.test"}],"paths":{"/users":{"get":{}},"/items":{"post":{}}}}`
	upload := httptest.NewRecorder()
	s.handleAPIDefinitions(upload, httptest.NewRequest(http.MethodPost, "/api/api-definitions", strings.NewReader(spec)))
	if upload.Code != http.StatusCreated {
		t.Fatalf("upload status=%d body=%s", upload.Code, upload.Body.String())
	}
	var metadata apiDefinitionMetadata
	if err := json.Unmarshal(upload.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	request := `{"assessment_mode":"BLACK_BOX","assessment_types":["API"],"assessment_targets":[{"id":"api","type":"URL","value":"https://inside.example.test:8443/v1"}],"api_definitions":[{"target_id":"api","definition_id":"` + metadata.ID + `"}]}`
	planned := httptest.NewRecorder()
	s.handleAssessmentPlan(planned, httptest.NewRequest(http.MethodPost, "/api/scans/plan", strings.NewReader(request)))
	if planned.Code != http.StatusOK {
		t.Fatalf("plan status=%d body=%s", planned.Code, planned.Body.String())
	}
	var plan struct {
		APIEndpoints []scanner.APIEndpoint `json:"api_endpoints"`
	}
	if err := json.Unmarshal(planned.Body.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.APIEndpoints) != 2 {
		t.Fatalf("API inventory=%+v", plan.APIEndpoints)
	}
	for _, endpoint := range plan.APIEndpoints {
		if endpoint.TargetID != "api" || endpoint.Origin != "https://inside.example.test:8443/v1" || strings.Contains(endpoint.Origin, "other.example.test") {
			t.Fatalf("spec server expanded target mapping: %+v", endpoint)
		}
	}
}

func TestAssessmentPlanMaterializesSuppliedOpenAPIPathAndQueryInputs(t *testing.T) {
	s := newTestServer(t, nil)
	spec := `{"openapi":"3.1.0","paths":{"/users/{userId}":{"get":{"operationId":"getUser","parameters":[{"name":"userId","in":"path","required":true},{"name":"filter","in":"query","required":true}]}}}}`
	upload := httptest.NewRecorder()
	s.handleAPIDefinitions(upload, httptest.NewRequest(http.MethodPost, "/api/api-definitions", strings.NewReader(spec)))
	var metadata apiDefinitionMetadata
	if err := json.Unmarshal(upload.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	cfg := assessment.AssessmentConfig{
		Mode: assessment.ModeBlackBox, Types: []assessment.Type{assessment.TypeAPI},
		Targets:            []assessment.Target{{ID: "api", Kind: assessment.KindURL, Value: "https://inside.example.test/v1"}},
		APIDefinitions:     []assessment.APIDefinitionBinding{{TargetID: "api", DefinitionID: metadata.ID}},
		APIOperationInputs: []assessment.APIOperationInput{{DefinitionID: metadata.ID, OperationID: "getUser", PathParams: map[string]string{"userId": "42"}, Query: map[string]string{"filter": "active"}}},
	}
	plan := s.buildAssessmentPlan(cfg)
	if len(plan.Errors) != 0 || len(plan.APIEndpoints) != 1 {
		t.Fatalf("plan errors=%+v endpoints=%+v", plan.Errors, plan.APIEndpoints)
	}
	endpoint := plan.APIEndpoints[0]
	if !endpoint.Resolved || !endpoint.Eligible || endpoint.Path != "/users/{userId}" || endpoint.RequestURL != "https://inside.example.test/v1/users/42?filter=active" {
		t.Fatalf("endpoint input not materialized: %+v", endpoint)
	}
	cfg.APIOperationInputs[0].OperationID = "unknown"
	plan = s.buildAssessmentPlan(cfg)
	if !slices.ContainsFunc(plan.Errors, func(problem assessment.Problem) bool { return problem.Code == "api_input.operation_unknown" }) {
		t.Fatalf("unknown input operation was not rejected: %+v", plan.Errors)
	}
}

func TestAssessmentPlanRejectsWriteApprovalNotInBoundOpenAPI(t *testing.T) {
	s := newTestServer(t, nil)
	spec := `{"openapi":"3.0.0","paths":{"/items":{"post":{"operationId":"createItem"}}}}`
	upload := httptest.NewRecorder()
	s.handleAPIDefinitions(upload, httptest.NewRequest(http.MethodPost, "/api/api-definitions", strings.NewReader(spec)))
	var metadata apiDefinitionMetadata
	if err := json.Unmarshal(upload.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	cfg := assessment.AssessmentConfig{
		Mode: assessment.ModeGrayBox, Types: []assessment.Type{assessment.TypeAPI}, TestEnvironment: true,
		Targets:        []assessment.Target{{ID: "api", Kind: assessment.KindURL, Value: "https://inside.example.test/v1"}},
		APIDefinitions: []assessment.APIDefinitionBinding{{TargetID: "api", DefinitionID: metadata.ID}},
		WriteApprovals: []assessment.WriteApproval{{TargetID: "api", Method: http.MethodPost, Path: "/items", OperationID: "differentOperation", FixtureRef: strings.Repeat("a", 64), ContentType: "application/json", CleanupMethod: http.MethodDelete, CleanupPath: "/items/1"}},
	}
	plan := s.buildAssessmentPlan(cfg)
	if !slices.ContainsFunc(plan.Errors, func(problem assessment.Problem) bool { return problem.Code == "api_write.operation_unknown" }) {
		t.Fatalf("unknown write operation was not rejected: %+v", plan.Errors)
	}
}

func TestAssessmentPlanUsesBoundCredentialWithoutReturningSecretOrClaimingVerifiedAuth(t *testing.T) {
	s := newTestServer(t, nil)
	keyPath := filepath.Join(t.TempDir(), "credential.key")
	if err := os.WriteFile(keyPath, []byte("01234567890123456789012345678901"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XALGORIX_CREDENTIAL_KEY_FILE", keyPath)
	const secret = "Bearer TOP-SECRET-credential-value"
	created := httptest.NewRecorder()
	s.handleCredentials(created, httptest.NewRequest(http.MethodPost, "/api/credentials", strings.NewReader(`{"name":"app headers","kind":"APPLICATION_HEADERS","target_ids":["app"],"values":{"Authorization":"`+secret+`"}}`)))
	if created.Code != http.StatusCreated {
		t.Fatalf("credential status=%d body=%s", created.Code, created.Body.String())
	}
	var metadata struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &metadata); err != nil || metadata.ID == "" {
		t.Fatalf("credential metadata=%+v err=%v", metadata, err)
	}
	body := `{"assessment_mode":"GRAY_BOX","assessment_types":["WEB_APPLICATION"],"assessment_targets":[{"id":"app","type":"URL","value":"https://app.example.test/"},{"id":"other","type":"URL","value":"https://other.example.test/"}],"access":[{"target_ids":["app"],"kind":"APPLICATION_HEADERS","credential_id":"` + metadata.ID + `","verify_url":"https://app.example.test/profile","verify_marker":"Account dashboard"}]}`
	planned := httptest.NewRecorder()
	s.handleAssessmentPlan(planned, httptest.NewRequest(http.MethodPost, "/api/scans/plan", strings.NewReader(body)))
	if planned.Code != http.StatusOK {
		t.Fatalf("plan status=%d body=%s", planned.Code, planned.Body.String())
	}
	if strings.Contains(planned.Body.String(), secret) {
		t.Fatal("plan response leaked credential material")
	}
	var plan struct {
		Capabilities []struct {
			TargetID   string `json:"target_id"`
			Capability string `json:"capability"`
			State      string `json:"state"`
		} `json:"capabilities"`
		Decisions []struct {
			Scanner       string `json:"scanner"`
			TargetID      string `json:"target_id"`
			ExecutionMode string `json:"execution_mode"`
		} `json:"decisions"`
	}
	if err := json.Unmarshal(planned.Body.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(plan.Capabilities, func(e struct {
		TargetID   string `json:"target_id"`
		Capability string `json:"capability"`
		State      string `json:"state"`
	}) bool {
		return e.TargetID == "app" && e.Capability == "authenticated_web" && e.State == "available"
	}) {
		t.Fatalf("bound credential was not available in plan: %+v", plan.Capabilities)
	}
	for _, d := range plan.Decisions {
		if d.Scanner == "zap" && d.TargetID == "app" && d.ExecutionMode != "unauthenticated" {
			t.Fatalf("unverified credentials must not be labeled authenticated: %+v", d)
		}
		if d.Scanner == "zap" && d.TargetID == "other" && d.ExecutionMode == "authenticated" {
			t.Fatalf("credential crossed target boundary: %+v", d)
		}
	}
}

func TestTypedAssessmentStartRequiresCurrentPlanFingerprint(t *testing.T) {
	s := newTestServer(t, nil)
	body := `{"assessment_mode":"BLACK_BOX","assessment_types":["WEB_APPLICATION"],"assessment_targets":[{"id":"app","type":"URL","value":"https://app.example.test/Portal/"}]}`
	rr := httptest.NewRecorder()
	s.handleScan(rr, httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(body)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(s.instances) != 0 {
		t.Fatal("typed assessment without a reviewed plan created a scan")
	}
	stale := strings.TrimSuffix(body, "}") + `,"plan_fingerprint":"sha256:stale"}`
	rr = httptest.NewRecorder()
	s.handleScan(rr, httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(stale)))
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), `"plan"`) {
		t.Fatalf("stale plan response status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(s.instances) != 0 {
		t.Fatal("stale assessment plan created a scan")
	}
}

func TestTypedAssessmentSavePersistsPlanSnapshotAndFingerprint(t *testing.T) {
	s := newTestServer(t, nil)
	body := `{"assessment":{"assessment_mode":"BLACK_BOX","assessment_types":["WEB_APPLICATION"],"assessment_targets":[{"id":"app","type":"URL","value":"https://app.example.test/Portal/"}]},"targets":["https://app.example.test/Portal/"],"save_only":true}`
	rr := httptest.NewRecorder()
	s.handleScan(rr, httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var result map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	inst := s.instances[result["instance_id"]]
	if inst == nil || inst.Assessment == nil || inst.PlanFingerprint == "" {
		t.Fatalf("saved typed assessment did not preserve its accepted identity: %+v", inst)
	}
	entries := s.findAllScans()
	if len(entries) != 1 || entries[0].rec.PlanFingerprint != inst.PlanFingerprint || entries[0].rec.AssessmentPlan == nil {
		t.Fatalf("saved record lost plan snapshot: %+v", entries)
	}
}

func TestTypedAssessmentStartRejectsPlanWithoutRunnableAdapters(t *testing.T) {
	s := newTestServer(t, nil)
	s.cfg.NucleiPath = "xalgorix-test-missing-nuclei"
	s.cfg.TestsslPath = "xalgorix-test-missing-testssl"
	s.cfg.ZAPURL = ""
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeBlackBox, Types: []assessment.Type{assessment.TypeWebApplication}, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.example.test/Portal/"}}, Profile: "web-gentle"}
	plan := s.buildAssessmentPlan(cfg)
	request, err := json.Marshal(map[string]any{
		"assessment": cfg, "targets": []string{"https://app.example.test/Portal/"}, "profile": "web-gentle", "plan_fingerprint": plan.Fingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	s.handleScan(rr, httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(string(request))))
	if rr.Code != http.StatusUnprocessableEntity || len(s.instances) != 0 {
		t.Fatalf("unsupported plan should not queue: status=%d instances=%d body=%s", rr.Code, len(s.instances), rr.Body.String())
	}
}

func TestTypedSourceOnlyStartDoesNotApplyNetworkSelfScanBlock(t *testing.T) {
	s := newTestServer(t, nil)
	s.cfg.SemgrepPath = "xalgorix-test-missing-semgrep"
	s.cfg.GitleaksPath = "xalgorix-test-missing-gitleaks"
	// Every source scanner is missing so no job is planned, independent of the
	// tools installed on the test machine.
	s.cfg.TrivyPath = "xalgorix-test-missing-trivy"
	s.cfg.OsvPath = "xalgorix-test-missing-osv"
	source := t.TempDir()
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeWhiteBox, Types: []assessment.Type{assessment.TypeSourceCode}, Targets: []assessment.Target{{ID: "source", Kind: assessment.KindLocalSourcePath, Value: source}}, Profile: "web-gentle"}
	plan := s.buildAssessmentPlan(cfg)
	request, err := json.Marshal(map[string]any{"assessment": cfg, "targets": []string{source}, "plan_fingerprint": plan.Fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	s.handleScan(rr, httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(string(request))))
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("source-only target should reach capability planning; status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestPlanHasRunnableJobsCountsConditionalSourceJobs(t *testing.T) {
	// A source-only repository assessment plans its scanners as conditional
	// (the clone happens at run time); it must be startable.
	conditional := scanner.AssessmentPlan{Jobs: []scanner.PlanJob{{Scanner: "trivy", TargetID: "artifact-1", State: scanner.PlanConditional}}}
	if !planHasRunnableJobs(conditional) {
		t.Fatal("a plan of conditional source jobs should be runnable")
	}
	selected := scanner.AssessmentPlan{Jobs: []scanner.PlanJob{{Scanner: "nuclei", TargetID: "app", State: scanner.PlanSelected}}}
	if !planHasRunnableJobs(selected) {
		t.Fatal("a plan with a selected job should be runnable")
	}
	gaps := scanner.AssessmentPlan{Jobs: []scanner.PlanJob{{Scanner: "zap", State: scanner.PlanUnavailable}, {Scanner: "nikto", State: scanner.PlanSkipped}}}
	if planHasRunnableJobs(gaps) {
		t.Fatal("a plan of only unavailable or skipped jobs must not start")
	}
}

func TestSavedScanRetainsSelectedWebProfile(t *testing.T) {
	s := newTestServer(t, nil)
	body := `{"targets":["https://app.example.test/Portal/"],"scan_mode":"single","profile":"web-thorough","save_only":true}`
	rr := httptest.NewRecorder()
	s.handleScan(rr, httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var response map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	inst := s.instances[response["instance_id"]]
	if inst == nil || inst.Profile != "web-thorough" {
		t.Fatalf("saved scan profile was lost: %+v", inst)
	}
}

func TestScanRequestAcceptsFlatAssessmentAndRejectsAmbiguousDualForms(t *testing.T) {
	var req ScanRequest
	if err := json.Unmarshal([]byte(`{"assessment_mode":"GRAY_BOX","assessment_types":["API"],"assessment_targets":[{"id":"api","type":"URL","value":"https://api.example.test/v1"}],"profile":"web-gentle"}`), &req); err != nil {
		t.Fatal(err)
	}
	if req.Assessment == nil || req.Assessment.Mode != "GRAY_BOX" || req.Assessment.Profile != "web-gentle" {
		t.Fatalf("flat assessment was not decoded: %+v", req.Assessment)
	}
	if err := json.Unmarshal([]byte(`{"assessment_mode":"BLACK_BOX","assessment":{"assessment_mode":"GRAY_BOX"}}`), &req); err == nil {
		t.Fatal("expected ambiguous flat and nested assessment forms to be rejected")
	}
}

func TestScannerRegistryIncludesUnavailableAdapters(t *testing.T) {
	s := newTestServer(t, nil)
	rr := httptest.NewRecorder()
	s.handleScannerRegistry(rr, httptest.NewRequest(http.MethodGet, "/api/scanners/registry", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	var body struct {
		Scanners []struct {
			ID        string `json:"id"`
			Available bool   `json:"available"`
		} `json:"scanners"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, d := range body.Scanners {
		seen[d.ID] = true
	}
	for _, id := range []string{"masscan", "nikto", "lynis"} {
		if !seen[id] {
			t.Errorf("registry omitted %s", id)
		}
	}
}

// saveScannerScan writes a schema-v2 scan record under s.dataDir so
// findScanByID finds it, returning its scan dir.
func saveScannerScan(t *testing.T, s *Server, id string, runs func(dir string) []scanner.Run) string {
	t.Helper()
	dir := filepath.Join(s.dataDir, "example.test", "2026-09-25", id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	rec := &ScanRecord{SchemaVersion: scanner.SchemaVersion, ID: id, Target: "example.test", Status: "finished", ScannerRuns: runs(dir), Events: []WSEvent{}, Vulns: []VulnSummary{}}
	s.saveScanRecordTo(rec, dir)
	return dir
}

func writeFile(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScannerOutputSelectsRunByScope(t *testing.T) {
	s := newTestServer(t, nil)
	saveScannerScan(t, s, "scope-out", func(dir string) []scanner.Run {
		return []scanner.Run{
			{Scanner: "nuclei", Scope: "host:a.test", Target: "a.test", Status: "completed", StdoutPath: writeFile(t, filepath.Join(dir, "hosts", "a.test", "nuclei.out"), "output for A")},
			{Scanner: "nuclei", Scope: "host:b.test", Target: "b.test", Status: "completed", StdoutPath: writeFile(t, filepath.Join(dir, "hosts", "b.test", "nuclei.out"), "output for B")},
		}
	})
	get := func(url string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		s.handleScannerOutput(rr, httptest.NewRequest(http.MethodGet, url, nil))
		return rr
	}
	if rr := get("/api/scans/scope-out/output/nuclei/stdout?scope=host:b.test"); rr.Code != 200 || rr.Body.String() != "output for B" {
		t.Fatalf("scoped: %d %q", rr.Code, rr.Body.String())
	}
	if rr := get("/api/scans/scope-out/output/nuclei/stdout"); rr.Code != 200 || rr.Body.String() != "output for A" {
		t.Fatalf("unscoped must keep first-run behaviour: %d %q", rr.Code, rr.Body.String())
	}
	if rr := get("/api/scans/scope-out/output/nuclei/stdout?scope=host:nope"); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown scope: %d", rr.Code)
	}
}

func TestScannerCombinedOutputIsPagedAndLegacyMissing(t *testing.T) {
	s := newTestServer(t, nil)
	saveScannerScan(t, s, "combined-out", func(dir string) []scanner.Run {
		return []scanner.Run{
			{Scanner: "nuclei", Scope: "host:a.test", Target: "a.test", Status: "completed", TranscriptPath: writeFile(t, filepath.Join(dir, "a", "combined.log"), "one\ntwo\nthree\n")},
			{Scanner: "nuclei", Scope: "host:b.test", Target: "b.test", Status: "completed", StdoutPath: writeFile(t, filepath.Join(dir, "b", "stdout.log"), "legacy")},
		}
	})
	get := func(url string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		s.handleScannerOutput(rr, httptest.NewRequest(http.MethodGet, url, nil))
		return rr
	}
	first := get("/api/scans/combined-out/output/nuclei/combined?scope=host:a.test&offset=0&limit=4")
	if first.Code != 200 || first.Body.String() != "one\n" || first.Header().Get("X-Start-Offset") != "0" || first.Header().Get("X-Next-Offset") != "4" || first.Header().Get("X-Total-Size") != "14" {
		t.Fatalf("first page: %d %q, headers=%v", first.Code, first.Body.String(), first.Header())
	}
	second := get("/api/scans/combined-out/output/nuclei/combined?scope=host:a.test&offset=4&limit=4")
	if second.Code != 200 || second.Body.String() != "two\n" {
		t.Fatalf("second page: %d %q", second.Code, second.Body.String())
	}
	if legacy := get("/api/scans/combined-out/output/nuclei/combined?scope=host:b.test"); legacy.Code != http.StatusNotFound {
		t.Fatalf("legacy scan must use separate logs, got %d", legacy.Code)
	}
}

func TestScannerCombinedOutputCapsPageSize(t *testing.T) {
	s := newTestServer(t, nil)
	content := strings.Repeat("x", 2<<20)
	saveScannerScan(t, s, "large-combined", func(dir string) []scanner.Run {
		return []scanner.Run{{Scanner: "nuclei", Target: "a.test", Status: "completed", TranscriptPath: writeFile(t, filepath.Join(dir, "combined.log"), content)}}
	})
	rr := httptest.NewRecorder()
	s.handleScannerOutput(rr, httptest.NewRequest(http.MethodGet, "/api/scans/large-combined/output/nuclei/combined?limit=999999999", nil))
	if rr.Code != 200 || rr.Body.Len() != 1<<20 || rr.Header().Get("X-Total-Size") != "2097152" {
		t.Fatalf("large page: status=%d bytes=%d headers=%v", rr.Code, rr.Body.Len(), rr.Header())
	}
}

func TestScannerCombinedOutputCanFollowNewBytes(t *testing.T) {
	s := newTestServer(t, nil)
	var path string
	saveScannerScan(t, s, "live-combined", func(dir string) []scanner.Run {
		path = writeFile(t, filepath.Join(dir, "combined.log"), "started\n")
		return []scanner.Run{{Scanner: "nuclei", Target: "a.test", Status: "running", TranscriptPath: path}}
	})
	get := func(offset int) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		s.handleScannerOutput(rr, httptest.NewRequest(http.MethodGet, "/api/scans/live-combined/output/nuclei/combined?offset="+strconv.Itoa(offset)+"&limit=65536", nil))
		return rr
	}
	first := get(0)
	if first.Code != 200 || first.Body.String() != "started\n" {
		t.Fatalf("initial live page: %d %q", first.Code, first.Body.String())
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("finding\n")
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	next := get(first.Body.Len())
	if next.Code != 200 || next.Body.String() != "finding\n" || next.Header().Get("X-Total-Size") != "16" {
		t.Fatalf("follow-up live page: %d %q headers=%v", next.Code, next.Body.String(), next.Header())
	}
}

// TestScannerOutputMatchesLegacyRunByHostScope locks in that a pre-scope
// (Increment-1) run with an empty Scope still answers a ?scope=host:<target>
// request, via scanner.FindingScope's empty-Scope fold to the target's host
// scope.
func TestScannerOutputMatchesLegacyRunByHostScope(t *testing.T) {
	s := newTestServer(t, nil)
	saveScannerScan(t, s, "legacy-scope", func(dir string) []scanner.Run {
		return []scanner.Run{
			{Scanner: "nuclei", Scope: "", Target: "legacy.test", Status: "completed", StdoutPath: writeFile(t, filepath.Join(dir, "nuclei.out"), "legacy output")},
		}
	})
	rr := httptest.NewRecorder()
	s.handleScannerOutput(rr, httptest.NewRequest(http.MethodGet, "/api/scans/legacy-scope/output/nuclei/stdout?scope=host:legacy.test", nil))
	if rr.Code != 200 || rr.Body.String() != "legacy output" {
		t.Fatalf("legacy run by host scope: %d %q", rr.Code, rr.Body.String())
	}
}

// TestScannerOutputMatchesPerHostReconRunByHostScope locks in that a per-host
// recon run (Scope "recon:<target>:<host>") answers a ?scope=host:<host>
// request, folding via scanner.FindingScope the same way the report's Scan
// Coverage section groups it under its host.
func TestScannerOutputMatchesPerHostReconRunByHostScope(t *testing.T) {
	s := newTestServer(t, nil)
	saveScannerScan(t, s, "recon-scope", func(dir string) []scanner.Run {
		return []scanner.Run{
			{Scanner: "nmap", Scope: "recon:example.test:a.example.test", Target: "example.test", Status: "completed", StdoutPath: writeFile(t, filepath.Join(dir, "nmap.out"), "nmap for a")},
		}
	})
	rr := httptest.NewRecorder()
	s.handleScannerOutput(rr, httptest.NewRequest(http.MethodGet, "/api/scans/recon-scope/output/nmap/stdout?scope=host:a.example.test", nil))
	if rr.Code != 200 || rr.Body.String() != "nmap for a" {
		t.Fatalf("per-host recon run by host scope: %d %q", rr.Code, rr.Body.String())
	}
}

// TestScannerArtifactSelectsRunByScope mirrors
// TestScannerOutputSelectsRunByScope for the artifact endpoint: ?scope=
// picks one host's artifact file, and without it the first run by name wins.
func TestScannerArtifactSelectsRunByScope(t *testing.T) {
	s := newTestServer(t, nil)
	saveScannerScan(t, s, "artifact-scope", func(dir string) []scanner.Run {
		return []scanner.Run{
			{Scanner: "nuclei", Scope: "host:a.test", Target: "a.test", Status: "completed", ArtifactPath: writeFile(t, filepath.Join(dir, "hosts", "a.test", "nuclei.jsonl"), "artifact for A")},
			{Scanner: "nuclei", Scope: "host:b.test", Target: "b.test", Status: "completed", ArtifactPath: writeFile(t, filepath.Join(dir, "hosts", "b.test", "nuclei.jsonl"), "artifact for B")},
		}
	})
	get := func(url string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		s.handleScannerOutput(rr, httptest.NewRequest(http.MethodGet, url, nil))
		return rr
	}
	if rr := get("/api/scans/artifact-scope/nuclei/artifact?scope=host:b.test"); rr.Code != 200 || rr.Body.String() != "artifact for B" {
		t.Fatalf("scoped artifact: %d %q", rr.Code, rr.Body.String())
	}
	if rr := get("/api/scans/artifact-scope/nuclei/artifact"); rr.Code != 200 || rr.Body.String() != "artifact for A" {
		t.Fatalf("unscoped artifact must keep first-run behaviour: %d %q", rr.Code, rr.Body.String())
	}
}

func TestScanScopesEndpoint(t *testing.T) {
	s := newTestServer(t, nil)
	saveScannerScan(t, s, "scopes-1", func(dir string) []scanner.Run {
		return []scanner.Run{
			{Scanner: "subfinder", Scope: "recon:example.test", Target: "example.test", Status: "completed"},
			{Scanner: "nmap", Scope: "recon:example.test:a.example.test", Target: "example.test", Status: "completed"},
			{Scanner: "nuclei", Scope: "host:a.example.test", Target: "a.example.test", Status: "completed", ArtifactPath: writeFile(t, filepath.Join(dir, "n.jsonl"), "{}\n"), Truncated: true},
			{Scanner: "trivy", Scope: "source:main", Target: "", Status: "not_applicable", Reason: "no source"},
		}
	})
	rr := httptest.NewRecorder()
	s.handleScanScopes(rr, httptest.NewRequest(http.MethodGet, "/api/scans/scopes-1/scopes", nil))
	if rr.Code != 200 {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Recon  []reportScopeRun `json:"recon"`
		Scopes []reportScope    `json:"scopes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Recon) != 1 || body.Recon[0].Scanner != "subfinder" || body.Recon[0].Scope != "recon:example.test" {
		t.Fatalf("recon = %+v (per-host nmap belongs to its host)", body.Recon)
	}
	if len(body.Scopes) != 2 || body.Scopes[0].ID != "host:a.example.test" || body.Scopes[1].ID != "source:main" {
		t.Fatalf("scopes = %+v", body.Scopes)
	}
	host := body.Scopes[0]
	if len(host.Runs) != 2 || host.Runs[0].Scanner != "nmap" || host.Runs[0].Scope != "recon:example.test:a.example.test" {
		t.Fatalf("host runs = %+v", host.Runs)
	}
	if n := host.Runs[1]; n.Scanner != "nuclei" || !n.HasArtifact || !n.Truncated || n.Scope != "host:a.example.test" {
		t.Fatalf("nuclei run = %+v", n)
	}
	legacy := httptest.NewRecorder()
	legacyDir := filepath.Join(s.dataDir, "old.test", "2026-01-01", "legacy-1")
	_ = os.MkdirAll(legacyDir, 0o700)
	s.saveScanRecordTo(&ScanRecord{SchemaVersion: 1, ID: "legacy-1", Target: "old.test", Status: "finished", Events: []WSEvent{}, Vulns: []VulnSummary{}}, legacyDir)
	s.handleScanScopes(legacy, httptest.NewRequest(http.MethodGet, "/api/scans/legacy-1/scopes", nil))
	if legacy.Code != 200 || legacy.Body.String() != "{\"recon\":[],\"scopes\":[]}\n" {
		t.Fatalf("legacy: %d %q", legacy.Code, legacy.Body.String())
	}
	missing := httptest.NewRecorder()
	s.handleScanScopes(missing, httptest.NewRequest(http.MethodGet, "/api/scans/nope/scopes", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing scan: %d", missing.Code)
	}
}

func TestIsScanScopesPath(t *testing.T) {
	cases := map[string]bool{
		"/api/scans/abc/scopes":       true,
		"/api/scans/abc/vulns/scopes": false,
		"/api/scans//scopes":          false,
		"/api/scans/abc/scopes/x":     false,
		"/api/scans/scopes":           false,
	}
	for path, want := range cases {
		if got := isScanScopesPath(path); got != want {
			t.Errorf("isScanScopesPath(%q) = %v, want %v", path, got, want)
		}
	}
}

// previewPlanProblems posts cfg to the preview endpoint and returns the
// response status and plan problem codes.
func previewPlanProblems(t *testing.T, s *Server, cfg assessment.AssessmentConfig) (int, []string) {
	t.Helper()
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	s.handleAssessmentPlan(rr, httptest.NewRequest(http.MethodPost, "/api/assessments/plan", strings.NewReader(string(body))))
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var plan struct {
		Errors []assessment.Problem `json:"errors"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &plan); err != nil {
		t.Fatalf("decode plan: %v body=%s", err, rr.Body.String())
	}
	codes := make([]string, 0, len(plan.Errors))
	for _, p := range plan.Errors {
		codes = append(codes, p.Code)
	}
	return rr.Code, codes
}

func approvedOriginConfig(origins ...string) assessment.AssessmentConfig {
	cfg := assessment.AssessmentConfig{
		Mode: assessment.ModeBlackBox, Types: []assessment.Type{assessment.TypeWebApplication}, Profile: "web-gentle",
		Targets: []assessment.Target{{ID: "app", Kind: assessment.KindIP, Value: "192.0.2.10"}},
	}
	for _, raw := range origins {
		o, err := assessment.ParseApprovedOrigin("app", raw)
		if err != nil {
			panic(err)
		}
		cfg.ApprovedOrigins = append(cfg.ApprovedOrigins, o)
	}
	return cfg
}

func TestPlanPreviewBlocksLocalOrListenerOrigin(t *testing.T) {
	s := newTestServer(t, nil)
	s.port = 9137
	status, codes := previewPlanProblems(t, s, approvedOriginConfig("http://192.0.2.10:8080/"))
	if slices.Contains(codes, "target.scope_blocked") {
		t.Fatalf("public approved origin was scope-blocked: status=%d codes=%v", status, codes)
	}
	for _, local := range []string{"http://127.0.0.1:8080/", "http://localhost:3000/app", "http://127.0.0.1:9137/"} {
		status, codes := previewPlanProblems(t, s, approvedOriginConfig("http://192.0.2.10:8080/", local))
		if status != http.StatusUnprocessableEntity || !slices.Contains(codes, "target.scope_blocked") {
			t.Fatalf("approved origin %s must be scope-blocked at preview: status=%d codes=%v", local, status, codes)
		}
	}
	// A local target value is blocked at preview too, not only at start.
	cfg := approvedOriginConfig()
	cfg.Targets[0].Value = "127.0.0.1"
	if status, codes := previewPlanProblems(t, s, cfg); status != http.StatusUnprocessableEntity || !slices.Contains(codes, "target.scope_blocked") {
		t.Fatalf("local target must be scope-blocked at preview: status=%d codes=%v", status, codes)
	}
}

func TestPlanPreviewHonoursAllowLocalTargets(t *testing.T) {
	s := newTestServer(t, nil)
	s.port = 9137
	s.cfg.AllowLocalTargets = true // XALGORIX_ALLOW_LOCAL_TARGETS=true
	if _, codes := previewPlanProblems(t, s, approvedOriginConfig("http://127.0.0.1:8080/")); slices.Contains(codes, "target.scope_blocked") {
		t.Fatalf("lab origin must be allowed when local targets are enabled: %v", codes)
	}
	// The dashboard listener stays out of scope even with the opt-in.
	if _, codes := previewPlanProblems(t, s, approvedOriginConfig("http://127.0.0.1:9137/")); !slices.Contains(codes, "target.scope_blocked") {
		t.Fatalf("listener origin must stay blocked with local targets enabled: %v", codes)
	}
	// The per-scan loopback allowlist reaches the same guard at start.
	s.cfg.AllowLocalTargets = false
	cfg := approvedOriginConfig("http://127.0.0.1:8080/")
	if plan := s.buildAssessmentPlanForScan(cfg, []int{8080}); slices.ContainsFunc(plan.Errors, func(p assessment.Problem) bool { return p.Code == "target.scope_blocked" }) {
		t.Fatalf("allowlisted loopback port was blocked: %+v", plan.Errors)
	}
	if plan := s.buildAssessmentPlan(cfg); !slices.ContainsFunc(plan.Errors, func(p assessment.Problem) bool { return p.Code == "target.scope_blocked" }) {
		t.Fatalf("preview without the allowlist must block loopback: %+v", plan.Errors)
	}
}

func TestPlanFingerprintIncludesToolVersionsAndCredentialRevision(t *testing.T) {
	s := newTestServer(t, nil)
	keyPath := filepath.Join(t.TempDir(), "credential.key")
	if err := os.WriteFile(keyPath, []byte("01234567890123456789012345678901"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XALGORIX_CREDENTIAL_KEY_FILE", keyPath)
	vault, err := s.credentialVault()
	if err != nil {
		t.Fatal(err)
	}
	record := credentials.Record{Name: "app headers", Kind: assessment.AccessApplicationHeaders, TargetIDs: []string{"app"}, Values: map[string]string{"Authorization": "Bearer one"}}
	meta, err := vault.Create(record)
	if err != nil {
		t.Fatal(err)
	}
	cfg := assessment.AssessmentConfig{
		Mode: assessment.ModeGrayBox, Types: []assessment.Type{assessment.TypeWebApplication}, Profile: "web-gentle",
		Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.example.test/"}},
		Access:  []assessment.AccessBinding{{TargetIDs: []string{"app"}, Kind: assessment.AccessApplicationHeaders, CredentialID: meta.ID, VerifyURL: "https://app.example.test/me", VerifyMarker: "Account"}},
	}
	s.toolVersions = map[string]string{"nuclei": "v3.11.1", "nuclei-templates": "abc"}
	base := s.buildAssessmentPlan(cfg).Fingerprint
	if base == "" || base != s.buildAssessmentPlan(cfg).Fingerprint {
		t.Fatal("fingerprint must be stable for unchanged inputs")
	}
	s.toolVersions = map[string]string{"nuclei": "v3.11.1", "nuclei-templates": "def"}
	templates := s.buildAssessmentPlan(cfg).Fingerprint
	if templates == base {
		t.Fatal("template upgrade did not change the plan fingerprint")
	}
	record.Values = map[string]string{"Authorization": "Bearer two"}
	if _, err := vault.Replace(meta.ID, record); err != nil {
		t.Fatal(err)
	}
	if rotated := s.buildAssessmentPlan(cfg).Fingerprint; rotated == templates {
		t.Fatal("credential rotation did not change the plan fingerprint")
	}
}
