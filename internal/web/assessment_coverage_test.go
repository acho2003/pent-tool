package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

func TestAssessmentCoverageDistinguishesCompletedAndUntestedOperations(t *testing.T) {
	s := newTestServer(t, nil)
	scanDir := filepath.Join(s.dataDir, "coverage-app", "2026-09-28", "coverage-scan")
	if err := os.MkdirAll(scanDir, 0700); err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(scanDir, "scanner-output", "nuclei.json")
	if err := os.MkdirAll(filepath.Dir(artifactPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifactPath, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	plan := &scanner.AssessmentPlan{
		Config: assessment.AssessmentConfig{
			Mode: assessment.ModeGrayBox, Types: []assessment.Type{assessment.TypeAPI},
			Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.example.test/Api"}},
		},
		Capabilities: []assessment.CapabilityEvidence{{Capability: assessment.CapAuthWeb, TargetID: "app", ReferenceID: "opaque-credential-id", State: assessment.StateAvailable, Reason: "credential exists; login not verified"}},
		Decisions:    []scanner.PlanDecision{{Scanner: "nuclei", TargetID: "app", Types: []assessment.Type{assessment.TypeAPI}, State: scanner.PlanSelected}, {Scanner: "zap", TargetID: "app", Types: []assessment.Type{assessment.TypeAPI}, State: scanner.PlanUnavailable, Reason: "dedicated daemon is unavailable"}},
		Jobs: []scanner.PlanJob{
			{ID: "nuclei:app:nuclei", State: scanner.PlanSelected, Scanner: "nuclei", TargetID: "app", Target: "https://app.example.test/Api", AssessmentType: assessment.TypeAPI, AssessmentTypes: []assessment.Type{assessment.TypeAPI}, Variant: "nuclei"},
			{ID: "zap:app:zap", State: scanner.PlanConditional, Scanner: "zap", TargetID: "app", Target: "https://app.example.test/Api", AssessmentType: assessment.TypeAPI, AssessmentTypes: []assessment.Type{assessment.TypeAPI}, Variant: "zap"},
		},
		Coverage:     []scanner.TypeCoverage{{Type: assessment.TypeAPI, State: "conditional", Reason: "part of API coverage remains conditional"}},
		APIEndpoints: []scanner.APIEndpoint{{TargetID: "app", Method: "GET", Path: "/users", Origin: "https://app.example.test", Source: "openapi", Resolved: true, Eligible: true}},
		Fingerprint:  "sha256:coverage-plan",
	}
	run := scanner.Run{Scanner: "nuclei", Variant: "nuclei", PlanFingerprint: plan.Fingerprint, Target: "https://app.example.test/Api", Status: "completed", ArtifactPath: artifactPath}
	run.Checksum = scanner.CalculateChecksum(run)
	record := &ScanRecord{SchemaVersion: 3, ID: "coverage-scan", Status: "finished", Profile: "web-gentle", PlanFingerprint: plan.Fingerprint, AssessmentPlan: plan, ScannerRuns: []scanner.Run{run}}
	s.saveScanRecordTo(record, scanDir)

	rr := httptest.NewRecorder()
	s.handleAssessmentCoverage(rr, httptest.NewRequest(http.MethodGet, "/api/scans/coverage-scan/coverage", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"state":"partial"`) {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	for _, want := range []string{`"status":"completed"`, `"status":"skipped"`, `"artifact_state":"verified"`, `"inventoried_not_executed"`, `"dedicated daemon is unavailable"`} {
		if !strings.Contains(rr.Body.String(), want) {
			t.Fatalf("coverage response omitted %s: %s", want, rr.Body.String())
		}
	}
	if strings.Contains(rr.Body.String(), "opaque-credential-id") {
		t.Fatal("coverage response exposed a credential reference")
	}
}

func TestAssessmentCoverageLabelsLegacyRecords(t *testing.T) {
	coverage := buildAssessmentCoverage("old-scan", &ScanRecord{ID: "old-scan", Status: "finished"}, "")
	if coverage.State != "legacy" || coverage.Reason == "" {
		t.Fatalf("legacy coverage = %+v", coverage)
	}
}

func TestAssessmentCoverageMarksExpiredSessionUnavailable(t *testing.T) {
	target := "https://app.example.test/Portal"
	plan := &scanner.AssessmentPlan{Config: assessment.AssessmentConfig{Mode: assessment.ModeGrayBox, Types: []assessment.Type{assessment.TypeWebApplication}}, Capabilities: []assessment.CapabilityEvidence{{Capability: assessment.CapAuthWeb, TargetID: "app", State: assessment.StateVerified}}, Jobs: []scanner.PlanJob{{ID: "zap:app", Scanner: "zap", TargetID: "app", Target: target, State: scanner.PlanSelected, AssessmentTypes: []assessment.Type{assessment.TypeWebApplication}}}, Coverage: []scanner.TypeCoverage{{Type: assessment.TypeWebApplication, State: "planned"}}}
	record := &ScanRecord{AssessmentPlan: plan, Status: "finished", ScannerRuns: []scanner.Run{{Scanner: "zap", Target: target, Status: "failed", Reason: "authenticated session expired or verification failed"}}}
	coverage := buildAssessmentCoverage("expired", record, "")
	if coverage.State != "partial" || len(coverage.Capabilities) != 1 || coverage.Capabilities[0].State != assessment.StateUnavailable || !strings.Contains(coverage.Capabilities[0].Reason, "expired") {
		t.Fatalf("expired login was not reported as a coverage gap: %+v", coverage)
	}
}

func TestAssessmentCoverageMarksFinishedJobsCompleteOnlyWhenCoverageIsComplete(t *testing.T) {
	plan := &scanner.AssessmentPlan{
		Config:      assessment.AssessmentConfig{Mode: assessment.ModeBlackBox, Types: []assessment.Type{assessment.TypeWebApplication}, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.example.test"}}},
		Jobs:        []scanner.PlanJob{{ID: "nuclei:app", State: scanner.PlanSelected, Scanner: "nuclei", Variant: "nuclei", TargetID: "app", Target: "https://app.example.test", AssessmentTypes: []assessment.Type{assessment.TypeWebApplication}}},
		Coverage:    []scanner.TypeCoverage{{Type: assessment.TypeWebApplication, State: "planned"}},
		Fingerprint: "sha256:complete-plan",
	}
	record := &ScanRecord{ID: "complete-scan", Status: "finished", AssessmentPlan: plan, ScannerRuns: []scanner.Run{{Scanner: "nuclei", Variant: "nuclei", Target: "https://app.example.test", PlanFingerprint: plan.Fingerprint, Status: "completed"}}}
	coverage := buildAssessmentCoverage(record.ID, record, "")
	if coverage.State != "complete" || coverage.TypeCoverage[0].State != "complete" {
		t.Fatalf("completed assessment was not marked complete: %+v", coverage)
	}

	plan.Config.Types = []assessment.Type{assessment.TypeAPI}
	plan.Jobs[0].AssessmentTypes = []assessment.Type{assessment.TypeAPI}
	plan.Coverage[0].Type = assessment.TypeAPI
	plan.APIEndpoints = []scanner.APIEndpoint{{TargetID: "app", Method: "GET", Path: "/health", Resolved: true, Eligible: true}}
	coverage = buildAssessmentCoverage(record.ID, record, "")
	if coverage.State != "partial" || coverage.TypeCoverage[0].State != "partial" || coverage.Operations[0].Status != "inventoried_not_executed" {
		t.Fatalf("unattempted API operation was treated as tested: %+v", coverage)
	}
}

func TestAssessmentCoverageReflectsAPIOperationSeedOutcomes(t *testing.T) {
	plan := &scanner.AssessmentPlan{
		Config: assessment.AssessmentConfig{Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.example.test/Portal"}}},
		APIEndpoints: []scanner.APIEndpoint{
			{TargetID: "app", Method: "GET", Path: "/health", Origin: "https://app.example.test", Resolved: true, Eligible: true},
			{TargetID: "app", Method: "POST", Path: "/users", Origin: "https://app.example.test", Resolved: true, Reason: "state-changing operation requires explicit approval"},
		},
		Fingerprint: "sha256:operation-plan",
	}
	record := &ScanRecord{AssessmentPlan: plan, ScannerRuns: []scanner.Run{{
		Scanner: "zap", PlanFingerprint: plan.Fingerprint, Target: "https://app.example.test/Portal", Status: "completed",
		APIEndpointResults: []scanner.APIEndpointResult{{Method: "GET", Path: "/health", Origin: "https://app.example.test", Status: "seeded"}},
	}}}
	coverage := buildAssessmentCoverage("scan", record, "")
	if len(coverage.Operations) != 2 || coverage.Operations[0].Status != "batch_completed" || coverage.Operations[1].Status != "skipped" || coverage.Operations[1].Eligible {
		t.Fatalf("operation coverage=%+v", coverage.Operations)
	}
	if coverage.OperationCounts != (assessmentOperationCounts{Discovered: 2, Eligible: 1, Attempted: 1, BatchCompleted: 1, Skipped: 1}) {
		t.Fatalf("operation counts=%+v", coverage.OperationCounts)
	}
	lines := assessmentCoverageLines(coverage)
	if !slices.ContainsFunc(lines, func(line string) bool { return strings.Contains(line, "batch completed 1") }) {
		t.Fatalf("coverage summary omits batch-only evidence: %v", lines)
	}
}

func TestAssessmentCoverageMarksNativeAPIChecksPerOperation(t *testing.T) {
	plan := &scanner.AssessmentPlan{
		Config:       assessment.AssessmentConfig{Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.example.test/"}}, Types: []assessment.Type{assessment.TypeAPI}},
		Jobs:         []scanner.PlanJob{{ID: "apichecks:app", Scanner: "apichecks", Variant: "apichecks", TargetID: "app", Target: "https://app.example.test/", State: scanner.PlanSelected, AssessmentTypes: []assessment.Type{assessment.TypeAPI}}},
		Coverage:     []scanner.TypeCoverage{{Type: assessment.TypeAPI, State: "planned"}},
		APIEndpoints: []scanner.APIEndpoint{{TargetID: "app", Method: "GET", Path: "/api/items", Origin: "https://app.example.test", Resolved: true, Eligible: true}},
		Fingerprint:  "sha256:native-api-checks",
	}
	record := &ScanRecord{ID: "native-api", Status: "finished", AssessmentPlan: plan, ScannerRuns: []scanner.Run{{Scanner: "apichecks", Variant: "apichecks", Target: "https://app.example.test/", PlanFingerprint: plan.Fingerprint, Status: "completed", APIEndpointResults: []scanner.APIEndpointResult{{Method: "GET", Path: "/api/items", Origin: "https://app.example.test", Status: "checked"}}}}}
	coverage := buildAssessmentCoverage(record.ID, record, "")
	if coverage.Operations[0].Status != "tested" || coverage.OperationCounts.Completed != 1 || coverage.OperationCounts.BatchCompleted != 0 || coverage.TypeCoverage[0].State != "complete" {
		t.Fatalf("native API operation coverage=%+v counts=%+v type=%+v jobs=%+v", coverage.Operations, coverage.OperationCounts, coverage.TypeCoverage, coverage.Jobs)
	}
}

func TestAssessmentCoverageAndReportExposeRunLimitations(t *testing.T) {
	s := newTestServer(t, nil)
	scanDir := filepath.Join(s.dataDir, "limit-app", "2026-10-07", "limit-scan")
	if err := os.MkdirAll(filepath.Join(scanDir, "scanner-output"), 0700); err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(scanDir, "scanner-output", "katana.jsonl")
	if err := os.WriteFile(artifactPath, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	plan := &scanner.AssessmentPlan{
		Config:      assessment.AssessmentConfig{Mode: assessment.ModeBlackBox, Types: []assessment.Type{assessment.TypeWebApplication}, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.example.test/app/"}}},
		Jobs:        []scanner.PlanJob{{ID: "katana:app:katana", State: scanner.PlanSelected, Scanner: "katana", TargetID: "app", Target: "https://app.example.test/app/", AssessmentType: assessment.TypeWebApplication, AssessmentTypes: []assessment.Type{assessment.TypeWebApplication}, Variant: "katana"}},
		Fingerprint: "sha256:limit-plan",
	}
	run := scanner.Run{Scanner: "katana", Variant: "katana", PlanFingerprint: plan.Fingerprint, Target: "https://app.example.test/app/", Status: "completed", ArtifactPath: artifactPath,
		Limitations: []scanner.RunLimitation{{Kind: scanner.LimitationScopeNotGatewayEnforced, Reason: "katana is not routed through the recording gateway"}}}
	run.Checksum = scanner.CalculateChecksum(run)
	record := &ScanRecord{SchemaVersion: 3, ID: "limit-scan", Status: "finished", Profile: "web-gentle", PlanFingerprint: plan.Fingerprint, AssessmentPlan: plan, ScannerRuns: []scanner.Run{run}}
	s.saveScanRecordTo(record, scanDir)

	rr := httptest.NewRecorder()
	s.handleAssessmentCoverage(rr, httptest.NewRequest(http.MethodGet, "/api/scans/limit-scan/coverage", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"limitations":[{"kind":"scope_not_gateway_enforced"`) {
		t.Fatalf("coverage did not expose the limitation: %d %s", rr.Code, rr.Body.String())
	}
	var coverage assessmentCoverageResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &coverage); err != nil || len(coverage.Jobs) != 1 || coverage.Jobs[0].Status != "completed" {
		t.Fatalf("decode: %v %+v", err, coverage.Jobs)
	}
	lines := assessmentCoverageLines(coverage)
	if !slices.ContainsFunc(lines, func(l string) bool {
		return strings.HasPrefix(l, "Limitation katana (scope_not_gateway_enforced): ") && strings.Contains(l, "recording gateway")
	}) {
		t.Fatalf("report lines omit the limitation: %q", lines)
	}
}

func TestAssessmentCoverageReflectsApprovedWriteOutcomes(t *testing.T) {
	s := newTestServer(t, nil)
	scanDir := filepath.Join(s.dataDir, "write-app", "2026-10-07", "write-scan")
	if err := os.MkdirAll(scanDir, 0700); err != nil {
		t.Fatal(err)
	}
	target := "https://app.example.test/app/"
	plan := &scanner.AssessmentPlan{
		Config: assessment.AssessmentConfig{Mode: assessment.ModeGrayBox, Types: []assessment.Type{assessment.TypeAPI}, TestEnvironment: true, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: target}}},
		Jobs:   []scanner.PlanJob{{ID: "apiwrites:app:apiwrites", State: scanner.PlanSelected, Scanner: "apiwrites", TargetID: "app", Target: target, AssessmentType: assessment.TypeAPI, AssessmentTypes: []assessment.Type{assessment.TypeAPI}, Variant: "apiwrites"}},
		APIEndpoints: []scanner.APIEndpoint{
			{TargetID: "app", Method: "POST", Path: "/api/notes", Origin: target, Source: "openapi", Resolved: false, Eligible: false, Reason: "request body needs an explicit safe request example"},
			{TargetID: "app", Method: "POST", Path: "/api/other", Origin: target, Source: "openapi", Resolved: false, Eligible: false, Reason: "request body needs an explicit safe request example"},
		},
		Fingerprint: "sha256:write-plan",
	}
	run := scanner.Run{Scanner: "apiwrites", Variant: "apiwrites", PlanFingerprint: plan.Fingerprint, Target: target, Status: "completed",
		APIEndpointResults: []scanner.APIEndpointResult{{Method: "POST", Path: "/api/notes", Origin: target, Status: "completed"}}}
	record := &ScanRecord{SchemaVersion: 3, ID: "write-scan", Status: "finished", Profile: "web-gentle", PlanFingerprint: plan.Fingerprint, AssessmentPlan: plan, ScannerRuns: []scanner.Run{run}}
	s.saveScanRecordTo(record, scanDir)
	rr := httptest.NewRecorder()
	s.handleAssessmentCoverage(rr, httptest.NewRequest(http.MethodGet, "/api/scans/write-scan/coverage", nil))
	var coverage assessmentCoverageResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &coverage); err != nil {
		t.Fatalf("decode: %v %s", err, rr.Body.String())
	}
	status := map[string]string{}
	for _, operation := range coverage.Operations {
		status[operation.Path] = operation.Status
	}
	if status["/api/notes"] != "tested" || status["/api/other"] != "skipped" {
		t.Fatalf("operation statuses = %v; an executed approved write is tested and an unapproved one stays skipped", status)
	}
	if coverage.OperationCounts.Completed != 1 || coverage.OperationCounts.Skipped != 1 {
		t.Fatalf("counts = %+v", coverage.OperationCounts)
	}
}

func TestAssessmentCoverageReportsSessionExpiryFromAnyAuthenticatedTool(t *testing.T) {
	target := "https://app.example.test/Portal"
	plan := &scanner.AssessmentPlan{Config: assessment.AssessmentConfig{Mode: assessment.ModeGrayBox, Types: []assessment.Type{assessment.TypeWebApplication}, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: target}}},
		Capabilities: []assessment.CapabilityEvidence{{Capability: assessment.CapAuthWeb, TargetID: "app", State: assessment.StateVerified, Reason: "verified before the run"}},
		Jobs:         []scanner.PlanJob{{ID: "nuclei:app", Scanner: "nuclei", TargetID: "app", Target: target, State: scanner.PlanSelected, AssessmentTypes: []assessment.Type{assessment.TypeWebApplication}}}}
	expired := scanner.Run{Scanner: "nuclei", Target: target, Status: "failed", GapKind: scanner.GapAuthExpired, AuthState: assessment.StateExpired, Reason: "authenticated session expired or rotated; retry with verified credentials"}
	record := &ScanRecord{AssessmentPlan: plan, Status: "finished", ScannerRuns: []scanner.Run{expired}}
	coverage := buildAssessmentCoverage("expired-nuclei", record, "")
	if len(coverage.Capabilities) != 1 || coverage.Capabilities[0].State != assessment.StateExpired || !strings.Contains(coverage.Capabilities[0].Reason, "nuclei") {
		t.Fatalf("a mid-run expiry reported by nuclei left the capability verified: %+v", coverage.Capabilities)
	}
	// A named identity losing its own session does not downgrade the primary capability.
	role := expired
	role.AuthIdentity = "viewer"
	record.ScannerRuns = []scanner.Run{role}
	if got := buildAssessmentCoverage("expired-role", record, "").Capabilities[0].State; got != assessment.StateVerified {
		t.Fatalf("an additional identity's expiry changed the primary capability to %s", got)
	}
}
