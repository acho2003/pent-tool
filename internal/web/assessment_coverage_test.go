package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
		APIEndpoints: []scanner.APIEndpoint{{TargetID: "app", Method: "GET", Path: "/users/{id}", Origin: "https://app.example.test", Source: "openapi", Resolved: true}},
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
