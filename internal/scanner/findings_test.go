package scanner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBuildFindingsSnapshotHostAndParameterCorrelation(t *testing.T) {
	runs := make([]Run, 0, 50)
	for i := 0; i < 50; i++ {
		path := fmt.Sprintf("https://target.test/path/%d", i)
		artifact := writeFixture(t, fmt.Sprintf("zap-%d.json", i), fmt.Sprintf(`{"alerts":[{"pluginId":"10038","name":"Content Security Policy (CSP) Header Not Set","riskdesc":"Medium","cweid":"693","instances":[{"uri":%q,"method":"GET"}]}]}`, path))
		runs = append(runs, Run{Scanner: "zap", Scope: "host:target.test", Status: "completed", ArtifactPath: artifact, FinishedAt: "2026-01-01T00:00:00Z"})
	}
	snapshot, errs := BuildFindingsSnapshot(runs, nil)
	if len(errs) != 0 {
		t.Fatalf("errors = %v", errs)
	}
	if snapshot.Summary.RawObservations != 50 || snapshot.Summary.UniqueFindings != 1 {
		t.Fatalf("summary = %+v", snapshot.Summary)
	}
	if got := snapshot.UniqueFindings[0].AffectedEndpointCount; got != 50 {
		t.Fatalf("endpoints = %d", got)
	}
}

func TestBuildFindingsSnapshotParameterValuesShareFinding(t *testing.T) {
	legacy := []Finding{
		{SourceID: "zap:1", Scanner: "zap", Title: "SQL Injection", Severity: "high", Target: "target.test", Endpoint: "https://target.test/product?id=1", Method: "GET", Parameter: "id"},
		{SourceID: "zap:2", Scanner: "zap", Title: "SQL Injection", Severity: "high", Target: "target.test", Endpoint: "https://target.test/product?id=2", Method: "GET", Parameter: "id"},
		{SourceID: "zap:3", Scanner: "zap", Title: "SQL Injection", Severity: "high", Target: "target.test", Endpoint: "https://target.test/product?id=3", Method: "GET", Parameter: "id"},
	}
	snapshot, errs := BuildFindingsSnapshot(nil, legacy)
	if len(errs) != 0 || len(snapshot.UniqueFindings) != 1 {
		t.Fatalf("snapshot = %#v errors=%v", snapshot, errs)
	}
	if snapshot.UniqueFindings[0].ObservationCount != 3 {
		t.Fatalf("observations = %d", snapshot.UniqueFindings[0].ObservationCount)
	}
}

func TestBuildFindingsSnapshotTechnologyIsObservation(t *testing.T) {
	snapshot, errs := BuildFindingsSnapshot(nil, []Finding{{SourceID: "nuclei:tech", Scanner: "nuclei", Title: "Wappalyzer Technology Detection", Severity: "info", Target: "target.test", Endpoint: "https://target.test/"}})
	if len(errs) != 0 || len(snapshot.UniqueFindings) != 1 {
		t.Fatalf("snapshot = %#v errors=%v", snapshot, errs)
	}
	if snapshot.UniqueFindings[0].Status != StatusObservation || snapshot.Summary.ActiveSecurityFindings != 0 {
		t.Fatalf("finding = %#v summary=%+v", snapshot.UniqueFindings[0], snapshot.Summary)
	}
}

func TestValidateSPAFallbackMatchesCanary(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body>single app shell</body></html>"))
	}))
	defer server.Close()
	snapshot, _ := BuildFindingsSnapshot(nil, []Finding{{SourceID: "nikto:1", Scanner: "nikto", Title: "Exposed .env file", Severity: "medium", Endpoint: server.URL + "/.env", Target: "127.0.0.1"}})
	results := ValidateSPAFallback(t.Context(), snapshot)
	if len(results) != 1 || results[0].Reason != "SPA_OR_WILDCARD_FALLBACK" {
		t.Fatalf("results = %#v", results)
	}
}
