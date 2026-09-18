package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

func TestScannerReportFallsBackWithoutAI(t *testing.T) {
	s := newTestServer(t, nil)
	s.cfg.LLM = ""
	dir := t.TempDir()
	artifact := filepath.Join(dir, "nuclei.jsonl")
	if err := os.WriteFile(artifact, []byte(`{"template-id":"test","matched-at":"https://example.test","host":"example.test","info":{"name":"Scanner issue","severity":"high"}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runs := make([]scanner.Run, 0, len(scanner.OrderedNames))
	for _, name := range scanner.OrderedNames {
		r := scanner.Run{Scanner: name, Target: "example.test", Status: "not_applicable", Checksum: name + "-checksum"}
		if name == "nuclei" {
			r.Status, r.ArtifactPath = "completed", artifact
		}
		r.Checksum = scanner.CalculateChecksum(r)
		runs = append(runs, r)
	}
	rec := &ScanRecord{SchemaVersion: scanner.SchemaVersion, ID: "fallback-scan", Target: "example.test", StartedAt: "2026-08-03T00:00:00Z", FinishedAt: "2026-08-03T00:01:00Z", Status: "finished", ScannerRuns: runs, Events: []WSEvent{}, Vulns: []VulnSummary{}}
	path := s.generateScannerReport(rec, dir, "")
	if path == "" {
		t.Fatal("expected fallback PDF")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("fallback PDF: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest reportManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Mode != "deterministic_fallback" {
		t.Fatalf("mode = %q", manifest.Mode)
	}
	if len(manifest.Findings) != 1 || manifest.Findings[0].SourceID == "" || manifest.Findings[0].EvidenceRef == "" {
		t.Fatalf("findings = %#v", manifest.Findings)
	}
	if len(manifest.SourceRuns) != 5 || manifest.SourceRuns[0].Checksum == "" {
		t.Fatalf("source runs = %#v", manifest.SourceRuns)
	}
}

func TestScannerReportFallsBackOnProviderFailure(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "offline", http.StatusServiceUnavailable)
	}))
	defer provider.Close()
	s := newTestServer(t, nil)
	s.cfg.LLM = "report-model"
	s.cfg.APIBase = provider.URL
	s.cfg.APIKey = "test-key"
	s.cfg.LLMMaxRetries = 1
	dir := t.TempDir()
	artifact := filepath.Join(dir, "nuclei.jsonl")
	if err := os.WriteFile(artifact, []byte(`{"template-id":"test","matched-at":"https://example.test","info":{"name":"Issue","severity":"medium"}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runs := make([]scanner.Run, 0, 5)
	for _, name := range scanner.OrderedNames {
		run := scanner.Run{Scanner: name, Status: "not_applicable", Checksum: name}
		if name == "nuclei" {
			run.Status, run.ArtifactPath = "completed", artifact
		}
		run.Checksum = scanner.CalculateChecksum(run)
		runs = append(runs, run)
	}
	rec := &ScanRecord{SchemaVersion: 2, ID: "provider-fallback", Target: "example.test", Status: "finished", ScannerRuns: runs, Events: []WSEvent{}, Vulns: []VulnSummary{}}
	if got := s.generateScannerReport(rec, dir, ""); got == "" || rec.ReportMode != "deterministic_fallback" {
		t.Fatalf("report=%q mode=%q", got, rec.ReportMode)
	}
}

func TestFallbackFindingTraceIsPreserved(t *testing.T) {
	in := []scanner.Finding{{SourceID: "trivy:CVE-1:app", Scanner: "trivy", Title: "Package issue", Severity: "high", Evidence: "1.0", EvidenceRef: "results.json#trivy:CVE-1:app"}}
	out := fallbackReportFindings(in)
	if len(out) != 1 || out[0].SourceID != in[0].SourceID || out[0].Scanner != "trivy" || out[0].Evidence != "1.0" || out[0].EvidenceRef != in[0].EvidenceRef {
		t.Fatalf("trace lost: %#v", out)
	}
}

func TestScannerReportRejectsChangedArtifact(t *testing.T) {
	s := newTestServer(t, nil)
	dir := t.TempDir()
	artifact := filepath.Join(dir, "nuclei.jsonl")
	if err := os.WriteFile(artifact, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := scanner.Run{Scanner: "nuclei", Status: "completed", ArtifactPath: artifact}
	run.Checksum = scanner.CalculateChecksum(run)
	if err := os.WriteFile(artifact, []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := &ScanRecord{SchemaVersion: 2, ID: "changed", ScannerRuns: []scanner.Run{run}}
	if path := s.generateScannerReport(rec, dir, ""); path != "" {
		t.Fatalf("generated report from changed artifact: %s", path)
	}
}
