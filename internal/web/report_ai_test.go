package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

// TestGenerateCLIReport exercises the exported CLI/TUI entry point directly.
// Increment 2's fan-out makes the number of scanner Runs variable (recon runs
// plus per-host scan runs), so completeness is "every run terminal", not
// "len(runs) == len(scanner.OrderedNames)".
func TestGenerateCLIReport(t *testing.T) {
	t.Run("variable-length terminal run set succeeds", func(t *testing.T) {
		dir := t.TempDir()
		artifact := filepath.Join(dir, "nuclei.jsonl")
		if err := os.WriteFile(artifact, []byte(`{"template-id":"test","matched-at":"https://example.test","host":"example.test","info":{"name":"Scanner issue","severity":"high"}}`+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		runs := []scanner.Run{
			{Scanner: "subfinder", Scope: "recon:example.test", Target: "example.test", Status: "completed", StartedAt: "2026-08-03T00:00:00Z", FinishedAt: "2026-08-03T00:00:01Z"},
			{Scanner: "nuclei", Scope: "host:a.example.test", Target: "a.example.test", Status: "completed", ArtifactPath: artifact, StartedAt: "2026-08-03T00:00:01Z", FinishedAt: "2026-08-03T00:00:02Z"},
			{Scanner: "zap", Scope: "host:b.example.test", Target: "b.example.test", Status: "failed", StartedAt: "2026-08-03T00:00:01Z", FinishedAt: "2026-08-03T00:00:02Z"},
		}
		for i := range runs {
			runs[i].Checksum = scanner.CalculateChecksum(runs[i])
		}
		cfg := &config.Config{DataDir: dir}
		path, err := GenerateCLIReport(cfg, "example.test", dir, runs)
		if err != nil {
			t.Fatalf("expected success with %d terminal runs, got error: %v", len(runs), err)
		}
		if path == "" {
			t.Fatal("expected non-empty report path")
		}
	})

	t.Run("no runs errors", func(t *testing.T) {
		cfg := &config.Config{DataDir: t.TempDir()}
		if _, err := GenerateCLIReport(cfg, "example.test", t.TempDir(), nil); err == nil {
			t.Fatal("expected error for empty run set")
		}
	})

	t.Run("non-terminal run still errors", func(t *testing.T) {
		dir := t.TempDir()
		runs := []scanner.Run{
			{Scanner: "subfinder", Scope: "recon:example.test", Status: "completed"},
			{Scanner: "nuclei", Scope: "host:a.example.test", Status: "running"},
		}
		cfg := &config.Config{DataDir: dir}
		if _, err := GenerateCLIReport(cfg, "example.test", dir, runs); err == nil {
			t.Fatal("expected error for non-terminal run")
		}
	})
}

func TestScannerReportFallsBackWithoutAI(t *testing.T) {
	s := newTestServer(t, nil)
	s.cfg.LLM = ""
	dir := t.TempDir()
	artifact := filepath.Join(dir, "nuclei.jsonl")
	if err := os.WriteFile(artifact, []byte(`{"template-id":"test","matched-at":"https://example.test","host":"example.test","info":{"name":"Scanner issue","severity":"high"}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Variable-length run set (a recon run plus two host-scoped scan runs)
	// rather than one run per scanner.OrderedNames entry: Increment 2's
	// fan-out means the number of runs is no longer fixed at five.
	runs := []scanner.Run{
		{Scanner: "subfinder", Scope: "recon:example.test", Target: "example.test", Status: "completed"},
		{Scanner: "nuclei", Scope: "host:a.example.test", Target: "example.test", Status: "completed", ArtifactPath: artifact},
		{Scanner: "zap", Scope: "host:b.example.test", Target: "example.test", Status: "not_applicable"},
	}
	for i := range runs {
		runs[i].Checksum = scanner.CalculateChecksum(runs[i])
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
	if len(manifest.SourceRuns) != len(runs) || manifest.SourceRuns[0].Checksum == "" {
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
	// Variable-length run set: a recon run plus two host-scoped scan runs,
	// not one run per scanner.OrderedNames entry.
	runs := []scanner.Run{
		{Scanner: "subfinder", Scope: "recon:example.test", Status: "completed"},
		{Scanner: "nuclei", Scope: "host:a.example.test", Status: "completed", ArtifactPath: artifact},
		{Scanner: "zap", Scope: "host:b.example.test", Status: "not_applicable"},
	}
	for i := range runs {
		runs[i].Checksum = scanner.CalculateChecksum(runs[i])
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
