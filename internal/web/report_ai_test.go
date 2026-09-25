package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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

// TestScannerReportAIKeepsMergedTraceAndSeverityFloor is the AI success path
// for a cross-scanner merged finding. The provider must only see primary
// source_ids (a secondary one in sources[] would be echoed back and rejected by
// the allow-map, forcing a fallback), the finding must keep its scope and both
// sources, and the AI may not lower the scanner-reported severity.
func TestScannerReportAIKeepsMergedTraceAndSeverityFloor(t *testing.T) {
	const primaryID = "nuclei:CVE-2021-41773:https://a.example.test/cgi-bin/"
	const secondaryID = "openvas:r1"
	var (
		mu     sync.Mutex
		bodies []string
	)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		content, _ := json.Marshal(map[string]any{"findings": []map[string]any{{
			"source_id":          primaryID,
			"scanner":            "nuclei",
			"title":              "Apache HTTP Server path traversal",
			"severity":           "low", // below the merged scanner severity
			"explanation":        "Scanners reported CVE-2021-41773 on this host.",
			"evidence_reference": "ignored; restored from the source",
			"impact":             "File disclosure outside the document root.",
			"remediation":        "Upgrade Apache HTTP Server to 2.4.51 or later.",
		}}})
		resp, _ := json.Marshal(map[string]any{"choices": []map[string]any{{"message": map[string]any{"role": "assistant", "content": string(content)}}}})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(resp)
	}))
	defer provider.Close()
	s := newTestServer(t, nil)
	s.cfg.LLM = "report-model"
	s.cfg.APIBase = provider.URL
	s.cfg.APIKey = "test-key"
	s.cfg.LLMMaxRetries = 1
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	nucleiA := write("nuclei-a.jsonl", `{"template-id":"CVE-2021-41773","matched-at":"https://a.example.test/cgi-bin/","host":"a.example.test","info":{"name":"Apache Path Traversal","severity":"critical","classification":{"cve-id":["cve-2021-41773"],"cvss-score":9.8}}}`+"\n")
	openvasA := write("openvas-a.xml", `<get_reports_response><report><results><result id="r1"><name>Apache Path Traversal</name><host>a.example.test</host><port>443/tcp</port><severity>7.5</severity><nvt oid="1.3.6"><cve>CVE-2021-41773</cve></nvt></result></results></report></get_reports_response>`)
	runs := []scanner.Run{
		{Scanner: "nuclei", Scope: "host:a.example.test", Target: "a.example.test", Status: "completed", ArtifactPath: nucleiA},
		{Scanner: "openvas", Scope: "host:a.example.test", Target: "a.example.test", Status: "completed", ArtifactPath: openvasA},
	}
	for i := range runs {
		runs[i].Checksum = scanner.CalculateChecksum(runs[i])
	}
	rec := &ScanRecord{SchemaVersion: scanner.SchemaVersion, ID: "ai-report", Target: "a.example.test", Status: "finished", ScannerRuns: runs, Events: []WSEvent{}, Vulns: []VulnSummary{}}
	if path := s.generateScannerReport(rec, dir, ""); path == "" {
		t.Fatal("report generation failed")
	}
	data, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest reportManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Mode != "ai" {
		t.Fatalf("mode = %q, want ai", manifest.Mode)
	}
	if len(manifest.Findings) != 1 {
		t.Fatalf("findings = %#v, want the one merged finding", manifest.Findings)
	}
	f := manifest.Findings[0]
	if f.SourceID != primaryID || f.Scope != "host:a.example.test" || len(f.Sources) != 2 {
		t.Fatalf("merged finding lost its trace: %#v", f)
	}
	if f.Severity != "critical" {
		t.Fatalf("severity = %q, want the source severity critical (AI may not downgrade)", f.Severity)
	}
	// The projection sent to the model must not mutate the caller's findings.
	parsed, _ := scanner.ParseRuns(runs)
	if _, err := s.aiReportFindings(parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 1 || len(parsed[0].Sources) != 2 {
		t.Fatalf("aiReportFindings mutated its input: %#v", parsed)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) == 0 {
		t.Fatal("provider received no request")
	}
	for _, b := range bodies {
		if !strings.Contains(b, primaryID) {
			t.Fatalf("provider request lacks the primary source_id: %s", b)
		}
		if strings.Contains(b, secondaryID) {
			t.Fatalf("provider request exposes secondary source_id %q: %s", secondaryID, b)
		}
	}
}

func TestFallbackFindingTraceIsPreserved(t *testing.T) {
	in := []scanner.Finding{{SourceID: "trivy:CVE-1:app", Scanner: "trivy", Title: "Package issue", Severity: "high", Evidence: "1.0", EvidenceRef: "results.json#trivy:CVE-1:app"}}
	out := fallbackReportFindings(in)
	if len(out) != 1 || out[0].SourceID != in[0].SourceID || out[0].Scanner != "trivy" || out[0].Evidence != "1.0" || out[0].EvidenceRef != in[0].EvidenceRef {
		t.Fatalf("trace lost: %#v", out)
	}
}

func TestScannerReportGroupsByScopeAndMergesCVE(t *testing.T) {
	s := newTestServer(t, nil)
	s.cfg.LLM = ""
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	nucleiA := write("nuclei-a.jsonl", `{"template-id":"CVE-2021-41773","matched-at":"https://a.example.test/cgi-bin/","host":"a.example.test","info":{"name":"Apache Path Traversal","severity":"critical","classification":{"cve-id":["cve-2021-41773"],"cvss-score":9.8}}}`+"\n")
	openvasA := write("openvas-a.xml", `<get_reports_response><report><results><result id="r1"><name>Apache Path Traversal</name><host>a.example.test</host><port>443/tcp</port><severity>7.5</severity><nvt oid="1.3.6"><cve>CVE-2021-41773</cve></nvt></result></results></report></get_reports_response>`)
	nucleiB := write("nuclei-b.jsonl", `{"template-id":"missing-hsts","matched-at":"https://b.example.test","host":"b.example.test","info":{"name":"Missing HSTS","severity":"info"}}`+"\n")
	nmapA := write("nmap-a.xml", `<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.5" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.2"/></port></ports></host></nmaprun>`)
	trivySrc := write("trivy.json", `{"Results":[{"Target":"go.sum","Vulnerabilities":[{"VulnerabilityID":"CVE-2023-1111","PkgName":"lib","Severity":"HIGH"}]}]}`)
	writeReconScopes(t, dir, []scanner.Scope{
		{ID: "host:a.example.test", Kind: scanner.ScopeHost, Target: "a.example.test", Evidence: scanner.HostEvidence{OpenPorts: []scanner.Port{{Number: 443, Protocol: "tcp", Service: "https"}, {Number: 22, Protocol: "tcp", Service: "ssh"}}}},
		{ID: "host:b.example.test", Kind: scanner.ScopeHost, Target: "b.example.test", Evidence: scanner.HostEvidence{LiveURLs: []string{"https://b.example.test"}}},
	})
	runs := []scanner.Run{
		{Scanner: "subfinder", Scope: "recon:example.test", Target: "example.test", Status: "completed"},
		// A per-host nmap recon run: its findings belong to host a, not recon.
		{Scanner: "nmap", Scope: "recon:example.test:a.example.test", Target: "example.test", Status: "completed", ArtifactPath: nmapA},
		{Scanner: "nuclei", Scope: "host:a.example.test", Target: "a.example.test", Status: "completed", ArtifactPath: nucleiA},
		{Scanner: "openvas", Scope: "host:a.example.test", Target: "a.example.test", Status: "completed", ArtifactPath: openvasA},
		{Scanner: "trivy", Scope: "source:main", Target: filepath.Join(dir, "src"), Status: "completed", ArtifactPath: trivySrc},
		{Scanner: "nuclei", Scope: "host:b.example.test", Target: "b.example.test", Status: "completed", ArtifactPath: nucleiB},
	}
	for i := range runs {
		runs[i].Checksum = scanner.CalculateChecksum(runs[i])
	}
	rec := &ScanRecord{SchemaVersion: scanner.SchemaVersion, ID: "scope-report", Target: "example.test", Status: "finished", ScannerRuns: runs, Events: []WSEvent{}, Vulns: []VulnSummary{}}
	if path := s.generateScannerReport(rec, dir, ""); path == "" {
		t.Fatal("report generation failed")
	}
	data, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest reportManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	var scopeIDs []string
	for _, sc := range manifest.Scopes {
		scopeIDs = append(scopeIDs, sc.ID)
	}
	if want := []string{"host:a.example.test", "host:b.example.test", "source:main"}; !slices.Equal(scopeIDs, want) {
		t.Fatalf("scopes = %v, want %v", scopeIDs, want)
	}
	// The nmap run is seen first but carries the request target; the host
	// scope must still be labelled with its own host.
	if got := manifest.Scopes[0].Target; got != "a.example.test" {
		t.Fatalf("host a target = %q, want a.example.test", got)
	}
	var hostARuns []string
	for _, r := range manifest.Scopes[0].Runs {
		hostARuns = append(hostARuns, r.Scanner)
	}
	if want := []string{"nmap", "nuclei", "openvas"}; !slices.Equal(hostARuns, want) {
		t.Fatalf("host a coverage runs = %v, want %v", hostARuns, want)
	}
	if got := manifest.Scopes[0].Tracks; !slices.Equal(got, []string{"web", "server"}) {
		t.Fatalf("host a tracks = %v", got)
	}
	if got := manifest.Scopes[1].Tracks; !slices.Equal(got, []string{"web"}) {
		t.Fatalf("host b tracks = %v", got)
	}
	if manifest.Recon == nil || manifest.Recon.Hosts != 2 || manifest.Recon.OpenPorts != 2 {
		t.Fatalf("recon = %#v", manifest.Recon)
	}
	// 4 = merged CVE (nuclei+openvas) + nmap open port on host a, HSTS on host
	// b, trivy on source.
	if len(manifest.Findings) != 4 {
		t.Fatalf("want 4 findings (CVE merged), got %d: %#v", len(manifest.Findings), manifest.Findings)
	}
	var order []string
	for _, f := range manifest.Findings {
		order = append(order, f.Scope)
	}
	if want := []string{"host:a.example.test", "host:a.example.test", "host:b.example.test", "source:main"}; !slices.Equal(order, want) {
		t.Fatalf("finding scope order = %v, want %v", order, want)
	}
	if merged := manifest.Findings[0]; len(merged.Sources) != 2 || merged.Severity != "critical" {
		t.Fatalf("merged finding = %#v", merged)
	}
	if nm := manifest.Findings[1]; nm.Scanner != "nmap" || nm.Scope != "host:a.example.test" {
		t.Fatalf("nmap finding = %#v, want scanner nmap in host:a.example.test", nm)
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
