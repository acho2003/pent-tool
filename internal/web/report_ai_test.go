package web

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
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

func TestTypedScannerReportIncludesCoverageWithoutCredentialReferences(t *testing.T) {
	s := newTestServer(t, nil)
	dir := t.TempDir()
	artifact := filepath.Join(dir, "nuclei.jsonl")
	if err := os.WriteFile(artifact, []byte(`{"template-id":"test","matched-at":"https://app.example.test/health","host":"app.example.test","info":{"name":"Scanner issue","severity":"high"}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan := &scanner.AssessmentPlan{
		Config:       assessment.AssessmentConfig{Mode: assessment.ModeGrayBox, Types: []assessment.Type{assessment.TypeAPI}, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.example.test"}}},
		Capabilities: []assessment.CapabilityEvidence{{Capability: assessment.CapAuthWeb, TargetID: "app", ReferenceID: "opaque-secret-reference", State: assessment.StateAvailable, Reason: "verification required"}},
		Jobs:         []scanner.PlanJob{{ID: "nuclei:app", State: scanner.PlanSelected, Scanner: "nuclei", Variant: "nuclei", TargetID: "app", Target: "https://app.example.test", AssessmentTypes: []assessment.Type{assessment.TypeAPI}}},
		Coverage:     []scanner.TypeCoverage{{Type: assessment.TypeAPI, State: "planned"}},
		APIEndpoints: []scanner.APIEndpoint{{TargetID: "app", Method: "GET", Path: "/health", Resolved: true, Eligible: true}},
		Fingerprint:  "sha256:typed-report",
	}
	run := scanner.Run{Scanner: "nuclei", Variant: "nuclei", Target: "https://app.example.test", PlanFingerprint: plan.Fingerprint, Status: "completed", ArtifactPath: artifact}
	run.Checksum = scanner.CalculateChecksum(run)
	record := &ScanRecord{SchemaVersion: 3, ID: "typed-report", Target: "https://app.example.test", Status: "finished", Profile: "web-gentle", AssessmentPlan: plan, PlanFingerprint: plan.Fingerprint, ScannerRuns: []scanner.Run{run}}
	if path := s.generateScannerReport(record, dir, ""); path == "" {
		t.Fatal("typed report PDF was not generated")
	}
	data, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest reportManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != 3 || manifest.Assessment == nil || manifest.Assessment.State != "partial" || len(manifest.Assessment.Operations) != 1 {
		t.Fatalf("typed coverage missing from report: %+v", manifest.Assessment)
	}
	if strings.Contains(string(data), "opaque-secret-reference") {
		t.Fatal("report exposed a credential reference")
	}
	lines := assessmentCoverageLines(*manifest.Assessment)
	if !slices.ContainsFunc(lines, func(line string) bool { return strings.Contains(line, "API GET /health: inventoried_not_executed") }) {
		t.Fatalf("PDF coverage lines omit untested API operation: %v", lines)
	}
}

func TestFallbackFindingTraceIsPreserved(t *testing.T) {
	in := []scanner.Finding{{SourceID: "trivy:CVE-1:app", Scanner: "trivy", Title: "Package issue", Severity: "high", Evidence: "1.0", EvidenceRef: "results.json#trivy:CVE-1:app"}}
	out := fallbackReportFindings(in)
	if len(out) != 1 || out[0].SourceID != in[0].SourceID || out[0].Scanner != "trivy" || out[0].Evidence != "1.0" || out[0].EvidenceRef != in[0].EvidenceRef {
		t.Fatalf("trace lost: %#v", out)
	}
}

func TestScannerReportIncludesRedactedScannerLocationsAndEvidence(t *testing.T) {
	s := newTestServer(t, nil)
	dir := t.TempDir()
	artifact := filepath.Join(dir, "nuclei.jsonl")
	body := `{"template-id":"reflected-value","matched-at":"https://example.test/search?access_token=must-not-leak&q=test","host":"example.test","matcher-name":"Authorization: Bearer scanner-secret","info":{"name":"Reflected value","severity":"medium"}}` + "\n"
	if err := os.WriteFile(artifact, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	run := scanner.Run{Scanner: "nuclei", Target: "https://example.test", Scope: "host:example.test", Status: "completed", ArtifactPath: artifact}
	run.Checksum = scanner.CalculateChecksum(run)
	rec := &ScanRecord{SchemaVersion: scanner.SchemaVersion, ID: "evidence-report", Target: "https://example.test", Status: "finished", ScannerRuns: []scanner.Run{run}, Events: []WSEvent{}}
	reportPath := s.generateScannerReport(rec, dir, "")
	if reportPath == "" {
		t.Fatal("report generation failed")
	}
	pdf, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(pdf) == 0 || !strings.Contains(strings.ToLower(rec.Vulns[0].TechnicalAnalysis), "affected locations") || !strings.Contains(rec.Vulns[0].TechnicalAnalysis, "[REDACTED]") {
		t.Fatal("PDF input did not include the affected-location evidence section or redaction")
	}
	data, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, secret := range []string{"must-not-leak", "scanner-secret"} {
		if strings.Contains(text, secret) {
			t.Errorf("report manifest leaked %q", secret)
		}
	}
	var manifest reportManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Findings) != 1 || len(manifest.Findings[0].EvidenceItems) != 1 {
		t.Fatalf("evidence items missing: %+v", manifest.Findings)
	}
	item := manifest.Findings[0].EvidenceItems[0]
	if item.Scanner != "nuclei" || item.Endpoint == "" || !strings.Contains(item.Endpoint, "[REDACTED]") || !strings.Contains(item.Evidence, "[REDACTED]") {
		t.Fatalf("report observation was not enriched/redacted: %+v", item)
	}
	if !strings.Contains(string(rec.Vulns[0].TechnicalAnalysis), "Affected locations") && !strings.Contains(string(rec.Vulns[0].TechnicalAnalysis), "affected locations") {
		t.Fatalf("PDF finding data lacks location/evidence section: %q", rec.Vulns[0].TechnicalAnalysis)
	}
}

func TestScannerReportGroupsByScopeAndMergesCVE(t *testing.T) {
	s := newTestServer(t, nil)
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
	if manifest.SchemaVersion != 2 || manifest.PromptVersion != "scanner-report-v2" {
		t.Fatalf("manifest version = %d / %q, want 2 / scanner-report-v2", manifest.SchemaVersion, manifest.PromptVersion)
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
	// The CVE observations use different, partly ambiguous locations (URL vs
	// service port), so they remain separate instead of implying correlation.
	if len(manifest.Findings) != 5 {
		t.Fatalf("want 5 findings (location-ambiguous CVE observations separate), got %d: %#v", len(manifest.Findings), manifest.Findings)
	}
	var order []string
	for _, f := range manifest.Findings {
		order = append(order, f.Scope)
	}
	if want := []string{"host:a.example.test", "host:a.example.test", "host:a.example.test", "host:b.example.test", "source:main"}; !slices.Equal(order, want) {
		t.Fatalf("finding scope order = %v, want %v", order, want)
	}
	if first, second := manifest.Findings[0], manifest.Findings[1]; len(first.Sources) != 0 || first.CVE == "" || len(second.Sources) != 0 || second.CVE == "" {
		t.Fatalf("ambiguous same-CVE locations must remain separate: %#v, %#v", first, second)
	}
	if nm := manifest.Findings[2]; nm.Scanner != "nmap" || nm.Scope != "host:a.example.test" {
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

// An unrated scanner severity stays flagged in the deterministic report.
func TestFallbackFindingKeepsSeverityUnrated(t *testing.T) {
	in := []scanner.Finding{
		{SourceID: "osv:x:GO-1", Scanner: "osv", Severity: "medium", SeverityUnrated: true, Scope: "source:main", EvidenceRef: "osv.json#osv:x:GO-1"},
		{SourceID: "osv:x:GO-2", Scanner: "osv", Severity: "high", Scope: "source:main", EvidenceRef: "osv.json#osv:x:GO-2"},
	}
	out := fallbackReportFindings(in)
	if len(out) != 2 || !out[0].SeverityUnrated || out[1].SeverityUnrated {
		t.Fatalf("unrated flag not carried: %#v", out)
	}
}
