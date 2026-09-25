package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFixture(t *testing.T, name, data string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseOSVFindings(t *testing.T) {
	body := `{"results":[{"source":{"path":"go.mod"},"packages":[{"package":{"name":"golang.org/x/net"},"vulnerabilities":[{"id":"GHSA-vvpx","summary":"DoS","aliases":["CVE-2023-44487"]}]}]}]}`
	p := writeFixture(t, "results.json", body)
	got, err := ParseRun(Run{Scanner: "osv", ArtifactPath: p})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SourceID != "osv:golang.org/x/net:GHSA-vvpx" {
		t.Fatalf("parsed %#v", got)
	}
	if got[0].CVE != "CVE-2023-44487" {
		t.Errorf("CVE = %q", got[0].CVE)
	}
}

func TestNativeFormatParsers(t *testing.T) {
	tests := []struct{ name, scanner, body string }{
		{"nuclei", "nuclei", `{"template-id":"cve-test","matched-at":"https://e.test/a","host":"e.test","info":{"name":"Test","severity":"high"}}` + "\n"},
		{"zap", "zap", `{"alerts":[{"pluginId":"1","name":"Header","riskdesc":"Medium (Medium)","instances":[{"uri":"https://e.test"}]}]}`},
		{"zap alerts view", "zap", `{"alerts":[{"pluginId":"10038","name":"Missing CSP","risk":"Medium","url":"https://e.test/a","description":"d","cweid":"693"}]}`},
		{"openvas", "openvas", `<get_reports_response><report><results><result id="r1"><name>TLS</name><host>e.test</host><port>443/tcp</port><severity>5.0</severity><nvt oid="1.2.3"/></result></results></report></get_reports_response>`},
		{"trivy", "trivy", `{"Results":[{"Target":"app","Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"lib","Severity":"CRITICAL"}]}]}`},
		{"vuls", "vuls", `{"serverName":"prod","scannedCves":{"CVE-2":{"title":"Kernel","cvss3Score":7.5}}}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := writeFixture(t, "result.json", tc.body)
			if tc.scanner == "openvas" {
				p = writeFixture(t, "result.xml", tc.body)
			}
			got, err := ParseRun(Run{Scanner: tc.scanner, ArtifactPath: p})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0].SourceID == "" || got[0].Scanner != tc.scanner {
				t.Fatalf("parsed %#v", got)
			}
		})
	}
}

func TestMalformedAndDuplicateInput(t *testing.T) {
	bad := writeFixture(t, "bad.jsonl", "{bad\n")
	if _, err := ParseRun(Run{Scanner: "nuclei", ArtifactPath: bad}); err == nil {
		t.Error("malformed input accepted")
	}
	p := writeFixture(t, "dupe.jsonl", `{"template-id":"x","matched-at":"u","info":{"severity":"low"}}`+"\n"+`{"template-id":"x","matched-at":"u","info":{"severity":"low"}}`+"\n")
	findings, errs := ParseRuns([]Run{{Scanner: "nuclei", Status: "completed", ArtifactPath: p}})
	if len(errs) != 0 || len(findings) != 1 {
		t.Fatalf("findings=%d errors=%v", len(findings), errs)
	}
}

func TestPartiallyWrittenNucleiKeepsCompleteRecords(t *testing.T) {
	p := writeFixture(t, "partial.jsonl", `{"template-id":"x","matched-at":"u","info":{"severity":"low"}}`+"\n"+`{"template-id":`)
	findings, errs := ParseRuns([]Run{{Scanner: "nuclei", Status: "completed", ArtifactPath: p}})
	if len(errs) != 1 || len(findings) != 1 || findings[0].EvidenceRef == "" {
		t.Fatalf("findings=%#v errors=%v", findings, errs)
	}
}

func TestParseNmapPorts(t *testing.T) {
	xml := `<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.5" addrtype="ipv4"/>` +
		`<ports><port protocol="tcp" portid="22"><state state="open"/>` +
		`<service name="ssh" product="OpenSSH" version="9.2"/></port>` +
		`<port protocol="tcp" portid="443"><state state="closed"/>` +
		`<service name="https"/></port></ports></host></nmaprun>`
	dir := t.TempDir()
	p := filepath.Join(dir, "nmap.xml")
	if err := os.WriteFile(p, []byte(xml), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := parseNmap(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 { // only the open port
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	f := findings[0]
	if f.SourceID != "nmap:10.0.0.5:22" || f.Scanner != "nmap" || f.Endpoint != "22" {
		t.Fatalf("unexpected finding: %+v", f)
	}
	if f.Title != "ssh" {
		t.Fatalf("title = %q, want ssh", f.Title)
	}
}

// TestParseRunsSurfacesNmapFinding proves an nmap-sourced Run flows through
// the same ParseRuns path the report pipeline uses (internal/web/report_ai.go
// calls scanner.ParseRuns(rec.ScannerRuns)): the finding survives with its
// "nmap:" SourceID prefix and a stamped EvidenceRef, so nothing about the
// generic Run dispatch or dedup step drops recon-sourced findings before they
// ever reach the report's dynamic source-id allow-map.
func TestParseRunsSurfacesNmapFinding(t *testing.T) {
	xmlBody := `<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.5" addrtype="ipv4"/>` +
		`<ports><port protocol="tcp" portid="22"><state state="open"/>` +
		`<service name="ssh" product="OpenSSH" version="9.2"/></port></ports></host></nmaprun>`
	p := writeFixture(t, "nmap.xml", xmlBody)
	findings, errs := ParseRuns([]Run{{Scanner: "nmap", Status: "completed", ArtifactPath: p}})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %#v", len(findings), findings)
	}
	f := findings[0]
	if !strings.HasPrefix(f.SourceID, "nmap:") {
		t.Fatalf("SourceID = %q, want nmap: prefix", f.SourceID)
	}
	if f.Scanner != "nmap" {
		t.Fatalf("Scanner = %q, want nmap", f.Scanner)
	}
	if f.EvidenceRef == "" || !strings.Contains(f.EvidenceRef, f.SourceID) {
		t.Fatalf("EvidenceRef = %q, want it to reference SourceID %q", f.EvidenceRef, f.SourceID)
	}
}

func TestParseRunEvidenceOnlyRecon(t *testing.T) {
	for _, name := range []string{"subfinder", "httpx"} {
		got, err := ParseRun(Run{Scanner: name, Status: "completed"})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got) != 0 {
			t.Fatalf("%s produced %d findings, want 0", name, len(got))
		}
	}
}

func TestParseTestsslFindings(t *testing.T) {
	body := `[
	  {"id":"SSLv3","ip":"example.com/93.184.216.34","port":"443","severity":"OK","finding":"not offered"},
	  {"id":"cert_expirationStatus","ip":"example.com/93.184.216.34","port":"443","severity":"HIGH","finding":"expired 3 days ago","cve":"","cwe":"CWE-298"},
	  {"id":"SWEET32","ip":"example.com/93.184.216.34","port":"443","severity":"MEDIUM","finding":"potentially vulnerable","cve":"CVE-2016-2183 CVE-2016-6329"}
	]`
	p := writeFixture(t, "results.json", body)
	got, err := ParseRun(Run{Scanner: "testssl", ArtifactPath: p})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 { // OK filtered out; HIGH + MEDIUM kept
		t.Fatalf("want 2 findings, got %d: %#v", len(got), got)
	}
	var sweet32 *Finding
	for i, f := range got {
		if f.Scanner != "testssl" {
			t.Errorf("scanner = %q", f.Scanner)
		}
		if !strings.HasPrefix(f.SourceID, "testssl:example.com:443:") {
			t.Errorf("SourceID = %q", f.SourceID)
		}
		if strings.HasSuffix(f.SourceID, ":SWEET32") {
			sweet32 = &got[i]
		}
	}
	// A space-separated multi-CVE entry keeps only the first CVE.
	if sweet32 == nil {
		t.Fatalf("SWEET32 finding missing: %#v", got)
	}
	if sweet32.CVE != "CVE-2016-2183" {
		t.Errorf("multi-CVE not narrowed to first: CVE = %q", sweet32.CVE)
	}
}

func TestParseSemgrepFindings(t *testing.T) {
	body := `{"results":[{"check_id":"go.lang.security.audit.xss","path":"web/h.go","start":{"line":42},"extra":{"message":"XSS","severity":"ERROR"}}]}`
	p := writeFixture(t, "results.json", body)
	got, err := ParseRun(Run{Scanner: "semgrep", ArtifactPath: p})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SourceID != "semgrep:go.lang.security.audit.xss:web/h.go:42" {
		t.Fatalf("parsed %#v", got)
	}
	if got[0].Severity != "high" {
		t.Errorf("severity = %q, want high", got[0].Severity)
	}
}

func TestParseGitleaksFindings(t *testing.T) {
	body := `[{"RuleID":"generic-api-key","File":"config.py","Commit":"abc123","StartLine":5,"Description":"API key"}]`
	p := writeFixture(t, "results.json", body)
	got, err := ParseRun(Run{Scanner: "gitleaks", ArtifactPath: p})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SourceID != "gitleaks:generic-api-key:config.py:abc123" {
		t.Fatalf("parsed %#v", got)
	}
}

func TestFindingScope(t *testing.T) {
	tests := []struct {
		name string
		run  Run
		want string
	}{
		{"pre-scope run folds to host", Run{Scanner: "nuclei", Target: "example.test"}, "host:example.test"},
		{"per-host nmap maps to host", Run{Scanner: "nmap", Scope: "recon:example.test:a.example.test", Target: "example.test"}, "host:a.example.test"},
		{"per-host nmap on colon target", Run{Scanner: "nmap", Scope: "recon:localhost:3000:localhost", Target: "localhost:3000"}, "host:localhost"},
		{"subfinder recon unchanged", Run{Scanner: "subfinder", Scope: "recon:example.test", Target: "example.test"}, "recon:example.test"},
		{"httpx recon unchanged", Run{Scanner: "httpx", Scope: "recon:localhost:3000", Target: "localhost:3000"}, "recon:localhost:3000"},
		{"host scope unchanged", Run{Scanner: "zap", Scope: "host:b.example.test", Target: "b.example.test"}, "host:b.example.test"},
		{"source scope unchanged", Run{Scanner: "trivy", Scope: "source:main", Target: "/src"}, "source:main"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := FindingScope(tc.run); got != tc.want {
				t.Fatalf("FindingScope(%+v) = %q, want %q", tc.run, got, tc.want)
			}
		})
	}
}

// TestParseRunsStampsNmapFindingWithHostScope proves a per-host nmap recon run's
// findings are stamped with that host's scope, not the recon scope the report
// drops.
func TestParseRunsStampsNmapFindingWithHostScope(t *testing.T) {
	xmlBody := `<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.5" addrtype="ipv4"/>` +
		`<ports><port protocol="tcp" portid="22"><state state="open"/>` +
		`<service name="ssh"/></port></ports></host></nmaprun>`
	p := writeFixture(t, "nmap.xml", xmlBody)
	findings, errs := ParseRuns([]Run{{Scanner: "nmap", Scope: "recon:example.test:a.example.test", Target: "example.test", Status: "completed", ArtifactPath: p}})
	if len(errs) != 0 || len(findings) != 1 {
		t.Fatalf("findings=%#v errors=%v", findings, errs)
	}
	if findings[0].Scope != "host:a.example.test" {
		t.Fatalf("Scope = %q, want host:a.example.test", findings[0].Scope)
	}
}

// TestDedupIsScopeAware proves two host scopes that resolve to one IP keep
// their own nmap finding: nmap SourceIDs use the IP, so a scope-blind dedup
// would collapse them.
func TestDedupIsScopeAware(t *testing.T) {
	xmlBody := `<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.5" addrtype="ipv4"/>` +
		`<ports><port protocol="tcp" portid="443"><state state="open"/>` +
		`<service name="https"/></port></ports></host></nmaprun>`
	pa := writeFixture(t, "nmap-a.xml", xmlBody)
	pb := writeFixture(t, "nmap-b.xml", xmlBody)
	findings, errs := ParseRuns([]Run{
		{Scanner: "nmap", Scope: "recon:example.test:a.example.test", Target: "example.test", Status: "completed", ArtifactPath: pa},
		{Scanner: "nmap", Scope: "recon:example.test:b.example.test", Target: "example.test", Status: "completed", ArtifactPath: pb},
	})
	if len(errs) != 0 {
		t.Fatalf("errors = %v", errs)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2 (one per scope): %#v", len(findings), findings)
	}
	if findings[0].Scope != "host:a.example.test" || findings[1].Scope != "host:b.example.test" {
		t.Fatalf("scopes = %q, %q", findings[0].Scope, findings[1].Scope)
	}
}

func TestParseOSVSeverity(t *testing.T) {
	body := `{"results":[{"source":{"path":"/src/go.mod"},"packages":[{"package":{"name":"golang.org/x/net","version":"0.1.0"},` +
		`"groups":[{"ids":["GHSA-aaaa","CVE-2023-44487"],"max_severity":"7.5"}],` +
		`"vulnerabilities":[` +
		`{"id":"GHSA-aaaa","summary":"grouped","aliases":["CVE-2023-44487"]},` +
		`{"id":"GHSA-bbbb","summary":"db-only","database_specific":{"severity":"MODERATE"}},` +
		`{"id":"GO-2024-1","summary":"unrated"}]}]}]}`
	got, err := ParseRun(Run{Scanner: "osv", ArtifactPath: writeFixture(t, "osv.json", body)})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("parsed %#v", got)
	}
	if got[0].Severity != "high" || got[0].CVSS != 7.5 || got[0].SeverityUnrated {
		t.Errorf("group max_severity: %#v", got[0])
	}
	if got[1].Severity != "medium" || got[1].SeverityUnrated {
		t.Errorf("database_specific MODERATE must be a rated medium: %#v", got[1])
	}
	if got[2].Severity != "medium" || !got[2].SeverityUnrated {
		t.Errorf("no severity data must be an unrated medium placeholder: %#v", got[2])
	}
	if got[0].Evidence != "golang.org/x/net@0.1.0" {
		t.Errorf("evidence = %q, want package@version", got[0].Evidence)
	}
}

func TestRelativeToRoot(t *testing.T) {
	cases := []struct{ p, root, want string }{
		{"/scan/src/web/package-lock.json", "/scan/src", "web/package-lock.json"},
		{"/scan/src/app.go:12", "/scan/src/", "app.go:12"},
		{"web/package-lock.json", "/scan/src", "web/package-lock.json"},
		{"/other/x.go", "/scan/src", "/other/x.go"},
		{"/scan/srcfoo/x.go", "/scan/src", "/scan/srcfoo/x.go"},
		{"/scan/src/x.go", "", "/scan/src/x.go"},
	}
	for _, c := range cases {
		if got := relativeToRoot(c.p, c.root); got != c.want {
			t.Errorf("relativeToRoot(%q, %q) = %q, want %q", c.p, c.root, got, c.want)
		}
	}
}

func TestParseRunsSourcePathsAndFileAwareMerge(t *testing.T) {
	root := t.TempDir()
	trivy := writeFixture(t, "trivy.json", `{"Results":[{"Target":"web/package-lock.json","Vulnerabilities":[{"VulnerabilityID":"CVE-2023-1111","PkgName":"lib","Severity":"HIGH"}]}]}`)
	osv := writeFixture(t, "osv.json", `{"results":[`+
		`{"source":{"path":"`+root+`/web/package-lock.json"},"packages":[{"package":{"name":"lib"},"vulnerabilities":[{"id":"GHSA-1","aliases":["CVE-2023-1111"]}]}]},`+
		`{"source":{"path":"`+root+`/api/package-lock.json"},"packages":[{"package":{"name":"lib"},"vulnerabilities":[{"id":"GHSA-1","aliases":["CVE-2023-1111"]}]}]}]}`)
	findings, errs := ParseRuns([]Run{
		{Scanner: "trivy", Scope: "source:main", Target: root, Status: "completed", ArtifactPath: trivy},
		{Scanner: "osv", Scope: "source:main", Target: root, Status: "completed", ArtifactPath: osv},
	})
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	if len(findings) != 2 {
		t.Fatalf("want web merged (trivy+osv) and api separate, got %d: %#v", len(findings), findings)
	}
	web, api := findings[0], findings[1]
	if web.Target != "web/package-lock.json" || len(web.Sources) != 2 {
		t.Fatalf("web finding = %#v", web)
	}
	if api.Scanner != "osv" || api.Target != "api/package-lock.json" || api.Endpoint != "api/package-lock.json" || len(api.Sources) != 0 {
		t.Fatalf("api finding must stay separate with relative paths, got %#v", api)
	}
	if !strings.HasPrefix(api.SourceID, "osv:lib:GHSA-1") {
		t.Fatalf("SourceID must be unchanged, got %q", api.SourceID)
	}
}
