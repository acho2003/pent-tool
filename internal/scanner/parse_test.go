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
