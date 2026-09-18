package scanner

import (
	"os"
	"path/filepath"
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
