package scanner

import "testing"

func TestMergeCrossScannerCollapsesSameCVEOnSameScope(t *testing.T) {
	in := []Finding{
		{SourceID: "openvas:r1", Scanner: "openvas", Severity: "medium", CVSS: 5.0, CVE: "CVE-2021-41773", Scope: "host:a", Endpoint: "443/tcp", EvidenceRef: "ov.xml#openvas:r1"},
		{SourceID: "nuclei:CVE-2021-41773:https://a/", Scanner: "nuclei", Severity: "critical", CVSS: 9.8, CVE: "cve-2021-41773", CWE: "CWE-22", Scope: "host:a", Endpoint: "https://a/", EvidenceRef: "n.jsonl#nuclei:CVE-2021-41773:https://a/"},
	}
	out := mergeCrossScanner(in)
	if len(out) != 1 {
		t.Fatalf("want 1 merged finding, got %d: %#v", len(out), out)
	}
	m := out[0]
	if m.SourceID != "openvas:r1" || m.Scanner != "openvas" || m.EvidenceRef != "ov.xml#openvas:r1" {
		t.Fatalf("primary must stay the first contributor, got %#v", m)
	}
	if m.Severity != "critical" || m.CVSS != 9.8 || m.CWE != "CWE-22" {
		t.Fatalf("merge must raise severity/CVSS and fill CWE, got sev=%s cvss=%v cwe=%s", m.Severity, m.CVSS, m.CWE)
	}
	if len(m.Sources) != 2 || m.Sources[0].Scanner != "openvas" || m.Sources[1].Scanner != "nuclei" || m.Sources[1].Endpoint != "https://a/" || m.Sources[1].EvidenceRef == "" {
		t.Fatalf("sources = %#v", m.Sources)
	}
}

func TestMergeCrossScannerLeavesDistinctFindingsAlone(t *testing.T) {
	cases := map[string][]Finding{
		"different scope": {
			{SourceID: "openvas:r1", Scanner: "openvas", CVE: "CVE-2021-41773", Scope: "host:a"},
			{SourceID: "nuclei:x", Scanner: "nuclei", CVE: "CVE-2021-41773", Scope: "host:b"},
		},
		"no CVE": {
			{SourceID: "zap:1", Scanner: "zap", Scope: "host:a"},
			{SourceID: "nuclei:y", Scanner: "nuclei", Scope: "host:a"},
		},
		"same scanner twice": {
			{SourceID: "trivy:CVE-2023-1111:go.sum", Scanner: "trivy", CVE: "CVE-2023-1111", Scope: "source:main"},
			{SourceID: "trivy:CVE-2023-1111:web/package-lock.json", Scanner: "trivy", CVE: "CVE-2023-1111", Scope: "source:main"},
		},
		"malformed CVE": {
			{SourceID: "openvas:r1", Scanner: "openvas", CVE: "CVE-2021-41773, CVE-2021-42013", Scope: "host:a"},
			{SourceID: "nuclei:z", Scanner: "nuclei", CVE: "CVE-2021-41773, CVE-2021-42013", Scope: "host:a"},
		},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			out := mergeCrossScanner(in)
			if len(out) != 2 || len(out[0].Sources) != 0 || len(out[1].Sources) != 0 {
				t.Fatalf("expected both findings untouched, got %#v", out)
			}
		})
	}
}

func TestParseRunsStampsScopeAndMerges(t *testing.T) {
	nuclei := writeFixture(t, "nuclei.jsonl", `{"template-id":"CVE-2021-41773","matched-at":"https://a.test/cgi-bin/","host":"a.test","info":{"name":"Apache Path Traversal","severity":"critical","classification":{"cve-id":["cve-2021-41773"],"cvss-score":9.8}}}`+"\n")
	openvas := writeFixture(t, "report.xml", `<get_reports_response><report><results><result id="r1"><name>Apache Path Traversal</name><host>a.test</host><port>443/tcp</port><severity>7.5</severity><nvt oid="1.3.6"><cve>CVE-2021-41773</cve></nvt></result></results></report></get_reports_response>`)
	legacy := writeFixture(t, "legacy.jsonl", `{"template-id":"hsts","matched-at":"https://b.test","host":"b.test","info":{"name":"Missing HSTS","severity":"info"}}`+"\n")
	findings, errs := ParseRuns([]Run{
		{Scanner: "nuclei", Scope: "host:a.test", Target: "a.test", Status: "completed", ArtifactPath: nuclei},
		{Scanner: "openvas", Scope: "host:a.test", Target: "a.test", Status: "completed", ArtifactPath: openvas},
		{Scanner: "nuclei", Target: "b.test", Status: "completed", ArtifactPath: legacy}, // pre-scope record
	})
	if len(errs) != 0 {
		t.Fatalf("errs = %v", errs)
	}
	if len(findings) != 2 {
		t.Fatalf("want merged CVE + legacy finding, got %d: %#v", len(findings), findings)
	}
	if findings[0].Scope != "host:a.test" || len(findings[0].Sources) != 2 || findings[0].Scanner != "nuclei" {
		t.Fatalf("merged finding = %#v", findings[0])
	}
	if findings[1].Scope != "host:b.test" {
		t.Fatalf("legacy empty-scope run must fold to host:<target>, got %q", findings[1].Scope)
	}
}
