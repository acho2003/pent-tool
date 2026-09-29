package scanner

import "testing"

func TestMergeCrossScannerCollapsesSameCVEOnSameScope(t *testing.T) {
	in := []Finding{
		{SourceID: "openvas:r1", Scanner: "openvas", Severity: "medium", CVSS: 5.0, CVE: "CVE-2021-41773", Scope: "host:a", Endpoint: "https://a/", EvidenceRef: "ov.xml#openvas:r1"},
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
		"different location": {
			{SourceID: "nuclei:a", Scanner: "nuclei", CVE: "CVE-2021-41773", Scope: "host:a", Endpoint: "https://a/one"},
			{SourceID: "zap:b", Scanner: "zap", CVE: "CVE-2021-41773", Scope: "host:a", Endpoint: "https://a/two"},
		},
		"ambiguous location": {
			{SourceID: "nuclei:a", Scanner: "nuclei", CVE: "CVE-2021-41773", Scope: "host:a"},
			{SourceID: "zap:b", Scanner: "zap", CVE: "CVE-2021-41773", Scope: "host:a"},
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
	if len(findings) != 3 {
		t.Fatalf("want separate findings for scanner-specific locations + legacy finding, got %d: %#v", len(findings), findings)
	}
	if findings[0].Scope != "host:a.test" || len(findings[0].Sources) != 0 || findings[0].Scanner != "nuclei" {
		t.Fatalf("location-specific finding = %#v", findings[0])
	}
	if findings[1].Scope != "host:a.test" || findings[1].Scanner != "openvas" {
		t.Fatalf("ambiguous service location must remain a separate finding, got %#v", findings[1])
	}
	if findings[2].Scope != "host:b.test" {
		t.Fatalf("legacy empty-scope run must fold to host:<target>, got %q", findings[2].Scope)
	}
}

func TestMergeIgnoresUnratedSeverity(t *testing.T) {
	trivyLow := Finding{SourceID: "trivy:CVE-2023-1000:go.mod", Scanner: "trivy", Severity: "low", CVE: "CVE-2023-1000", Scope: "source:main", Target: "go.mod"}
	osvUnrated := Finding{SourceID: "osv:x:GO-1", Scanner: "osv", Severity: "medium", SeverityUnrated: true, CVE: "CVE-2023-1000", Scope: "source:main", Target: "go.mod"}
	if out := mergeCrossScanner([]Finding{trivyLow, osvUnrated}); len(out) != 1 || out[0].Severity != "low" {
		t.Fatalf("unrated contributor must not raise severity, got %#v", out)
	}
	out := mergeCrossScanner([]Finding{osvUnrated, trivyLow})
	if len(out) != 1 || out[0].Severity != "low" || out[0].SeverityUnrated {
		t.Fatalf("a rated contributor must replace an unrated primary's placeholder, got %#v", out)
	}
}

func TestFindingFingerprintUsesVulnerabilityAndExactLocation(t *testing.T) {
	base := Finding{Scanner: "zap", SourceID: "zap:alert-1", CVE: "cve-2025-1234", Scope: "app:one", Target: "https://app.example.test:8443/", Endpoint: "https://app.example.test:8443/Portal/Case"}
	fingerprint := FindingFingerprint(base)
	changedPresentation := base
	changedPresentation.Scanner = "nuclei"
	changedPresentation.SourceID = "nuclei:other-template"
	changedPresentation.Title = "Different display text"
	changedPresentation.Severity = "critical"
	if got := FindingFingerprint(changedPresentation); got != fingerprint {
		t.Fatalf("presentation/scanner changes altered identifier: %s != %s", got, fingerprint)
	}
	for name, mutate := range map[string]func(*Finding){
		"path case": func(f *Finding) { f.Endpoint = "https://app.example.test:8443/portal/Case" },
		"port":      func(f *Finding) { f.Endpoint = "https://app.example.test:9443/Portal/Case" },
		"endpoint":  func(f *Finding) { f.Endpoint = "https://app.example.test:8443/Portal/Other" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if got := FindingFingerprint(changed); got == fingerprint {
				t.Fatalf("distinct location shared fingerprint %s", got)
			}
		})
	}
}
