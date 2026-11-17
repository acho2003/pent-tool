package web

import (
	"strings"
	"testing"
)

func TestReportFindingSectionsPrintScannerRemediation(t *testing.T) {
	v := VulnSummary{Title: "Cross Site Scripting (Reflected)", Endpoint: "https://app.test/s?q=1", Remediation: "<p>Validate all input.</p><p>Encode output &amp; use a CSP.</p>"}
	sections := reportFindingSections(v, nil)
	var remediation string
	for _, s := range sections {
		if s.label == "REMEDIATION" {
			remediation = s.content
		}
	}
	if remediation != "Validate all input.\nEncode output & use a CSP." {
		t.Fatalf("remediation section = %q (sections %+v)", remediation, sections)
	}
	if strings.Contains(remediation, "<") {
		t.Fatalf("HTML left in remediation: %q", remediation)
	}

	// A finding with an explicit Fix equal to its remediation prints it once.
	same := reportFindingSections(VulnSummary{Fix: "Upgrade Next.js.", Remediation: "Upgrade Next.js."}, nil)
	count := 0
	for _, s := range same {
		if s.label == "REMEDIATION" || s.label == "SUGGESTED FIX" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("duplicate fix/remediation sections: %+v", same)
	}

	// No remediation supplied: no empty section.
	for _, s := range reportFindingSections(VulnSummary{Remediation: "  <p></p> "}, nil) {
		if s.label == "REMEDIATION" {
			t.Fatalf("empty remediation produced a section: %+v", s)
		}
	}
}
