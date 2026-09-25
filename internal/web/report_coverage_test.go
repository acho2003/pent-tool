package web

import (
	"slices"
	"strings"
	"testing"

	"github.com/go-pdf/fpdf"
)

func TestReportScopeLabel(t *testing.T) {
	cases := []struct {
		in   reportScope
		want string
	}{
		{reportScope{ID: "host:a.test", Kind: "host", Target: "a.test", Tracks: []string{"web", "server"}}, "HOST  a.test  [web, server]"},
		{reportScope{ID: "source:main", Kind: "source", Target: "/scans/x/source/checkout"}, "SOURCE CODE  /scans/x/source/checkout"},
		{reportScope{ID: "source:main", Kind: "source"}, "SOURCE CODE  none provided"},
	}
	for _, tc := range cases {
		if got := reportScopeLabel(tc.in); got != tc.want {
			t.Errorf("reportScopeLabel(%s) = %q, want %q", tc.in.ID, got, tc.want)
		}
	}
}

func TestScopeCoverageLines(t *testing.T) {
	host := reportScope{Kind: "host", Tracks: []string{"web"}, OpenPorts: []string{"443/tcp https"}, Runs: []reportScopeRun{{Scanner: "nuclei", Status: "completed"}, {Scanner: "openvas", Status: "not_applicable", Reason: "not on the server track"}}}
	want := []string{
		"Tracks: web",
		"Open ports: 443/tcp https",
		"nuclei     completed",
		"openvas    not_applicable - not on the server track",
	}
	if got := scopeCoverageLines(host); !slices.Equal(got, want) {
		t.Fatalf("host lines = %q, want %q", got, want)
	}
	src := reportScope{Kind: "source", Runs: []reportScopeRun{{Scanner: "semgrep", Status: "not_applicable"}}}
	if got := scopeCoverageLines(src); !slices.Equal(got, []string{"semgrep    not_applicable"}) {
		t.Fatalf("source lines = %q", got)
	}
	noPorts := reportScope{Kind: "host", Tracks: []string{"web", "server"}}
	if got := scopeCoverageLines(noPorts); !slices.Equal(got, []string{"Tracks: web, server", "Open ports: none recorded"}) {
		t.Fatalf("no-port lines = %q", got)
	}
}

func TestFitPDFText(t *testing.T) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Helvetica", "B", 9)
	short := "HOST  a.test  [web]"
	if got := fitPDFText(pdf, short, 182); got != short {
		t.Fatalf("short label changed: %q", got)
	}
	long := "HOST  " + strings.Repeat("very-long-subdomain.", 20) + "example.test  [web, server]"
	got := fitPDFText(pdf, long, 182)
	if !strings.HasSuffix(got, "...") || pdf.GetStringWidth(got) > 182 {
		t.Fatalf("long label not fitted: %q (width %.1f)", got, pdf.GetStringWidth(got))
	}
}

func TestReconSummaryLine(t *testing.T) {
	if got := reconSummaryLine(reportReconSummary{Hosts: 2, OpenPorts: 3, Services: []string{"https", "ssh"}}); got != "Recon discovered 2 host(s) with 3 open port(s). Detected services: https, ssh." {
		t.Fatalf("got %q", got)
	}
	if got := reconSummaryLine(reportReconSummary{Hosts: 1}); got != "Recon discovered 1 host(s) with 0 open port(s). Detected services: none recorded." {
		t.Fatalf("got %q", got)
	}
}
