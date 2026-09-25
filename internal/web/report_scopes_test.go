package web

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

func writeReconScopes(t *testing.T, scanDir string, scopes []scanner.Scope) {
	t.Helper()
	data, err := json.Marshal(scopes)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(scanDir, "scanner-output", "recon-scopes.json")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestBuildReportScopes(t *testing.T) {
	dir := t.TempDir()
	writeReconScopes(t, dir, []scanner.Scope{
		{ID: "host:a.test", Kind: scanner.ScopeHost, Target: "a.test", Evidence: scanner.HostEvidence{OpenPorts: []scanner.Port{{Number: 443, Protocol: "tcp", Service: "https", Product: "nginx"}, {Number: 22, Protocol: "tcp", Service: "ssh"}}}},
	})
	runs := []scanner.Run{
		{Scanner: "subfinder", Scope: "recon:a.test", Status: "completed"},
		{Scanner: "trivy", Scope: "source:main", Target: "", Status: "not_applicable", Reason: "no source"},
		{Scanner: "nuclei", Scope: "host:a.test", Target: "a.test", Status: "completed"},
		{Scanner: "vuls", Scope: "host:a.test", Target: "a.test", Status: "skipped", Reason: "not selected for this scan"},
		{Scanner: "nuclei", Target: "legacy.test", Status: "completed"}, // pre-scope record
	}
	got := buildReportScopes(dir, runs)
	ids := make([]string, len(got))
	for i, sc := range got {
		ids[i] = sc.ID
	}
	if !slices.Equal(ids, []string{"host:a.test", "host:legacy.test", "source:main"}) {
		t.Fatalf("scope order = %v (recon excluded, hosts first-seen, source last)", ids)
	}
	a := got[0]
	if a.Kind != "host" || !slices.Equal(a.Tracks, []string{"web", "server"}) || !slices.Equal(a.OpenPorts, []string{"443/tcp https nginx", "22/tcp ssh"}) || !slices.Equal(a.Services, []string{"https", "ssh"}) {
		t.Fatalf("host scope = %#v", a)
	}
	if len(a.Runs) != 2 || a.Runs[1] != (reportScopeRun{Scanner: "vuls", Status: "skipped", Reason: "not selected for this scan"}) {
		t.Fatalf("host runs = %#v", a.Runs)
	}
	if legacy := got[1]; !slices.Equal(legacy.Tracks, []string{"web", "server"}) || legacy.Target != "legacy.test" {
		t.Fatalf("host with no evidence must fail open to both tracks, got %#v", legacy)
	}
	if src := got[2]; src.Kind != "source" || len(src.Tracks) != 0 || len(src.Runs) != 1 {
		t.Fatalf("source scope = %#v", src)
	}
	sum := summarizeReportRecon(got)
	if sum.Hosts != 2 || sum.OpenPorts != 2 || !slices.Equal(sum.Services, []string{"https", "ssh"}) {
		t.Fatalf("recon summary = %#v", sum)
	}
}

func TestRedactURL(t *testing.T) {
	cases := map[string]string{
		"https://user:tok@github.com/a/b.git": "https://github.com/a/b.git",
		"https://github.com/a/b.git":          "https://github.com/a/b.git",
		"git@github.com:a/b.git":              "git@github.com:a/b.git",
	}
	for in, want := range cases {
		if got := redactURL(in); got != want {
			t.Errorf("redactURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildReportScopesSourceOrigin(t *testing.T) {
	dir := t.TempDir()
	writeSourceScope := func(sc scanner.Scope) {
		data, _ := json.Marshal(sc)
		p := filepath.Join(dir, "scanner-output", "source-scope.json")
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runs := []scanner.Run{{Scanner: "trivy", Scope: "source:main", Target: "/scans/x/source/checkout", Status: "completed"}}
	writeSourceScope(scanner.Scope{ID: "source:main", Kind: scanner.ScopeSource, Target: "/scans/x/source/checkout", Source: scanner.SourceRef{Path: "/scans/x/source/checkout", Provenance: "clone:https://user:tok@github.com/a/b.git"}})
	if got := buildReportScopes(dir, runs); len(got) != 1 || got[0].Origin != "https://github.com/a/b.git" || reportScopeLabel(got[0]) != "SOURCE CODE  https://github.com/a/b.git" {
		t.Fatalf("clone origin: %#v", got)
	}
	writeSourceScope(scanner.Scope{ID: "source:main", Kind: scanner.ScopeSource, Target: "/home/me/app", Source: scanner.SourceRef{Path: "/home/me/app", Provenance: "provided:filesystem"}})
	if got := buildReportScopes(dir, runs); got[0].Origin != "/home/me/app" {
		t.Fatalf("provided origin: %#v", got)
	}
	if got := buildReportScopes(t.TempDir(), runs); got[0].Origin != "" || reportScopeLabel(got[0]) != "SOURCE CODE  /scans/x/source/checkout" {
		t.Fatalf("legacy scan without source-scope.json must keep the old label: %#v", got)
	}
}

func TestOrderReportFindings(t *testing.T) {
	scopes := []reportScope{{ID: "host:a"}, {ID: "host:b"}, {ID: "source:main"}}
	in := []reportFinding{
		{SourceID: "trivy:1", Scope: "source:main", Severity: "critical"},
		{SourceID: "nuclei:z", Scope: "host:b", Severity: "low"},
		{SourceID: "nuclei:b", Scope: "host:a", Severity: "medium"},
		{SourceID: "nuclei:a", Scope: "host:a", Severity: "medium"},
		{SourceID: "zap:1", Scope: "host:a", Severity: "high"},
		{SourceID: "x:1", Scope: "unknown", Severity: "critical"},
	}
	orderReportFindings(in, scopes)
	var got []string
	for _, f := range in {
		got = append(got, f.SourceID)
	}
	want := []string{"zap:1", "nuclei:a", "nuclei:b", "nuclei:z", "trivy:1", "x:1"}
	if !slices.Equal(got, want) {
		t.Fatalf("order = %v, want %v (scope, then severity desc, then source id; unknown scope last)", got, want)
	}
}

func TestReportFindingsToVulnsCarriesScopeAndSources(t *testing.T) {
	in := []reportFinding{{
		SourceID: "nuclei:x", Scanner: "nuclei", Title: "t", Severity: "critical", Scope: "host:a", Evidence: "ev", EvidenceRef: "n.jsonl#nuclei:x",
		Sources: []scanner.FindingSource{{Scanner: "nuclei", SourceID: "nuclei:x", EvidenceRef: "n.jsonl#nuclei:x"}, {Scanner: "openvas", SourceID: "openvas:r1", EvidenceRef: "ov.xml#openvas:r1"}},
	}}
	v := reportFindingsToVulns(in)[0]
	if v.Scope != "host:a" || v.VerificationMethod != "nuclei, openvas" || !slices.Contains(v.Tags, "openvas") {
		t.Fatalf("vuln = %#v", v)
	}
	want := "ev\nEvidence reference (nuclei): n.jsonl#nuclei:x\nEvidence reference (openvas): ov.xml#openvas:r1"
	if v.TechnicalAnalysis != want {
		t.Fatalf("technical analysis = %q", v.TechnicalAnalysis)
	}
	single := reportFindingsToVulns([]reportFinding{{SourceID: "zap:1", Scanner: "zap", Evidence: "e", EvidenceRef: "z.json#zap:1"}})[0]
	if single.TechnicalAnalysis != "e\nEvidence reference: z.json#zap:1" || single.VerificationMethod != "zap" {
		t.Fatalf("unmerged vuln must keep the existing shape, got %#v", single)
	}
}

// Findings that tie on scope, severity, and source ID are ordered by Target,
// then Endpoint, so the order never depends on the input order.
func TestOrderReportFindingsTieBreaksOnTargetAndEndpoint(t *testing.T) {
	scopes := []reportScope{{ID: "source:main"}}
	in := []reportFinding{
		{SourceID: "osv:lib:GHSA-1", Scope: "source:main", Severity: "high", Target: "web/package-lock.json"},
		{SourceID: "osv:lib:GHSA-1", Scope: "source:main", Severity: "high", Target: "api/package-lock.json", Endpoint: "b"},
		{SourceID: "osv:lib:GHSA-1", Scope: "source:main", Severity: "high", Target: "api/package-lock.json", Endpoint: "a"},
	}
	orderReportFindings(in, scopes)
	var got []string
	for _, f := range in {
		got = append(got, f.Target+"|"+f.Endpoint)
	}
	want := []string{"api/package-lock.json|a", "api/package-lock.json|b", "web/package-lock.json|"}
	if !slices.Equal(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}
