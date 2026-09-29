package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The most important SQLMap test: the emitted command must be detection-only.
// None of the data-exfiltration / shell / file / enumeration flags may ever
// appear, regardless of inputs.
func TestBuildSqlmap_NeverEmitsDestructiveFlags(t *testing.T) {
	spec := buildSqlmap(Request{
		ScanDir:            t.TempDir(),
		SQLMapApprovedURLs: []string{"https://app.test/item?id=1"},
		TargetAuth:         "Cookie: s=1",
	}, Config{SqlmapPath: "/usr/bin/sqlmap", SqlmapTimeout: 5 * time.Minute, RateRPS: 10})

	if spec.notApp != "" {
		t.Fatalf("unexpected notApp: %s", spec.notApp)
	}
	joined := strings.Join(spec.args, " ")
	for _, bad := range sqlmapForbiddenFlags {
		for _, a := range spec.args {
			if a == bad || strings.HasPrefix(a, bad+"=") {
				t.Errorf("sqlmap must never emit destructive flag %q; args=%s", bad, joined)
			}
		}
	}
	// Detection-only bounds must be present.
	if lvl, _ := argValue(spec.args, "--level"); lvl != "1" {
		t.Errorf("--level = %q, want 1", lvl)
	}
	if risk, _ := argValue(spec.args, "--risk"); risk != "1" {
		t.Errorf("--risk = %q, want 1", risk)
	}
	if !hasArg(spec.args, "--batch") {
		t.Errorf("expected --batch (non-interactive, never a destructive default)")
	}
	if !hasArg(spec.args, "--technique=BEUST") {
		t.Errorf("expected bounded detection technique set")
	}
}

// SQLMap is opt-in: with no approved URLs it must be not_applicable and never
// fall back to scanning discovered or seed URLs.
func TestBuildSqlmap_OptInOnly(t *testing.T) {
	spec := buildSqlmap(Request{
		Target:       "https://app.test/item?id=1",
		WebEndpoints: []string{"https://app.test/x?y=1"},
		ScanDir:      t.TempDir(),
	}, Config{SqlmapPath: "sqlmap", SqlmapTimeout: time.Minute})
	if spec.notApp == "" {
		t.Error("SQLMap must be not_applicable without explicitly approved URLs")
	}
}

func TestApprovedSQLMapURLs_FiltersToParameterizedHTTP(t *testing.T) {
	got := approvedSQLMapURLs([]string{
		"https://app.test/item?id=1",
		"https://app.test/nolist",    // no query -> excluded
		"ftp://app.test/x?y=1",       // non-http -> excluded
		"https://app.test/item?id=1", // dup
	})
	if len(got) != 1 || got[0] != "https://app.test/item?id=1" {
		t.Errorf("got %v, want one parameterized http url", got)
	}
}

func TestBuildSqlmap_WritesApprovedListInPrepare(t *testing.T) {
	dir := t.TempDir()
	spec := buildSqlmap(Request{ScanDir: dir, SQLMapApprovedURLs: []string{"https://app.test/item?id=1"}}, Config{SqlmapPath: "sqlmap", SqlmapTimeout: time.Minute})
	if spec.prepare == nil {
		t.Fatal("expected prepare step")
	}
	if err := spec.prepare(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "scanner-output", "sqlmap", "targets.txt"))
	if err != nil || !strings.Contains(string(data), "https://app.test/item?id=1") {
		t.Fatalf("approved list not written: %v", err)
	}
}

func TestParseSqlmap_CSVFindings(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "results.csv")
	csvBody := "Target URL,Place,Parameter,Technique(s),Note(s)\n" +
		"https://app.test/item?id=1,GET,id,B,\n" +
		"https://app.test/p?q=2,GET,q,T,\n"
	if err := os.WriteFile(art, []byte(csvBody), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := parseSqlmap(art)
	if err != nil {
		t.Fatalf("parseSqlmap: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	f := findings[0]
	if f.Scanner != "sqlmap" || f.Title != "SQL Injection" || f.CWE != "CWE-89" || f.Parameter != "id" || f.Severity != "high" {
		t.Errorf("unexpected finding: %+v", f)
	}
}
