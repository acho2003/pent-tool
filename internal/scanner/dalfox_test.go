package scanner

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParameterizedURLs_OnlyQueryURLs(t *testing.T) {
	got := parameterizedURLs("https://app.test/", []string{
		"https://app.test/search?q=1",
		"https://app.test/about", // no query -> excluded
		"https://app.test/item?id=5&x=2",
		"https://app.test/search?q=1", // dup
		"ftp://app.test/x?y=1",        // non-http -> excluded
	})
	want := []string{
		"https://app.test/search?q=1",
		"https://app.test/item?id=5&x=2",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParameterizedURLs_IncludesSeedWhenParameterized(t *testing.T) {
	got := parameterizedURLs("https://app.test/p?x=1", nil)
	if len(got) != 1 || got[0] != "https://app.test/p?x=1" {
		t.Errorf("seed with query should be included, got %v", got)
	}
}

func TestBuildDalfox_NotApplicableWithoutParameterizedURLs(t *testing.T) {
	spec := buildDalfox(Request{Target: "https://app.test/", ScanDir: t.TempDir()}, Config{DalfoxPath: "dalfox", DalfoxTimeout: time.Minute})
	if spec.notApp == "" {
		t.Error("expected notApp when no parameterized URLs are available")
	}
}

func TestBuildDalfox_BoundedRunOverDiscoveredURLs(t *testing.T) {
	dir := t.TempDir()
	spec := buildDalfox(Request{
		Target:       "https://app.test/",
		ScanDir:      dir,
		WebEndpoints: []string{"https://app.test/s?q=1"},
	}, Config{DalfoxPath: "/usr/bin/dalfox", DalfoxTimeout: 5 * time.Minute, RateRPS: 10})

	if spec.notApp != "" {
		t.Fatalf("unexpected notApp: %s", spec.notApp)
	}
	if !hasArg(spec.args, "file") {
		t.Errorf("dalfox should run in file mode over the discovered list; args=%v", spec.args)
	}
	if fmtv, _ := argValue(spec.args, "--format"); fmtv != "json" {
		t.Errorf("--format = %q, want json", fmtv)
	}
	if !hasArg(spec.args, "--skip-bav") {
		t.Errorf("expected --skip-bav to stay focused on XSS")
	}
	if d, ok := argValue(spec.args, "--delay"); !ok || d != "100" {
		t.Errorf("--delay = %q, want 100 (from RateRPS=10)", d)
	}
	// The prepare step must materialize the discovered URL list.
	if spec.prepare == nil {
		t.Fatal("expected prepare to write the target list")
	}
	if err := spec.prepare(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "scanner-output", "dalfox", "targets.txt"))
	if err != nil || string(data) == "" {
		t.Fatalf("target list not written: %v", err)
	}
}

func TestParseDalfox_JSONFindings(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "results.json")
	// A vulnerability row (V) and an informational grep row (G-ignored non-V/G? G kept) plus a non-vuln row.
	body := `[
	  {"type":"V","method":"GET","data":"https://app.test/s?q=<script>","param":"q","evidence":"reflected","cwe":"79","severity":"high","message_str":"reflected XSS","poc":"https://app.test/s?q=<script>alert(1)</script>"},
	  {"type":"I","method":"GET","data":"https://app.test/s?q=1","param":"q","message_str":"info only"}
	]`
	if err := os.WriteFile(art, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := parseDalfox(art)
	if err != nil {
		t.Fatalf("parseDalfox: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (only the V row)", len(findings))
	}
	f := findings[0]
	if f.Scanner != "dalfox" || f.Severity != "high" || f.Parameter != "q" {
		t.Errorf("unexpected finding: %+v", f)
	}
	if f.CWE != "CWE-79" {
		t.Errorf("CWE = %q, want CWE-79 (normalized)", f.CWE)
	}
	if f.Title != "Cross-Site Scripting (XSS)" {
		t.Errorf("title = %q", f.Title)
	}
}

func TestParseDalfox_EmptyArtifact(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(art, []byte("  "), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := parseDalfox(art)
	if err != nil || findings != nil {
		t.Errorf("empty artifact should yield no findings, got %v err=%v", findings, err)
	}
}
