package scanner

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildWapiti_BoundedScopedRun(t *testing.T) {
	dir := t.TempDir()
	spec := buildWapiti(Request{
		Target:       "https://app.test/",
		ScanDir:      dir,
		WebEndpoints: []string{"https://app.test/s?q=1", "https://app.test/x?y=2"},
	}, Config{WapitiPath: "/usr/bin/wapiti", WapitiTimeout: 10 * time.Minute})

	if spec.notApp != "" {
		t.Fatalf("unexpected notApp: %s", spec.notApp)
	}
	if u, _ := argValue(spec.args, "-u"); u != "https://app.test/" {
		t.Errorf("-u = %q", u)
	}
	if s, _ := argValue(spec.args, "--scope"); s != "folder" {
		t.Errorf("--scope = %q, want folder (bounded)", s)
	}
	if !hasArg(spec.args, "--max-scan-time") {
		t.Errorf("expected a bounded --max-scan-time")
	}
	if f, _ := argValue(spec.args, "--format"); f != "json" {
		t.Errorf("--format = %q, want json", f)
	}
	// Discovered endpoints added as extra crawl entry points.
	starts := 0
	for i, a := range spec.args {
		if a == "--start" && i+1 < len(spec.args) {
			starts++
		}
	}
	if starts != 2 {
		t.Errorf("expected 2 --start entry points, got %d", starts)
	}
}

func TestBuildWapiti_RejectsNonHTTP(t *testing.T) {
	spec := buildWapiti(Request{Target: "ftp://x/", ScanDir: t.TempDir()}, Config{WapitiPath: "wapiti", WapitiTimeout: time.Minute})
	if spec.notApp == "" {
		t.Error("expected notApp for non-HTTP target")
	}
}

func TestParseWapiti_JSONFindings(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "results.json")
	body := `{
	  "vulnerabilities": {
	    "SQL Injection": [
	      {"method":"GET","path":"https://app.test/item?id=1","info":"SQLi in id","level":3,"parameter":"id","http_request":"GET /item?id=1","curl_command":"curl ..."}
	    ],
	    "Cross Site Scripting": [
	      {"method":"GET","path":"https://app.test/s?q=1","info":"XSS in q","level":2,"parameter":"q","http_request":"GET /s?q=1","curl_command":"curl ..."}
	    ]
	  },
	  "classifications": {
	    "SQL Injection": {"ref": {"cwe": "89"}},
	    "Cross Site Scripting": {"ref": {"cwe": "CWE-79"}}
	  }
	}`
	if err := os.WriteFile(art, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := parseWapiti(art)
	if err != nil {
		t.Fatalf("parseWapiti: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	// Verify each category is represented with normalized CWE + severity.
	byTitle := map[string]Finding{}
	for _, f := range findings {
		byTitle[f.Title] = f
	}
	if sqli, ok := byTitle["SQL Injection"]; !ok || sqli.CWE != "CWE-89" || sqli.Severity != "high" || sqli.Parameter != "id" {
		t.Errorf("SQLi finding wrong: %+v", sqli)
	}
	if xss, ok := byTitle["Cross Site Scripting"]; !ok || xss.CWE != "CWE-79" || xss.Severity != "medium" {
		t.Errorf("XSS finding wrong: %+v", xss)
	}
}

func TestParseWapiti_EmptyArtifact(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "e.json")
	if err := os.WriteFile(art, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := parseWapiti(art)
	if err != nil || f != nil {
		t.Errorf("empty artifact should yield no findings, got %v err=%v", f, err)
	}
}
