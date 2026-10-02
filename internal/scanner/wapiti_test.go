package scanner

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestBuildWapiti_BoundedScopedRun(t *testing.T) {
	dir := t.TempDir()
	spec := buildWapiti(Request{
		Target:          "https://app.test/",
		ScanDir:         dir,
		WebEndpoints:    []string{"https://app.test/s?q=1", "https://app.test/x?y=2"},
		TestEnvironment: true,
	}, Config{WapitiPath: "/usr/bin/wapiti", WapitiTimeout: 10 * time.Minute})

	if spec.notApp != "" {
		t.Fatalf("unexpected notApp: %s", spec.notApp)
	}
	if u, _ := argValue(spec.args, "-u"); u != "https://app.test/" {
		t.Errorf("-u = %q", u)
	}
	if s, _ := argValue(spec.args, "--scope"); s != "url" {
		t.Errorf("--scope = %q, want url (no crawl beyond dispatched entry points)", s)
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
	spec := buildWapiti(Request{Target: "ftp://x/", ScanDir: t.TempDir(), TestEnvironment: true}, Config{WapitiPath: "wapiti", WapitiTimeout: time.Minute})
	if spec.notApp == "" {
		t.Error("expected notApp for non-HTTP target")
	}
}

// Wapiti's crawler submits discovered forms and its default module set
// includes SSRF with an external callback, so outside a declared test
// environment it is refused with a visible excluded gap instead of running.
func TestWapitiRestrictedUnderDefaultPolicy(t *testing.T) {
	dir := t.TempDir()
	req := Request{Target: "https://app.test/", ScanDir: dir, WebEndpoints: []string{"https://app.test/s?q=1"}, TypedAssessment: true}
	cfg := Config{WapitiPath: "/usr/bin/wapiti", WapitiTimeout: time.Minute}
	spec := buildWapiti(req, cfg)
	if spec.notApp == "" || len(spec.args) != 0 || !strings.Contains(spec.notApp, "test environment") {
		t.Fatalf("default-policy Wapiti spec = %+v, want a policy refusal", spec)
	}
	var events []Event
	run := wapitiRunner{}.Run(context.Background(), req, cfg, func(e Event) { events = append(events, e) })
	if run.Status != "not_applicable" || run.GapKind != GapExcluded || run.Reason != spec.notApp {
		t.Fatalf("restricted Wapiti run = %+v", run)
	}
	if len(events) != 1 || events[0].Type != "scanner_not_applicable" || events[0].Run.GapKind != GapExcluded {
		t.Fatalf("restricted Wapiti events = %+v", events)
	}
	// The plan-time check gives the same answer for the same policy.
	if restricted, reason := AdapterPolicyRestriction("wapiti", assessment.AssessmentConfig{}); !restricted || reason != spec.notApp {
		t.Fatalf("AdapterPolicyRestriction = %v %q, want %q", restricted, reason, spec.notApp)
	}
}

func TestWapitiTestEnvironmentArgs(t *testing.T) {
	scope := assessment.NewAppScope(
		[]assessment.ApprovedOrigin{{Scheme: "https", Host: "app.test", PathPrefix: "/"}},
		assessment.Exclusion{PathPattern: "/logout", Reason: "ends the session"},
		assessment.Exclusion{PathPattern: "/admin/*/delete"},
		assessment.Exclusion{Origin: "https://other.test", PathPattern: "/never"},
	)
	req := Request{
		Target: "https://app.test/", ScanDir: t.TempDir(), TypedAssessment: true, StructuredDispatch: true,
		EndpointTargets: []string{"https://app.test/s?q=1", "https://app.test/logout?next=/", "https://elsewhere.test/x?y=1", "https://app.test/x?y=2"},
		AppScope:        &scope, TestEnvironment: true,
	}
	spec := buildWapiti(req, Config{WapitiPath: "/usr/bin/wapiti", WapitiTimeout: 10 * time.Minute})
	if spec.notApp != "" {
		t.Fatalf("unexpected notApp: %s", spec.notApp)
	}
	modules, ok := argValue(spec.args, "-m")
	if !ok || modules != wapitiTestEnvironmentModules {
		t.Fatalf("-m = %q, want the reviewed allowlist %q", modules, wapitiTestEnvironmentModules)
	}
	for _, module := range strings.Split(modules, ",") {
		name, method, _ := strings.Cut(module, ":")
		switch name {
		case "ssrf", "exec", "upload", "permanentxss", "xxe", "log4shell", "spring4shell", "shellshock", "csrf", "methods", "htaccess", "brute_login_form", "buster", "nikto", "takeover", "htp", "wapp", "cms", "wp_enum", "timesql":
			t.Fatalf("write-capable, callback or brute-force module %q in allowlist %q", name, modules)
		case "passive":
		default:
			if method != "get" {
				t.Fatalf("active module %q is not restricted to GET in %q", module, modules)
			}
		}
	}
	if v, _ := argValue(spec.args, "--tasks"); v != "1" {
		t.Errorf("--tasks = %q, want 1", v)
	}
	if v, _ := argValue(spec.args, "--scope"); v != "url" {
		t.Errorf("--scope = %q, want url", v)
	}
	if v, _ := argValue(spec.args, "-d"); v != "0" {
		t.Errorf("-d = %q, want 0 so the crawler never follows discovered forms", v)
	}
	wantExcludes := []string{"https://app.test/admin/*/delete*", "https://app.test/logout*"}
	if got := argValues(spec.args, "-x"); !slices.Equal(got, wantExcludes) {
		t.Errorf("-x = %v, want one per applicable exclusion %v", got, wantExcludes)
	}
	if u, _ := argValue(spec.args, "-u"); u != "https://app.test/s?q=1" {
		t.Errorf("-u = %q", u)
	}
	// Excluded and out-of-scope endpoints never become entry points.
	if got := argValues(spec.args, "--start"); !slices.Equal(got, []string{"https://app.test/x?y=2"}) {
		t.Errorf("--start = %v", got)
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
