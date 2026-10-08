package scanner

import (
	"context"
	"os"
	"path/filepath"
	"slices"
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
	if fmtv, _ := argValue(spec.args, "--format"); fmtv != "jsonl" {
		t.Errorf("--format = %q, want jsonl (written incrementally, so a cancelled run keeps what it found)", fmtv)
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

// One worker and a per-request delay rounded up from RateRPS keep Dalfox at or
// below the profile rate; parameter mining and headless verification (whose
// browser requests bypass both the delay and the scope gate) are disabled.
func TestDalfoxSkipsMiningSingleWorkerDelayFromRate(t *testing.T) {
	for _, tc := range []struct {
		rate  int
		delay string
	}{{rate: 2, delay: "500"}, {rate: 3, delay: "334"}, {rate: 10, delay: "100"}, {rate: 5000, delay: "1"}} {
		spec := buildDalfox(Request{Target: "https://app.test/", ScanDir: t.TempDir(), WebEndpoints: []string{"https://app.test/s?q=1"}},
			Config{DalfoxPath: "dalfox", DalfoxTimeout: time.Minute, RateRPS: tc.rate})
		if spec.notApp != "" {
			t.Fatalf("unexpected notApp: %s", spec.notApp)
		}
		if w := argValues(spec.args, "--worker"); !slices.Equal(w, []string{"1"}) {
			t.Fatalf("rate %d: --worker = %v, want exactly one worker", tc.rate, w)
		}
		if d := argValues(spec.args, "--delay"); !slices.Equal(d, []string{tc.delay}) {
			t.Fatalf("rate %d: --delay = %v, want %s", tc.rate, d, tc.delay)
		}
		for _, flag := range []string{"--skip-mining-all", "--skip-headless", "--skip-bav"} {
			if !hasArg(spec.args, flag) {
				t.Fatalf("rate %d: missing %s in %v", tc.rate, flag, spec.args)
			}
		}
		for _, forbidden := range []string{"-b", "--blind", "--follow-redirects", "-F", "--found-action", "--multicast", "--mass"} {
			if hasArg(spec.args, forbidden) {
				t.Fatalf("rate %d: forbidden flag %s in %v", tc.rate, forbidden, spec.args)
			}
		}
	}
}

func TestDalfoxCompletedRunRecordsHeadlessLimitation(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-dalfox")
	script := "#!/bin/sh\nout=\nwhile [ $# -gt 0 ]; do if [ \"$1\" = -o ]; then shift; out=$1; fi; shift; done\nprintf '' > \"$out\"\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	req := Request{Target: "https://app.test/", ScanDir: dir, WebEndpoints: []string{"https://app.test/s?q=1"}}
	run := dalfoxRunner{}.Run(context.Background(), req, Config{DalfoxPath: bin, DalfoxTimeout: time.Minute, RateRPS: 2}, nil)
	if run.Status != "completed" || len(run.Limitations) != 1 || run.Limitations[0].Kind != LimitationHeadlessExcluded {
		t.Fatalf("completed Dalfox run = %+v", run)
	}
}

// Dalfox carries only the verified, target-bound session of a typed
// assessment. Operator scan headers and an unverified legacy TargetAuth are
// never forwarded.
func TestDalfoxSendsVerifiedAuthHeadersOnly(t *testing.T) {
	cfg := Config{DalfoxPath: "dalfox", DalfoxTimeout: time.Minute, ScanHeaders: []string{"X-Operator: static"}}
	base := Request{Target: "https://app.test/", WebEndpoints: []string{"https://app.test/s?q=1"}}

	anonymous := base
	anonymous.ScanDir, anonymous.TypedAssessment = t.TempDir(), true
	if h := argValues(buildDalfox(anonymous, cfg).args, "-H"); len(h) != 0 {
		t.Fatalf("anonymous typed run sent headers %v", h)
	}

	legacy := base
	legacy.ScanDir, legacy.TargetAuth = t.TempDir(), "Cookie: sid=legacy"
	if h := argValues(buildDalfox(legacy, cfg).args, "-H"); len(h) != 0 {
		t.Fatalf("unverified legacy TargetAuth forwarded as %v", h)
	}

	verified := base
	verified.ScanDir, verified.TypedAssessment = t.TempDir(), true
	verified.TargetAuth = "Cookie: sid=abc123\n\nAuthorization: Bearer tok-456\n"
	want := []string{"Cookie: sid=abc123", "Authorization: Bearer tok-456"}
	if h := argValues(buildDalfox(verified, cfg).args, "-H"); !slices.Equal(h, want) {
		t.Fatalf("verified headers = %v, want %v", h, want)
	}
}

func TestParseDalfox_JSONLFindings(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "results.jsonl")
	// A vulnerability row (V), an informational row (I, ignored) and a blank
	// line (as a trailing newline from Dalfox's own writer would produce).
	body := "" +
		`{"type":"V","method":"GET","data":"https://app.test/s?q=<script>","param":"q","evidence":"reflected","cwe":"79","severity":"high","message_str":"reflected XSS","poc":"https://app.test/s?q=<script>alert(1)</script>"}` + "\n" +
		`{"type":"I","method":"GET","data":"https://app.test/s?q=1","param":"q","message_str":"info only"}` + "\n" +
		"\n"
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

// A run cancelled mid-write (process_unix.go) can leave an incomplete final
// line. That must not discard every earlier, complete line already written —
// the same resilience parseNuclei already has for its own jsonl artifact.
func TestParseDalfox_PreservesCompleteLinesBeforeATruncatedLast(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "results.jsonl")
	body := `{"type":"V","method":"GET","data":"https://app.test/s?q=1","param":"q","severity":"high","message_str":"reflected XSS"}` + "\n" +
		`{"type":"V","method":"GET","data":"https://app.test/s?q=2","param":"q","severity":"medium","message_str":"reflected XSS"` // no closing brace: killed mid-write
	if err := os.WriteFile(art, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := parseDalfox(art)
	if err == nil {
		t.Fatal("expected an error reporting the truncated line")
	}
	if len(findings) != 1 || findings[0].Target != "https://app.test/s?q=1" {
		t.Fatalf("the complete first line was not preserved: %+v (err=%v)", findings, err)
	}
}

func TestParseDalfox_EmptyArtifact(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "empty.jsonl")
	if err := os.WriteFile(art, []byte("  "), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := parseDalfox(art)
	if err != nil || findings != nil {
		t.Errorf("empty artifact should yield no findings, got %v err=%v", findings, err)
	}
}
