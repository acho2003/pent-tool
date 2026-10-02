package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func argValue(args []string, flag string) (string, bool) {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

func hasArg(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func TestBuildKatana_BoundedInScopeCrawl(t *testing.T) {
	cfg := Config{KatanaPath: "/usr/bin/katana", KatanaTimeout: 5 * time.Minute, RateRPS: 10}
	req := Request{Target: "https://app.example.test/Portal/", ScanDir: t.TempDir()}
	spec := buildKatana(req, cfg)

	if spec.notApp != "" {
		t.Fatalf("unexpected notApp: %s", spec.notApp)
	}
	if spec.path != "/usr/bin/katana" {
		t.Errorf("path = %q", spec.path)
	}
	if u, _ := argValue(spec.args, "-u"); u != "https://app.example.test/Portal/" {
		t.Errorf("target url = %q", u)
	}
	// Field-scoped to the host so the crawl never leaves the approved FQDN.
	if fs, _ := argValue(spec.args, "-fs"); fs != "fqdn" {
		t.Errorf("-fs = %q, want fqdn (in-scope crawl)", fs)
	}
	// Bounded depth and rate limit present.
	if d, ok := argValue(spec.args, "-d"); !ok || d != "5" {
		t.Errorf("-d = %q, want bounded depth 5", d)
	}
	for _, flag := range []string{"-jsonl", "-jc", "-xhr", "-fx", "-or", "-ob"} {
		if !hasArg(spec.args, flag) {
			t.Errorf("katana args missing structured discovery flag %q: %v", flag, spec.args)
		}
	}
	if rl, ok := argValue(spec.args, "-rl"); !ok || rl != "10" {
		t.Errorf("-rl = %q, want rate limit from RateRPS", rl)
	}
	if spec.timeout != 5*time.Minute {
		t.Errorf("timeout = %v", spec.timeout)
	}
	// It must not carry any request-submitting/destructive flags; crawling only.
	for _, bad := range []string{"-X", "--data", "-d POST"} {
		if hasArg(spec.args, bad) {
			t.Errorf("katana args must not contain %q (crawl-only)", bad)
		}
	}
}

func TestBuildKatana_RejectsArtifactTarget(t *testing.T) {
	spec := buildKatana(Request{Target: "artifact://repository"}, Config{KatanaPath: "katana"})
	if spec.notApp == "" {
		t.Error("expected notApp for artifact:// target")
	}
}

func TestParseKatanaEndpoints_DedupsAndFiltersNoise(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "endpoints.txt")
	content := strings.Join([]string{
		"https://app.example.test/",
		"https://app.example.test/login",
		"https://app.example.test/login", // dup
		"",                               // blank
		"not a url",                      // noise
		"https://app.example.test/api/v1/users?id=1",
	}, "\n")
	if err := os.WriteFile(art, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got := parseKatanaEndpoints(art)
	want := []string{
		"https://app.example.test/",
		"https://app.example.test/login",
		"https://app.example.test/api/v1/users?id=1",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d endpoints %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("endpoint[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseKatanaEndpoints_MissingArtifact(t *testing.T) {
	if got := parseKatanaEndpoints(filepath.Join(t.TempDir(), "nope.txt")); got != nil {
		t.Errorf("missing artifact should yield nil, got %v", got)
	}
}

// Nuclei must scan the crawled endpoint list (-l) when katana produced one, and
// fall back to the single seed URL (-u) otherwise.
func TestBuildNuclei_ConsumesWebEndpoints(t *testing.T) {
	cfg := Config{NucleiPath: "nuclei", NucleiTimeout: time.Hour, RateRPS: 10}
	dir := t.TempDir()

	withEndpoints := buildNuclei(Request{
		Target:       "https://app.example.test/",
		ScanDir:      dir,
		WebEndpoints: []string{"https://app.example.test/a", "https://app.example.test/b"},
	}, cfg)
	if !hasArg(withEndpoints.args, "-l") {
		t.Errorf("nuclei should use -l with a crawled endpoint list; args=%v", withEndpoints.args)
	}
	if hasArg(withEndpoints.args, "-u") {
		t.Errorf("nuclei should not also pass -u when using the endpoint list")
	}
	if withEndpoints.prepare == nil {
		t.Fatal("expected a prepare step to write the endpoint list")
	}
	if err := withEndpoints.prepare(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	listPath := filepath.Join(dir, "scanner-output", "nuclei", "targets.txt")
	data, err := os.ReadFile(listPath)
	if err != nil {
		t.Fatalf("endpoint list not written: %v", err)
	}
	if !strings.Contains(string(data), "https://app.example.test/a") {
		t.Errorf("endpoint list missing crawled URL: %s", data)
	}

	// No endpoints -> single seed URL.
	seedOnly := buildNuclei(Request{Target: "https://app.example.test/", ScanDir: dir}, cfg)
	if u, _ := argValue(seedOnly.args, "-u"); u != "https://app.example.test/" {
		t.Errorf("without endpoints nuclei should scan the seed url via -u, got args=%v", seedOnly.args)
	}
	if hasArg(seedOnly.args, "-l") {
		t.Errorf("without endpoints nuclei should not use -l")
	}
}

func TestHostIsWeb(t *testing.T) {
	cases := []struct {
		name string
		ev   HostEvidence
		want bool
	}{
		{"live url", HostEvidence{LiveURLs: []string{"https://x/"}}, true},
		{"tls", HostEvidence{TLS: true}, true},
		{"web port", HostEvidence{OpenPorts: []Port{{Number: 8080}}}, true},
		{"https port", HostEvidence{OpenPorts: []Port{{Number: 443}}}, true},
		{"ssh only", HostEvidence{OpenPorts: []Port{{Number: 22}}}, false},
		{"empty", HostEvidence{}, false},
	}
	for _, c := range cases {
		if got := hostIsWeb(c.ev); got != c.want {
			t.Errorf("%s: hostIsWeb = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPrimaryWebURL(t *testing.T) {
	if got := primaryWebURL("h", HostEvidence{LiveURLs: []string{"https://h/app"}}); got != "https://h/app" {
		t.Errorf("live url not preferred: %q", got)
	}
	if got := primaryWebURL("h", HostEvidence{TLS: true}); got != "https://h" {
		t.Errorf("tls host = %q, want https://h", got)
	}
	if got := primaryWebURL("h", HostEvidence{}); got != "http://h" {
		t.Errorf("plain host = %q, want http://h", got)
	}
}

func TestKatanaAvailable(t *testing.T) {
	if katanaAvailable(Config{KatanaPath: ""}) {
		t.Error("empty path should be unavailable")
	}
	if katanaAvailable(Config{KatanaPath: "/nonexistent/katana-xyz"}) {
		t.Error("nonexistent absolute path should be unavailable")
	}
}

func TestBuildKatana_UsesSystemChromePath(t *testing.T) {
	// With a chrome path configured, katana must be told to use it (so its
	// headless go-rod doesn't try to download a browser and yield 0 endpoints).
	withChrome := buildKatana(Request{Target: "https://app.test/", ScanDir: t.TempDir()},
		Config{KatanaPath: "katana", KatanaTimeout: 60000000000, KatanaChromePath: "/usr/bin/chromium"})
	if !hasArg(withChrome.args, "-system-chrome") {
		t.Errorf("expected -system-chrome; args=%v", withChrome.args)
	}
	if p, _ := argValue(withChrome.args, "-scp"); p != "/usr/bin/chromium" {
		t.Errorf("-scp = %q, want /usr/bin/chromium", p)
	}

	// Without a configured path, katana is left to its own resolution (no -scp).
	noChrome := buildKatana(Request{Target: "https://app.test/", ScanDir: t.TempDir()},
		Config{KatanaPath: "katana", KatanaTimeout: 60000000000})
	if hasArg(noChrome.args, "-scp") {
		t.Errorf("no chrome path configured should not add -scp; args=%v", noChrome.args)
	}
}

func TestBuildKatana_AuthenticatedCrawlUsesStandardEngine(t *testing.T) {
	cfg := Config{KatanaPath: "katana", KatanaTimeout: 60000000000, KatanaChromePath: "/usr/bin/chromium"}
	// katana's headless engine drops -H headers, so a session must switch the
	// crawl to the standard engine or the crawl silently runs logged out.
	authed := buildKatana(Request{Target: "https://app.test/", ScanDir: t.TempDir(), TargetAuth: "Cookie: session=opaque"}, cfg)
	if hasArg(authed.args, "-headless") || hasArg(authed.args, "-system-chrome") {
		t.Errorf("authenticated crawl must not use headless mode; args=%v", authed.args)
	}
	if h, _ := argValue(authed.args, "-H"); h != "Cookie: session=opaque" {
		t.Errorf("session header not attached: -H %q; args=%v", h, authed.args)
	}
	if !hasArg(authed.args, "-jc") {
		t.Errorf("authenticated crawl should still mine JS for routes; args=%v", authed.args)
	}
	public := buildKatana(Request{Target: "https://app.test/", ScanDir: t.TempDir()}, cfg)
	if !hasArg(public.args, "-headless") {
		t.Errorf("unauthenticated crawl should keep headless rendering; args=%v", public.args)
	}
}
