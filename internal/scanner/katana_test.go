package scanner

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
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

func TestBuildKatana_RejectsEmptyTypedScope(t *testing.T) {
	scope := assessment.NewAppScope(nil)
	spec := buildKatana(Request{Target: "https://app.example.test/", ScanDir: t.TempDir(), AppScope: &scope}, Config{KatanaPath: "katana"})
	if spec.notApp == "" || hasArg(spec.args, "-ns") {
		t.Fatalf("empty approved scope must not start an unrestricted crawl: %+v", spec)
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

// argValues returns every value passed for a repeatable flag.
func argValues(args []string, flag string) []string {
	var out []string
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			out = append(out, args[i+1])
		}
	}
	return out
}

// katanaRegexes compiles every value of a katana regex flag. katana parses
// -cs/-cos with goflags' comma-separated slice options, so a raw comma would
// split one regex into two broken ones; none may appear.
func katanaRegexes(t *testing.T, args []string, flag string) []*regexp.Regexp {
	t.Helper()
	var out []*regexp.Regexp
	for _, v := range argValues(args, flag) {
		if strings.Contains(v, ",") {
			t.Errorf("%s value %q contains a raw comma (goflags would split it)", flag, v)
		}
		re, err := regexp.Compile(v)
		if err != nil {
			t.Fatalf("%s value %q does not compile: %v", flag, v, err)
		}
		out = append(out, re)
	}
	return out
}

func anyMatch(res []*regexp.Regexp, s string) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func TestKatanaScopeRegexEnforcesPortAndPath(t *testing.T) {
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{
		{TargetID: "t1", Scheme: "https", Host: "app.example.test", Port: 8443, PathPrefix: "/portal"},
		{TargetID: "t1", Scheme: "https", Host: "api.example.test", PathPrefix: "/"},
	})
	spec := buildKatana(Request{Target: "https://app.example.test:8443/portal/", ScanDir: t.TempDir(), AppScope: &scope},
		Config{KatanaPath: "katana", KatanaTimeout: time.Minute, RateRPS: 5})
	cs := katanaRegexes(t, spec.args, "-cs")
	if len(cs) == 0 {
		t.Fatalf("typed scope must add -cs regexes; args=%v", spec.args)
	}
	for _, u := range []string{
		"https://app.example.test:8443/portal",
		"https://app.example.test:8443/portal/",
		"https://app.example.test:8443/portal/users?id=1",
		"https://app.example.test:8443/portal?x=1",
		"https://APP.example.test:8443/portal/a",
		"https://api.example.test/v1/items",
		"https://api.example.test:443/v1/items",
		"https://api.example.test",
	} {
		if !anyMatch(cs, u) {
			t.Errorf("-cs should allow in-scope %q", u)
		}
	}
	for _, u := range []string{
		"https://app.example.test/portal/users",         // default port, not :8443
		"https://app.example.test:443/portal/users",     // wrong port
		"http://app.example.test:8443/portal/users",     // wrong scheme
		"https://app.example.test:8443/portalx",         // not a segment boundary
		"https://app.example.test:8443/admin",           // outside the path prefix
		"https://app.example.test:84430/portal",         // port prefix trick
		"https://app.example.test.evil.net:8443/portal", // host suffix trick
		"https://api.example.test:8443/v1",              // non-approved port
		"https://evil.net/?https://api.example.test/",   // embedded origin
	} {
		if anyMatch(cs, u) {
			t.Errorf("-cs must refuse out-of-scope %q", u)
		}
	}
	// A host-only field scope would block the explicitly approved API origin.
	if hasArg(spec.args, "-fs") {
		t.Errorf("typed crawl must allow all approved origins: %v", spec.args)
	}
	if !hasArg(spec.args, "-ns") {
		t.Errorf("typed crawl must disable implicit host scope while keeping -cs: %v", spec.args)
	}

	// Legacy requests (no typed scope) keep the old argv: no -cs/-cos.
	legacy := buildKatana(Request{Target: "https://app.example.test/", ScanDir: t.TempDir()}, Config{KatanaPath: "katana"})
	if hasArg(legacy.args, "-cs") || hasArg(legacy.args, "-cos") {
		t.Errorf("legacy crawl must not gain scope regexes; args=%v", legacy.args)
	}
	if fs, _ := argValue(legacy.args, "-fs"); fs != "fqdn" {
		t.Errorf("legacy crawl must remain host-scoped: %v", legacy.args)
	}
	if hasArg(legacy.args, "-ns") {
		t.Errorf("legacy crawl must not disable host scoping: %v", legacy.args)
	}
}

func TestKatanaExclusionsAddedToOutOfScopeRegex(t *testing.T) {
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{
		{TargetID: "t1", Scheme: "https", Host: "app.example.test", PathPrefix: "/"},
	},
		assessment.Exclusion{PathPattern: "/logout", Reason: "ends the session"},
		assessment.Exclusion{PathPattern: "/api/*/delete"},
		assessment.Exclusion{PathPattern: "/admin"},
		assessment.Exclusion{Method: "POST", PathPattern: "/checkout/purchase"},
		assessment.Exclusion{PathPattern: "/ops/a,b"},
		assessment.Exclusion{Origin: "https://other.example.test", PathPattern: "/operator"},
	)
	spec := buildKatana(Request{Target: "https://app.example.test/", ScanDir: t.TempDir(), AppScope: &scope},
		Config{KatanaPath: "katana", KatanaTimeout: time.Minute})
	cos := katanaRegexes(t, spec.args, "-cos")
	if len(cos) == 0 {
		t.Fatalf("exclusions must add -cos regexes; args=%v", spec.args)
	}
	for _, u := range []string{
		"https://app.example.test/logout",
		"https://app.example.test/LOGOUT?next=/",
		"https://app.example.test:443/logout",
		"https://app.example.test/logout/",
		"https://app.example.test/api/v1/delete",
		"https://app.example.test/api/v1/delete?id=7",
		"https://app.example.test/admin/users",
		"https://app.example.test/checkout/purchase", // method-bound exclusions still fence the crawl
		"https://app.example.test/ops/a,b",
		"https://other.example.test/operator/x",
	} {
		if !anyMatch(cos, u) {
			t.Errorf("-cos should exclude %q", u)
		}
	}
	for _, u := range []string{
		"https://app.example.test/login",
		"https://app.example.test/logoutx",
		"https://app.example.test/administrator",
		"https://app.example.test/api/v1/items",
		"https://app.example.test/operator", // origin-bound exclusion is for another origin
		"https://app.example.test/?next=/logout",
	} {
		if anyMatch(cos, u) {
			t.Errorf("-cos must not exclude %q", u)
		}
	}
}

func TestKatanaAuthenticatedCrawlDoesNotFollowCrossOriginRedirect(t *testing.T) {
	cfg := Config{KatanaPath: "katana", KatanaTimeout: time.Minute}
	authed := buildKatana(Request{Target: "https://app.example.test/", ScanDir: t.TempDir(), TargetAuth: "X-API-Key: opaque"}, cfg)
	if !hasArg(authed.args, "-dr") {
		t.Errorf("authenticated crawl must disable redirects (-dr); args=%v", authed.args)
	}
	headered := buildKatana(Request{Target: "https://app.example.test/", ScanDir: t.TempDir()},
		Config{KatanaPath: "katana", ScanHeaders: []string{"Authorization: Bearer opaque"}})
	if !hasArg(headered.args, "-dr") {
		t.Errorf("crawl carrying operator headers must disable redirects (-dr); args=%v", headered.args)
	}
	public := buildKatana(Request{Target: "https://app.example.test/", ScanDir: t.TempDir()}, cfg)
	if hasArg(public.args, "-dr") {
		t.Errorf("anonymous crawl keeps following redirects; args=%v", public.args)
	}

	// The redirects katana did not follow are recorded: cross-origin targets as
	// out_of_scope candidates, in-scope targets as dispatchable inventory.
	dir := t.TempDir()
	artifact := filepath.Join(dir, "results.jsonl")
	rows := strings.Join([]string{
		`{"timestamp":"2026-10-02T00:00:00Z","request":{"method":"GET","endpoint":"https://app.example.test/sso"},"response":{"status_code":302,"headers":{"Location":"https://idp.evil.example/steal?c=1"}}}`,
		`{"timestamp":"2026-10-02T00:00:01Z","request":{"method":"GET","endpoint":"https://app.example.test/home"},"response":{"status_code":301,"headers":{"location":"/dashboard"}}}`,
		`{"timestamp":"2026-10-02T00:00:02Z","request":{"method":"GET","endpoint":"https://app.example.test/ok"},"response":{"status_code":200,"headers":{"Location":"https://ignored.example/"}}}`,
		`not json`,
	}, "\n")
	if err := os.WriteFile(artifact, []byte(rows), 0o600); err != nil {
		t.Fatal(err)
	}
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{{TargetID: "t1", Scheme: "https", Host: "app.example.test", PathPrefix: "/"}})
	surface := NewSeedAttackSurface("t1", "https://app.example.test/")
	added := MergeKatanaRedirectTargets(surface, artifact, &scope, true)
	if added != 2 {
		t.Errorf("MergeKatanaRedirectTargets added %d, want 2", added)
	}
	byURL := map[string]AttackSurfaceEndpoint{}
	for _, ep := range surface.Endpoints {
		byURL[ep.URL] = ep
	}
	cross, ok := byURL["https://idp.evil.example/steal?c=1"]
	if !ok {
		t.Fatalf("cross-origin redirect target not recorded; endpoints=%+v", surface.Endpoints)
	}
	if cross.State != EndpointStateOutOfScope || cross.StateReason == "" {
		t.Errorf("cross-origin redirect state = %q (%q), want out_of_scope with reason", cross.State, cross.StateReason)
	}
	if !hasString(cross.Sources, "redirect") {
		t.Errorf("redirect target sources = %v, want redirect", cross.Sources)
	}
	same, ok := byURL["https://app.example.test/dashboard"]
	if !ok {
		t.Fatalf("relative in-scope redirect target not resolved/recorded; endpoints=%+v", surface.Endpoints)
	}
	if same.State != EndpointStateInScope {
		t.Errorf("in-scope redirect state = %q, want in_scope", same.State)
	}
	if _, ok := byURL["https://ignored.example/"]; ok {
		t.Error("a Location header on a non-3xx response is not a redirect")
	}
	if MergeKatanaRedirectTargets(nil, artifact, &scope, true) != 0 {
		t.Error("nil surface must be a no-op")
	}
	if MergeKatanaRedirectTargets(NewSeedAttackSurface("t1", "https://app.example.test/"), filepath.Join(dir, "missing.jsonl"), &scope, true) != 0 {
		t.Error("missing artifact must be a no-op")
	}
}

func hasString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func TestKatanaConcurrencyBoundedByRate(t *testing.T) {
	cases := []struct {
		rate      int
		wantC     string
		wantRL    string
		wantRLSet bool
	}{
		{rate: 1, wantC: "1", wantRL: "1", wantRLSet: true},
		{rate: 2, wantC: "2", wantRL: "2", wantRLSet: true},
		{rate: 10, wantC: "10", wantRL: "10", wantRLSet: true},
		{rate: 150, wantC: "10", wantRL: "150", wantRLSet: true},
		{rate: 0, wantC: "10"}, // no rate configured: legacy concurrency, no -rl
	}
	for _, c := range cases {
		spec := buildKatana(Request{Target: "https://app.example.test/", ScanDir: t.TempDir()},
			Config{KatanaPath: "katana", KatanaTimeout: time.Minute, RateRPS: c.rate})
		if got := argValues(spec.args, "-c"); len(got) != 1 || got[0] != c.wantC {
			t.Errorf("rate %d: -c = %v, want [%s]", c.rate, got, c.wantC)
		}
		rl, ok := argValue(spec.args, "-rl")
		if ok != c.wantRLSet || rl != c.wantRL {
			t.Errorf("rate %d: -rl = %q (set %v), want %q (set %v)", c.rate, rl, ok, c.wantRL, c.wantRLSet)
		}
		if r, _ := argValue(spec.args, "-retry"); r != "1" {
			t.Errorf("rate %d: -retry = %q, want 1", c.rate, r)
		}
		if to, ok := argValue(spec.args, "-timeout"); !ok || to == "" || to == "0" {
			t.Errorf("rate %d: -timeout = %q, want a per-request timeout", c.rate, to)
		}
	}
}

func TestKatanaDisablesUpdateCheck(t *testing.T) {
	for _, req := range []Request{
		{Target: "https://app.example.test/", ScanDir: t.TempDir()},
		{Target: "https://app.example.test/", ScanDir: t.TempDir(), TargetAuth: "Cookie: s=1"},
	} {
		spec := buildKatana(req, Config{KatanaPath: "katana"})
		if !hasArg(spec.args, "-duc") {
			t.Errorf("katana must not phone home for updates (-duc); args=%v", spec.args)
		}
	}
}

func TestKatanaCrawlDurationCappedByBudget(t *testing.T) {
	parseCT := func(t *testing.T, args []string) time.Duration {
		t.Helper()
		v, ok := argValue(args, "-ct")
		if !ok {
			t.Fatalf("missing -ct; args=%v", args)
		}
		d, err := time.ParseDuration(v)
		if err != nil {
			t.Fatalf("-ct %q is not a duration: %v", v, err)
		}
		return d
	}
	req := Request{Target: "https://app.example.test/", ScanDir: t.TempDir()}

	// Without a budget the crawl stops on its own before the process timeout,
	// so katana flushes its JSONL instead of being killed mid-write.
	plain := buildKatana(req, Config{KatanaPath: "katana", KatanaTimeout: 10 * time.Minute})
	if ct := parseCT(t, plain.args); ct <= 0 || ct >= 10*time.Minute {
		t.Errorf("-ct = %v, want positive and below the 10m process timeout", ct)
	}
	if plain.timeout != 10*time.Minute {
		t.Errorf("timeout = %v, want KatanaTimeout", plain.timeout)
	}

	// The remaining assessment budget caps both the crawl and the process.
	budget := NewAssessmentBudget(10, 0, 2*time.Minute)
	capped := buildKatana(req, Config{KatanaPath: "katana", KatanaTimeout: time.Hour, Budget: budget})
	if ct := parseCT(t, capped.args); ct <= 0 || ct > 2*time.Minute {
		t.Errorf("-ct = %v, want <= remaining budget 2m", ct)
	}
	if capped.timeout <= 0 || capped.timeout > 2*time.Minute {
		t.Errorf("timeout = %v, want capped by the 2m remaining budget", capped.timeout)
	}

	// No KatanaTimeout: the budget alone bounds the crawl.
	budgetOnly := buildKatana(req, Config{KatanaPath: "katana", Budget: NewAssessmentBudget(10, 0, 3*time.Minute)})
	if ct := parseCT(t, budgetOnly.args); ct <= 0 || ct > 3*time.Minute {
		t.Errorf("-ct = %v, want <= 3m budget", ct)
	}
	if budgetOnly.timeout <= 0 || budgetOnly.timeout > 3*time.Minute {
		t.Errorf("timeout = %v, want bounded by the 3m budget", budgetOnly.timeout)
	}

	// A budget without a deadline does not cap anything.
	noDeadline := buildKatana(req, Config{KatanaPath: "katana", KatanaTimeout: 10 * time.Minute, Budget: NewAssessmentBudget(10, 0, 0)})
	if noDeadline.timeout != 10*time.Minute {
		t.Errorf("timeout = %v, want KatanaTimeout when the budget has no deadline", noDeadline.timeout)
	}

	// An exhausted budget sends no traffic at all.
	spent := NewAssessmentBudget(10, 0, time.Nanosecond)
	time.Sleep(time.Millisecond)
	exhausted := buildKatana(req, Config{KatanaPath: "katana", KatanaTimeout: time.Hour, Budget: spent})
	if exhausted.notApp == "" {
		t.Errorf("an exhausted budget must not start the crawl; args=%v", exhausted.args)
	}
}
