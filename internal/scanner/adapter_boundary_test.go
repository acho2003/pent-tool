package scanner

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func scopeFor(t *testing.T, raw string, exclusions ...assessment.Exclusion) *assessment.AppScope {
	t.Helper()
	origin, err := assessment.ParseApprovedOrigin("app", raw)
	if err != nil {
		t.Fatal(err)
	}
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin}, exclusions...)
	return &scope
}

func TestTestsslIsRestrictedWhenItsRootRequestWouldLeaveTheApprovedPaths(t *testing.T) {
	cfg := Config{TestsslPath: "testssl.sh"}
	pathBounded := Request{Target: "https://app.test/app/", ScanDir: t.TempDir(), AppScope: scopeFor(t, "https://app.test/app/")}
	if spec := buildTestssl(pathBounded, cfg); spec.notApp == "" || !strings.Contains(spec.notApp, "origin root") {
		t.Fatalf("testssl must refuse a path-bounded origin: %+v", spec)
	}
	rootBounded := Request{Target: "https://app.test/", ScanDir: t.TempDir(), AppScope: scopeFor(t, "https://app.test/")}
	if spec := buildTestssl(rootBounded, cfg); spec.notApp != "" {
		t.Fatalf("testssl must run for a whole-origin boundary: %q", spec.notApp)
	}
	excludedRoot := Request{Target: "https://app.test/", ScanDir: t.TempDir(), AppScope: scopeFor(t, "https://app.test/", assessment.Exclusion{PathPattern: "/"})}
	if spec := buildTestssl(excludedRoot, cfg); spec.notApp == "" {
		t.Fatal("testssl must refuse when the origin root is excluded")
	}
	legacy := Request{Target: "app.test", ScanDir: t.TempDir()}
	if spec := buildTestssl(legacy, cfg); spec.notApp != "" {
		t.Fatalf("legacy scans have no scope and must still run: %q", spec.notApp)
	}
	// The refusal is tagged as a policy gap, like nikto and wapiti.
	run := executePolicySpec(t.Context(), "testssl", pathBounded, cfg, buildTestssl(pathBounded, cfg), nil)
	if run.Status != "not_applicable" || run.GapKind != GapExcluded {
		t.Fatalf("refused testssl run = status %q gap %q", run.Status, run.GapKind)
	}
}

func TestNiktoChecksScopeExclusionsAndTheScopeGuard(t *testing.T) {
	cfg := Config{NiktoPath: "nikto"}
	inScope := Request{Target: "https://app.test/", ScanDir: t.TempDir(), AppScope: scopeFor(t, "https://app.test/")}
	if spec := buildNikto(inScope, cfg); spec.notApp != "" {
		t.Fatalf("an in-scope root must run: %q", spec.notApp)
	}
	outside := Request{Target: "https://other.test/", ScanDir: t.TempDir(), AppScope: scopeFor(t, "https://app.test/")}
	if spec := buildNikto(outside, cfg); !strings.Contains(spec.notApp, "outside the approved scope") {
		t.Fatalf("an out-of-scope target must be refused: %q", spec.notApp)
	}
	guarded := cfg
	guarded.ScopeGuard = func(string, []string) (bool, string) { return true, "scope guard: target is the dashboard listener" }
	if spec := buildNikto(inScope, guarded); !strings.Contains(spec.notApp, "dashboard listener") {
		t.Fatalf("the scope guard was not consulted: %q", spec.notApp)
	}
}

func TestNmapIsBoundedAndChecksResolvedAddresses(t *testing.T) {
	cfg := Config{NmapPath: "nmap"}
	spec := buildNmap(Request{Target: "192.0.2.10", ScanDir: t.TempDir()}, cfg)
	if spec.notApp != "" || !slices.Contains(spec.args, "-n") || !slices.Contains(spec.args, "--max-rate") {
		t.Fatalf("nmap must skip reverse DNS and bound its rate: %+v", spec)
	}
	if spec := buildNmap(Request{Target: "192.0.2.0/24", ScanDir: t.TempDir()}, cfg); spec.notApp != "" {
		t.Fatalf("a /24 is the largest allowed network: %q", spec.notApp)
	}
	if spec := buildNmap(Request{Target: "10.0.0.0/16", ScanDir: t.TempDir()}, cfg); !strings.Contains(spec.notApp, "at most 256 addresses") {
		t.Fatalf("a /16 must be refused: %q", spec.notApp)
	}
	if spec := buildNmap(Request{Target: "2001:db8::/64", ScanDir: t.TempDir()}, cfg); !strings.Contains(spec.notApp, "at most 256 addresses") {
		t.Fatalf("a /64 IPv6 network must be refused: %q", spec.notApp)
	}
	var seen []string
	guarded := cfg
	guarded.ScopeGuard = func(raw string, resolved []string) (bool, string) {
		seen = resolved
		return slices.Contains(resolved, "127.0.0.1"), "scope guard: resolved address 127.0.0.1 is the scanner host"
	}
	if spec := buildNmap(Request{Target: "127.0.0.1", ScanDir: t.TempDir()}, guarded); !strings.Contains(spec.notApp, "scanner host") || !slices.Contains(seen, "127.0.0.1") {
		t.Fatalf("the scope guard did not judge the resolved address: %q seen=%v", spec.notApp, seen)
	}
	if spec := buildNmap(Request{Target: "192.0.2.10", ScanDir: t.TempDir()}, guarded); spec.notApp != "" {
		t.Fatalf("an allowed address was refused: %q", spec.notApp)
	}
}

// recordingServer counts every request so a test can show that a refused
// adapter sent nothing at all.
func recordingServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	return server, &seen
}

func blockingGuard(resolved *[]string) func(string, []string) (bool, string) {
	return func(_ string, addresses []string) (bool, string) {
		*resolved = addresses
		return true, "scope guard: resolved address is the scanner host or dashboard listener"
	}
}

func TestNextjsAssetsAsksTheScopeGuardAboutResolvedAddresses(t *testing.T) {
	server, seen := recordingServer(t, func(w http.ResponseWriter, _ *http.Request) { w.Header().Set("X-Powered-By", "Next.js") })
	target := server.URL + "/"
	req := Request{Target: target, ScanDir: t.TempDir(), Scope: "assessment:app", TypedAssessment: true, AppScope: scopeFor(t, target)}
	var resolved []string
	run := (nextjsAssetsRunner{}).Run(t.Context(), req, Config{ScopeGuard: blockingGuard(&resolved)}, nil)
	if len(*seen) != 0 {
		t.Fatalf("a guarded origin was requested: %v", *seen)
	}
	if !slices.Contains(resolved, "127.0.0.1") {
		t.Fatalf("the guard was not given the resolved address: %v", resolved)
	}
	if run.Status != "failed" || !strings.Contains(run.Reason, "scope guard") {
		t.Fatalf("status=%q reason=%q", run.Status, run.Reason)
	}
}

func TestKubeExposureAsksTheScopeGuardAboutResolvedAddresses(t *testing.T) {
	server, seen := recordingServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
	target := server.URL + "/"
	req := Request{Target: target, ScanDir: t.TempDir(), Scope: "assessment:app", TypedAssessment: true, AppScope: scopeFor(t, target)}
	var resolved []string
	run := (kubeExposureRunner{}).Run(t.Context(), req, Config{Budget: NewAssessmentBudget(0, 20, 0), ScopeGuard: blockingGuard(&resolved)}, nil)
	if len(*seen) != 0 {
		t.Fatalf("a guarded origin was requested: %v", *seen)
	}
	if !slices.Contains(resolved, "127.0.0.1") {
		t.Fatalf("the guard was not given the resolved address: %v", resolved)
	}
	if run.Status != "failed" || !strings.Contains(run.Reason, "scope guard") {
		t.Fatalf("status=%q reason=%q", run.Status, run.Reason)
	}
}

func TestKubeExposureHonoursExclusionsIncludingRedirectTargets(t *testing.T) {
	server, seen := recordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dashboard/":
			http.Redirect(w, r, "/logout", http.StatusFound)
		case "/api/health":
			http.Redirect(w, r, "/api/health/ok", http.StatusFound)
		case "/api/health/ok":
			_, _ = w.Write([]byte(`{"database":"ok"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	target := server.URL + "/"
	scope := scopeFor(t, target, assessment.Exclusion{PathPattern: "/version"}, assessment.Exclusion{PathPattern: "/logout"})
	req := Request{Target: target, ScanDir: t.TempDir(), Scope: "assessment:app", TypedAssessment: true, AppScope: scope}
	run := (kubeExposureRunner{}).Run(t.Context(), req, Config{Budget: NewAssessmentBudget(0, 40, 0)}, nil)
	if run.Status != "completed" {
		t.Fatalf("status=%q reason=%q", run.Status, run.Reason)
	}
	for _, got := range *seen {
		if got == "GET /version" || got == "GET /logout" {
			t.Fatalf("an excluded path was requested: %v", *seen)
		}
	}
	if !slices.Contains(*seen, "GET /dashboard/") || !slices.Contains(*seen, "GET /api/health/ok") {
		t.Fatalf("an in-scope redirect was not followed: %v", *seen)
	}
	findings, err := ParseRun(run)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(findings, func(f Finding) bool { return f.RuleID == "grafana" }) {
		t.Fatalf("the redirected Grafana health response was not classified: %+v", findings)
	}
}
