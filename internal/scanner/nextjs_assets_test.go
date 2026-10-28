package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

type nextjsFixture struct {
	mu       sync.Mutex
	requests []string
	auth     []string
}

func (f *nextjsFixture) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
		f.auth = append(f.auth, r.URL.Path)
	}
	f.mu.Unlock()
	switch r.URL.Path {
	case "/app/":
		w.Header().Set("X-Powered-By", "Next.js")
		_, _ = w.Write([]byte(`<html><script id="__NEXT_DATA__" type="application/json">{"props":{},"buildId":"BuildX1"}</script>` +
			`<script src="/app/_next/static/chunks/main-abc.js" defer=""></script>` +
			`<script src="/app/_next/static/chunks/inline-map.js" defer=""></script>` +
			`<script src="/app/_next/static/chunks/spa-fallback.js" defer=""></script></html>`))
	case "/app/_next/static/chunks/main-abc.js":
		_, _ = w.Write([]byte("window.next={version:\"14.1.0\",appDir:false};\n//# sourceMappingURL=main-abc.js.map\n"))
	case "/app/_next/static/chunks/main-abc.js.map":
		_, _ = w.Write([]byte(`{"version":3,"file":"main-abc.js","sources":["webpack://_N_E/./pages/_app.tsx"],"mappings":"AAAA"}`))
	case "/app/_next/static/chunks/inline-map.js":
		_, _ = w.Write([]byte("console.log(1);\n//# sourceMappingURL=data:application/json;base64,e30=\n"))
	case "/app/_next/static/chunks/spa-fallback.js":
		_, _ = w.Write([]byte("console.log(2);\n//# sourceMappingURL=spa-fallback.js.map\n"))
	case "/app/_next/static/chunks/spa-fallback.js.map":
		// Single-page apps often answer unknown paths with the HTML shell.
		_, _ = w.Write([]byte(`<!doctype html><html><body>app</body></html>`))
	case "/outside.js":
		_, _ = w.Write([]byte("//# sourceMappingURL=outside.js.map\n"))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func nextjsTestRequest(t *testing.T, target string) Request {
	t.Helper()
	cfg := assessment.AssessmentConfig{Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: target}}}
	scope := assessment.AppScopeForTarget(cfg, "app")
	return Request{Target: target, ScanDir: t.TempDir(), Scope: "assessment:app", TypedAssessment: true, AppScope: &scope}
}

func TestNextjsAssetsFingerprintsAndFindsPublicSourceMaps(t *testing.T) {
	fixture := &nextjsFixture{}
	server := httptest.NewServer(http.HandlerFunc(fixture.handler))
	defer server.Close()

	req := nextjsTestRequest(t, server.URL+"/app/")
	// Credentials are configured for the target but must not reach asset requests.
	req.TargetAuth = "Cookie: session=fixture-secret"
	req.Inventory = &AttackSurface{Endpoints: []AttackSurfaceEndpoint{
		{URL: server.URL + "/app/_next/static/chunks/main-abc.js", Method: http.MethodGet, Path: "/app/_next/static/chunks/main-abc.js", Kind: "static"},
		{URL: server.URL + "/outside.js", Method: http.MethodGet, Path: "/outside.js", Kind: "static"},
		{URL: "http://unapproved.example.test/other.js", Method: http.MethodGet, Path: "/other.js", Kind: "static"},
		{URL: server.URL + "/app/_next/static/chunks/posted.js", Method: http.MethodPost, Path: "/app/_next/static/chunks/posted.js", Kind: "static"},
	}}
	run := (nextjsAssetsRunner{}).Run(context.Background(), req, Config{Budget: NewAssessmentBudget(0, 50, 0)}, nil)
	if run.Status != "completed" {
		t.Fatalf("status=%q reason=%q", run.Status, run.Reason)
	}

	for _, got := range fixture.requests {
		if !strings.HasPrefix(got, "GET /app/") {
			t.Fatalf("request outside the approved method or path scope: %s", got)
		}
		if strings.HasSuffix(got, "posted.js") {
			t.Fatalf("non-GET inventory entry was requested: %s", got)
		}
	}
	if len(fixture.auth) != 0 {
		t.Fatalf("credentials were forwarded to asset requests: %v", fixture.auth)
	}

	findings, err := ParseRun(run)
	if err != nil {
		t.Fatal(err)
	}
	var fingerprint, maps []Finding
	for _, f := range findings {
		switch f.RuleID {
		case "nextjs-fingerprint":
			fingerprint = append(fingerprint, f)
		case "nextjs-source-map":
			maps = append(maps, f)
		default:
			t.Fatalf("unexpected rule %q", f.RuleID)
		}
	}
	if len(fingerprint) != 1 || fingerprint[0].PackageVersion != "14.1.0" || !strings.Contains(fingerprint[0].Evidence, "build ID BuildX1") || fingerprint[0].Package != "next" {
		t.Fatalf("fingerprint = %+v", fingerprint)
	}
	// Only the real map counts: the data: URI is inline and the SPA fallback is HTML.
	if len(maps) != 1 || !strings.HasSuffix(maps[0].Endpoint, "/app/_next/static/chunks/main-abc.js.map") || maps[0].CWE != "CWE-540" {
		t.Fatalf("source map findings = %+v", maps)
	}
	if strings.Contains(maps[0].Evidence, "webpack://") || strings.Contains(maps[0].Evidence, "AAAA") {
		t.Fatalf("source map content was retained in evidence: %q", maps[0].Evidence)
	}
	if !hasLimitation(run, LimitationAnonymousAssets) {
		t.Fatalf("anonymous-assets limitation missing: %+v", run.Limitations)
	}
}

func TestNextjsAssetsReportsNoSignalsForOtherApps(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><script src="/static/app.js"></script></html>`))
	}))
	defer server.Close()
	run := (nextjsAssetsRunner{}).Run(context.Background(), nextjsTestRequest(t, server.URL+"/"), Config{}, nil)
	if run.Status != "completed" || !strings.Contains(run.Reason, "no Next.js signals") {
		t.Fatalf("status=%q reason=%q", run.Status, run.Reason)
	}
	if findings, err := ParseRun(run); err != nil || len(findings) != 0 {
		t.Fatalf("findings=%v err=%v", findings, err)
	}
}

func TestNextjsAssetsCapsScriptsAndKeepsManifestFirst(t *testing.T) {
	req := nextjsTestRequest(t, "https://app.example.test/")
	var scripts []string
	for i := range nextjsMaxScripts + 5 {
		scripts = append(scripts, "https://app.example.test/_next/static/chunks/"+strings.Repeat("a", i+1)+".js")
	}
	scripts = append(scripts, "https://app.example.test/_next/static/B1/_buildManifest.js", "https://other.example.test/x.js", scripts[0])
	got := nextjsInScopeScripts(req, scripts)
	if len(got) != nextjsMaxScripts+6 || !strings.HasSuffix(got[0], "_buildManifest.js") {
		t.Fatalf("got %d scripts, first %q", len(got), got[0])
	}
	for _, s := range got {
		if strings.Contains(s, "other.example.test") {
			t.Fatalf("out-of-scope script kept: %s", s)
		}
	}
}

func TestNextjsAssetsCancelledBeforeRequests(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	run := (nextjsAssetsRunner{}).Run(ctx, nextjsTestRequest(t, "https://app.example.test/"), Config{Budget: NewAssessmentBudget(0, 50, 0)}, nil)
	if run.Status != "failed" || run.GapKind != GapCancelled {
		t.Fatalf("status=%q gap=%q reason=%q", run.Status, run.GapKind, run.Reason)
	}
}

func TestNextjsAssetsRequiresTypedScope(t *testing.T) {
	run := (nextjsAssetsRunner{}).Run(context.Background(), Request{Target: "https://app.example.test/", ScanDir: t.TempDir()}, Config{}, nil)
	if run.Status != "failed" {
		t.Fatalf("status=%q", run.Status)
	}
}

func TestNextjsAssetsRegisteredAsPassiveOptionalStage(t *testing.T) {
	def, ok := RegistryEntry("nextjs-assets")
	if !ok || def.DefaultSelection != "optional" || def.Stage != StagePassive || !def.Selectable || !HasAssessmentRunner("nextjs-assets") {
		t.Fatalf("registry entry = %+v ok=%v", def, ok)
	}
	if _, err := NormalizeScanners([]string{"nextjs-assets"}); err != nil {
		t.Fatal(err)
	}
}

func hasLimitation(run Run, kind string) bool {
	for _, l := range run.Limitations {
		if l.Kind == kind {
			return true
		}
	}
	return false
}

func TestNextjsAssetsPlannedOnlyWhenSelected(t *testing.T) {
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeBlackBox, Types: []assessment.Type{assessment.TypeWebApplication}, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.example.test/"}}}
	stateOf := func(plan AssessmentPlan) (PlanState, string) {
		for _, job := range plan.Jobs {
			if job.Scanner == "nextjs-assets" {
				return job.State, job.Stage
			}
		}
		return "", ""
	}
	if state, _ := stateOf(PlanAssessment(PlanInput{Config: cfg})); state == PlanSelected {
		t.Fatal("optional Next.js checks were selected without operator opt-in")
	}
	cfg.ScannerSelection = assessment.ScannerSelection{Mode: "custom", Variants: []string{"nextjs-assets"}}
	plan := PlanAssessment(PlanInput{Config: cfg})
	if state, stage := stateOf(plan); state != PlanSelected || stage != StagePassive {
		t.Fatalf("selected job state=%q stage=%q", state, stage)
	}
	if plan.ToolVersions["nextjs-assets-catalog"] != nextjsAssetsCatalogVersion {
		t.Fatalf("catalog version not fingerprinted: %v", plan.ToolVersions)
	}
}
