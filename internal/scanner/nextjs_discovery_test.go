package scanner

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestNextjsHTMLReferencesHandleModulePreloadsAndAttributeSyntax(t *testing.T) {
	base, _ := url.Parse("https://app.test/portal/")
	refs := nextjsHTMLReferences(base, []byte(`<script SRC='/portal/_next/static/main.mjs?v=1&amp;x=2' type=module></script><link rel=modulepreload href='/portal/_next/static/lazy.js'><a href='reports?id=1&amp;sort=asc'>Report</a><script src='javascript:alert(1)'></script>`))
	if len(refs.Scripts) != 2 || refs.Scripts[0] != "https://app.test/portal/_next/static/main.mjs?v=1&x=2" || len(refs.Links) != 1 || refs.Links[0] != "https://app.test/portal/reports?id=1&sort=asc" {
		t.Fatalf("references: %+v", refs)
	}
}

func TestNextjsDeepDiscoversLinkedPagesChunksAndAPISeeds(t *testing.T) {
	hits := map[string]int{}
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits[r.URL.Path]++
		if r.Method != "GET" || r.Header.Get("Authorization") != "" {
			t.Error("discovery mixed method or credentials")
		}
		switch r.URL.Path {
		case "/app/":
			w.Write([]byte(`<script>self.__next_f=[]</script><script src='/app/_next/static/main.js'></script><a href='/app/reports'>Reports</a><a href='/app/logout'>Logout</a><a href='/app/api/delete'>API</a><a href='https://outside.test/page'>External</a>`))
		case "/app/reports":
			w.Write([]byte(`<script type=module src='/app/_next/static/reports.mjs'></script><a href='/app/'>Home</a>`))
		case "/app/_next/static/main.js":
			w.Write([]byte(`const chunk="/app/_next/static/lazy.js";const api="/app/api/items?limit=5";`))
		default:
			w.Write([]byte(`console.log("fixture")`))
		}
	}))
	defer lab.Close()
	req := nextjsTestRequest(t, lab.URL+"/app/")
	req.Profile = ProfileNextjsDeep
	req.TargetAuth = "Authorization: fixture-secret"
	run := (nextjsAssetsRunner{}).Run(t.Context(), req, Config{}, nil)
	if run.Status != "completed" {
		t.Fatalf("run: %+v", run)
	}
	for _, path := range []string{"/app/", "/app/reports", "/app/_next/static/main.js", "/app/_next/static/reports.mjs", "/app/_next/static/lazy.js"} {
		if hits[path] != 1 {
			t.Errorf("%s hits=%d", path, hits[path])
		}
	}
	if hits["/app/logout"] != 0 || hits["/app/api/delete"] != 0 || hits["/app/api/items"] != 0 {
		t.Fatalf("unsafe or speculative requests: %v", hits)
	}
	found := false
	for _, candidate := range run.HistoricalCandidates {
		if strings.Contains(candidate.URL, "/api/items?") {
			found = candidate.Source == "javascript_api_reference" && candidate.State == EndpointStateHistoricalUnverified && candidate.Status == 0
		}
	}
	if !found {
		t.Fatalf("missing unverified API seed: %+v", run.HistoricalCandidates)
	}
}

func TestNextjsDeepReportsLimitsAndPreservesCandidates(t *testing.T) {
	hits := 0
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Write([]byte(`<script>self.__next_f=[]</script><a href='/second'>second</a><script src='/_next/static/main.js'></script>`))
	}))
	defer lab.Close()
	req := nextjsTestRequest(t, lab.URL+"/")
	req.Profile, req.Nextjs = ProfileNextjsDeep, assessment.NextjsScanOptions{MaxPages: 1, MaxRequests: 1}
	run := (nextjsAssetsRunner{}).Run(t.Context(), req, Config{}, nil)
	if hits != 1 || run.GapKind != GapBudgetExhausted || !hasNextjsLimitation(run, "nextjs_page_limit") || len(run.HistoricalCandidates) == 0 {
		t.Fatalf("hits=%d run=%+v", hits, run)
	}
}

func TestNextjsDeepHonorsPerURLScopeGuardAndExclusions(t *testing.T) {
	var paths []string
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Write([]byte(`<script>self.__next_f=[]</script><script src='/_next/static/blocked.js'></script><a href='/excluded'>excluded</a>`))
	}))
	defer lab.Close()
	req := nextjsTestRequest(t, lab.URL+"/")
	req.Profile = ProfileNextjsDeep
	scope := assessment.NewAppScope(req.AppScope.Origins(), assessment.Exclusion{Method: "GET", PathPattern: "/excluded"})
	req.AppScope = &scope
	cfg := Config{ScopeGuard: func(raw string, addresses []string) (bool, string) {
		return strings.Contains(raw, "blocked.js"), "blocked fixture"
	}}
	run := (nextjsAssetsRunner{}).Run(t.Context(), req, cfg, nil)
	if len(paths) != 1 || run.Status != "completed" || !hasNextjsLimitation(run, "nextjs_request_failed") {
		t.Fatalf("paths=%v run=%+v", paths, run)
	}
}

func TestNextjsSourceMapRequiresTypedTopLevelStructure(t *testing.T) {
	for _, body := range []string{`{"version":2,"sources":[]}`, `{"message":"\"version\" \"sources\""}`, `{"version":3,"sources":"not-array"}`, `{"nested":{"version":3,"sources":[]}}`, `<!doctype html>{"version":3,"sources":[]}`} {
		if looksLikeSourceMap([]byte(body)) {
			t.Errorf("accepted non-map: %s", body)
		}
	}
	for _, body := range []string{`{"version":3,"sources":["app.ts"],"mappings":""}`, `{"file":"a.js","sources":["app.ts"],"version":3}`, `{"version":3,"sources":["truncated-very-large-map`} {
		if !looksLikeSourceMap([]byte(body)) {
			t.Errorf("missed map structure: %s", body)
		}
	}
}

func TestNextjsDeepAdjacentMapAndDiscoveryReceipts(t *testing.T) {
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<script>self.__next_f=[]</script><script src='/_next/static/main.js'></script>`))
		case "/_next/static/main.js":
			w.Write([]byte(`console.log(1)`))
		case "/_next/static/main.js.map":
			w.Write([]byte(`{"version":3,"sources":["private/source.ts"],"mappings":""}`))
		}
	}))
	defer lab.Close()
	req := nextjsTestRequest(t, lab.URL+"/")
	req.Profile = ProfileNextjsDeep
	run := (nextjsAssetsRunner{}).Run(t.Context(), req, Config{}, nil)
	findings, err := ParseRun(run)
	if err != nil {
		t.Fatal(err)
	}
	maps := 0
	for _, finding := range findings {
		if finding.RuleID == "nextjs-source-map" {
			maps++
			if finding.EvidenceRef == "" || strings.Contains(finding.Evidence, "private/source") {
				t.Fatalf("evidence: %+v", finding)
			}
		}
	}
	if maps != 1 {
		t.Fatalf("findings=%+v", findings)
	}
	events, err := ReadCoverageEvents(run.CoverageEventsPath)
	if err != nil || len(events) != 6 {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	for _, event := range events {
		if event.Phase != "discovery" {
			t.Fatalf("discovery misrepresented: %+v", event)
		}
	}
}

func TestNextjsDiscoveryEnforcesGlobalEndpointAndByteBudgets(t *testing.T) {
	for _, mode := range []string{"endpoints", "bytes"} {
		t.Run(mode, func(t *testing.T) {
			hits := 0
			lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits++
				w.Write([]byte(`<script>self.__next_f=[]</script><script src='/_next/static/main.js'></script>`))
			}))
			defer lab.Close()
			req := nextjsTestRequest(t, lab.URL+"/")
			req.Profile = ProfileNextjsDeep
			cfg := Config{}
			if mode == "endpoints" {
				cfg.Budget = NewAssessmentBudget(0, 1, 0)
			} else {
				req.Nextjs.MaxResponseBytes = 10
			}
			run := (nextjsAssetsRunner{}).Run(t.Context(), req, cfg, nil)
			if hits != 1 || run.GapKind != GapBudgetExhausted {
				t.Fatalf("hits=%d run=%+v", hits, run)
			}
		})
	}
}

func TestNextjsFailedResponseBytesStillConsumeBudget(t *testing.T) {
	hits := 0
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Length", "100")
		w.Write([]byte(strings.Repeat("x", 20))) // Deliberately truncated transfer.
	}))
	defer lab.Close()
	req := nextjsTestRequest(t, lab.URL+"/")
	req.Profile, req.Nextjs.MaxResponseBytes = ProfileNextjsDeep, 30
	req.Inventory = &AttackSurface{Endpoints: []AttackSurfaceEndpoint{
		{URL: lab.URL + "/_next/static/a.js", Path: "/_next/static/a.js", Method: "GET"},
		{URL: lab.URL + "/_next/static/b.js", Path: "/_next/static/b.js", Method: "GET"},
	}}
	run := (nextjsAssetsRunner{}).Run(t.Context(), req, Config{}, nil)
	if hits != 2 || run.GapKind != GapBudgetExhausted {
		t.Fatalf("failed reads bypassed byte budget: hits=%d run=%+v", hits, run)
	}
}
