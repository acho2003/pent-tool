package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/apifixture"
	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func boundaryFixture(t *testing.T, target string, f NextjsBoundaryFixture, collector string) (Request, Config) {
	t.Helper()
	store := apifixture.Store{Dir: t.TempDir()}
	raw, _ := json.Marshal(f)
	meta, err := store.Put(bytes.NewReader(raw), "application/json")
	if err != nil {
		t.Fatal(err)
	}
	req := nextjsTestRequest(t, target+"/")
	req.TargetID, req.WorkflowVersion, req.TestEnvironment = "app", "unified-v1", true
	req.APIFixtureDir, req.WriteJournalDir = store.Dir, t.TempDir()
	if collector != "" {
		origin, err := assessment.ParseApprovedOrigin("app", collector)
		if err != nil {
			t.Fatal(err)
		}
		req.AppScope = ptrBoundaryScope(assessment.NewAppScope(append(req.AppScope.Origins(), origin)))
	}
	req.NextjsBoundaryApprovals = []assessment.NextjsBoundaryApproval{{ID: "controlled-" + f.Kind, TargetID: "app", Kind: f.Kind, FixtureRef: meta.Ref, Identity: "anonymous"}}
	if f.Kind == "cache" {
		req.NextjsBoundaryApprovals[0].OwnerIdentity = "owner"
	}
	for _, identity := range []string{"owner", "reader"} {
		req.AuthContexts = append(req.AuthContexts, AuthContext{ID: AuthenticationContextID("app", identity), TargetID: "app", Identity: identity, State: assessment.StateVerified, Headers: []string{"Authorization: Bearer " + identity + "-secret"}, Refresh: func(_ context.Context, headers []string) ([]string, error) { return headers, nil }})
	}
	req.TargetAuth = "Authorization: PRIMARY_SHOULD_NOT_LEAK"
	return req, Config{Budget: NewAssessmentBudget(0, 100, 0), ScanHeaders: []string{"Cookie: GLOBAL_SHOULD_NOT_LEAK"}}
}
func ptrBoundaryScope(scope assessment.AppScope) *assessment.AppScope { return &scope }

type boundaryCacheLab struct {
	mu            sync.Mutex
	cached        bool
	mode          string
	fills, resets int
}

func (lab *boundaryCacheLab) handler(t *testing.T, w http.ResponseWriter, r *http.Request) {
	lab.mu.Lock()
	defer lab.mu.Unlock()
	if r.Header.Get("Cookie") != "" {
		t.Error("global credentials leaked")
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/private":
		owner := r.Header.Get("Authorization") == "Bearer owner-secret"
		bypass := r.URL.Query().Get("uncached") == "1"
		if owner {
			lab.fills++
			lab.cached = true
		}
		leak := lab.cached && lab.mode != "patched" && (!bypass || lab.mode == "bypass-leaks")
		w.Header().Set("Content-Type", "application/json")
		if owner && lab.mode == "generic-owner" {
			w.Write([]byte(`{"page":"login"}`))
			return
		}
		if owner || leak {
			if !owner && lab.mode != "no-hit-header" {
				w.Header().Set("X-Nextjs-Cache", "HIT")
			}
			w.Write([]byte(`{"record":"PRIVATE_CONTROLLED_42"}`))
			return
		}
		http.Error(w, "DENIED_CONTROLLED_42", 403)
	case r.Method == "DELETE" && r.URL.Path == "/reset-cache":
		lab.resets++
		if r.Header.Get("Authorization") != "Bearer owner-secret" {
			t.Error("reset did not use owner")
		}
		if lab.mode == "reset-fails" {
			http.Error(w, "reset failed", 500)
			return
		}
		if lab.mode != "reset-lies" {
			lab.cached = false
		}
		w.WriteHeader(204)
	default:
		t.Errorf("unexpected cache request: %s %s", r.Method, r.URL.String())
		http.NotFound(w, r)
	}
}
func (lab *boundaryCacheLab) snapshot() (bool, int, int) {
	lab.mu.Lock()
	defer lab.mu.Unlock()
	return lab.cached, lab.fills, lab.resets
}
func cacheBoundaryManifest(base string) NextjsBoundaryFixture {
	return NextjsBoundaryFixture{Kind: "cache", URL: base + "/private", BypassURL: base + "/private?uncached=1", Representation: "pages-json", PrivateMarker: "PRIVATE_CONTROLLED_42", DeniedMarker: "DENIED_CONTROLLED_42", Isolated: true, CleanupURL: base + "/reset-cache", CleanupMethod: "DELETE"}
}

func TestNextjsCacheBoundaryRequiresPairedControlsAndVerifiesReset(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	for _, mode := range []string{"patched", "vulnerable", "no-hit-header", "bypass-leaks", "generic-owner", "reset-fails", "reset-lies"} {
		t.Run(mode, func(t *testing.T) {
			lab := &boundaryCacheLab{mode: mode}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { lab.handler(t, w, r) }))
			defer server.Close()
			req, cfg := boundaryFixture(t, server.URL, cacheBoundaryManifest(server.URL), "")
			run := (nextjsBoundariesRunner{}).Run(t.Context(), req, cfg, nil)
			cached, fills, resets := lab.snapshot()
			if fills != 1 || resets != 1 {
				t.Fatalf("fills=%d resets=%d run=%+v", fills, resets, run)
			}
			findings, err := ParseRun(run)
			if err != nil {
				t.Fatal(err)
			}
			want := 1
			if mode == "patched" || mode == "generic-owner" {
				want = 0
			}
			if len(findings) != want || len(run.AuthorizationResults) != 1 {
				t.Fatalf("findings=%+v run=%+v", findings, run)
			}
			result := run.AuthorizationResults[0]
			if mode == "no-hit-header" || mode == "bypass-leaks" {
				if result.CacheAttribution != "unverified" || strings.Contains(findings[0].Title, "Shared cache") {
					t.Fatal("cache cause was overstated")
				}
			}
			if mode == "vulnerable" && result.CacheAttribution != "confirmed" {
				t.Fatalf("missing cache attribution: %+v", result)
			}
			if mode == "reset-fails" || mode == "reset-lies" {
				if run.Status != "failed" || result.CleanupStatus != "failed" {
					t.Fatalf("unsafe reset: %+v", run)
				}
			} else if cached || result.CleanupStatus != "verified" {
				t.Fatalf("reset was not proven: %+v", run)
			}
			if mode == "generic-owner" && run.Outcome != "PARTIAL" {
				t.Fatal("unknown baseline reported clean")
			}
			for _, path := range []string{run.ArtifactPath, run.CoverageEventsPath, WriteJournalPath(req.WriteJournalDir)} {
				data, _ := os.ReadFile(path)
				for _, value := range []string{"PRIVATE_CONTROLLED_42", "owner-secret", "PRIMARY_SHOULD_NOT_LEAK", "GLOBAL_SHOULD_NOT_LEAK"} {
					if strings.Contains(string(data), value) {
						t.Fatalf("secret retained: %s", path)
					}
				}
			}
			req.ScanDir = t.TempDir()
			again := (nextjsBoundariesRunner{}).Run(t.Context(), req, cfg, nil)
			_, nextFills, _ := lab.snapshot()
			if again.Status != "failed" || nextFills != 1 {
				t.Fatal("cache probe replayed")
			}
		})
	}
}

type boundaryCollector struct {
	mu         sync.Mutex
	hits       map[string]int
	directHits int
	mode       string
}

func (collector *boundaryCollector) handler(t *testing.T, w http.ResponseWriter, r *http.Request) {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
		t.Error("target credentials reached collector")
	}
	token := r.URL.Query().Get("scan_token")
	if r.URL.Path == "/hit" {
		collector.hits[token]++
		collector.directHits++
		w.Write([]byte("controlled callback"))
		return
	}
	if r.URL.Path != "/events" {
		t.Errorf("unexpected collector path %s", r.URL.Path)
		http.NotFound(w, r)
		return
	}
	count := collector.hits[token]
	if collector.mode == "stale" {
		count = 1
	}
	if collector.mode == "wrong-token" {
		token = "unrelated-token"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(boundaryCallbackEvent{Token: token, Count: count, Method: "GET"})
}
func TestNextjsProxyBoundaryUsesFreshCallbackAndDoesNotFetchItDirectly(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	for _, mode := range []string{"fetches", "blocked", "stale", "wrong-token"} {
		t.Run(mode, func(t *testing.T) {
			collector := &boundaryCollector{hits: map[string]int{}, mode: mode}
			callback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { collector.handler(t, w, r) }))
			defer callback.Close()
			var mu sync.Mutex
			probes := 0
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				probes++
				mu.Unlock()
				if mode == "fetches" {
					response, err := http.Get(r.URL.Query().Get("url"))
					if err != nil {
						t.Error(err)
					} else {
						io.Copy(io.Discard, response.Body)
						response.Body.Close()
					}
				}
				w.WriteHeader(400)
			}))
			defer target.Close()
			f := NextjsBoundaryFixture{Kind: "proxy", URL: target.URL + "/_next/image?url=%2Fcontrolled.png&w=64&q=75", Parameter: "url", CallbackURL: callback.URL + "/hit", EventsURL: callback.URL + "/events"}
			req, cfg := boundaryFixture(t, target.URL, f, callback.URL)
			run := (nextjsBoundariesRunner{}).Run(t.Context(), req, cfg, nil)
			findings, err := ParseRun(run)
			if err != nil {
				t.Fatal(err)
			}
			collector.mu.Lock()
			hits := collector.directHits
			collector.mu.Unlock()
			mu.Lock()
			count := probes
			mu.Unlock()
			if mode == "fetches" {
				if len(findings) != 1 || hits != 1 || count != 1 || run.AuthorizationResults[0].CorrelationDigest == "" {
					t.Fatalf("missing correlation: %+v hits=%d probes=%d", run, hits, count)
				}
			} else {
				if len(findings) != 0 || hits != 0 || run.Outcome != "PARTIAL" {
					t.Fatalf("false fetch/clean result: %+v hits=%d", run, hits)
				}
			}
			if (mode == "stale" || mode == "wrong-token") && count != 0 {
				t.Fatal("probe sent despite invalid fresh control")
			}
		})
	}
}

func TestNextjsRedirectBoundaryComparesLocalControlWithoutFollowing(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	for _, vulnerable := range []bool{false, true} {
		t.Run(fmt.Sprint(vulnerable), func(t *testing.T) {
			sinkHits := 0
			var mu sync.Mutex
			sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				sinkHits++
				mu.Unlock()
				t.Error("redirect was followed")
			}))
			defer sink.Close()
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/login" {
					t.Error("local redirect followed")
				}
				next := r.URL.Query().Get("next")
				if strings.HasPrefix(next, "http") && !vulnerable {
					http.Error(w, "rejected", 400)
					return
				}
				w.Header().Set("Location", next)
				w.WriteHeader(302)
			}))
			defer target.Close()
			req, cfg := boundaryFixture(t, target.URL, NextjsBoundaryFixture{Kind: "redirect", URL: target.URL + "/login?next=%2Faccount", Parameter: "next", ControlValue: "/account", DestinationURL: sink.URL + "/sink"}, sink.URL)
			run := (nextjsBoundariesRunner{}).Run(t.Context(), req, cfg, nil)
			findings, err := ParseRun(run)
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if vulnerable {
				want = 1
			}
			mu.Lock()
			hits := sinkHits
			mu.Unlock()
			if len(findings) != want || hits != 0 || run.Status != "completed" {
				t.Fatalf("redirect proof incorrect: %+v findings=%+v hits=%d", run, findings, hits)
			}
		})
	}
}

func TestNextjsBoundaryRefusesScopeAndGuardFailuresBeforeProbe(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	for _, mode := range []string{"unapproved-callback", "excluded-callback", "guarded-callback", "not-test", "wrong-target"} {
		t.Run(mode, func(t *testing.T) {
			hits := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; t.Error("invalid probe reached network") }))
			defer server.Close()
			callback := httptest.NewServer(http.NotFoundHandler())
			defer callback.Close()
			f := NextjsBoundaryFixture{Kind: "proxy", URL: server.URL + "/proxy?url=%2Fsafe", Parameter: "url", CallbackURL: callback.URL + "/hit", EventsURL: callback.URL + "/events"}
			req, cfg := boundaryFixture(t, server.URL, f, callback.URL)
			switch mode {
			case "unapproved-callback":
				req = func() Request {
					original := req
					original.AppScope = nextjsTestRequest(t, server.URL+"/").AppScope
					return original
				}()
			case "excluded-callback":
				scope := assessment.NewAppScope(req.AppScope.Origins(), assessment.Exclusion{Method: "GET", PathPattern: "/hit"})
				req.AppScope = &scope
			case "guarded-callback":
				cfg.ScopeGuard = func(raw string, addresses []string) (bool, string) {
					return strings.HasPrefix(raw, callback.URL), "collector blocked"
				}
			case "not-test":
				req.TestEnvironment = false
			case "wrong-target":
				req.TargetID = "different"
			}
			run := (nextjsBoundariesRunner{}).Run(t.Context(), req, cfg, nil)
			if run.Status != "failed" || hits != 0 {
				t.Fatalf("invalid approval accepted: %+v", run)
			}
		})
	}
}

func TestNextjsBoundaryInputsPreserveExactProxyCorrelation(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	req, _ := boundaryFixture(t, "https://app.test", NextjsBoundaryFixture{Kind: "proxy", URL: "https://app.test/proxy?url=%2Fsafe", Parameter: "url", CallbackURL: "https://collector.test/hit", EventsURL: "https://collector.test/events"}, "https://collector.test/")
	probes, err := prepareBoundaryProbes(&req, nil)
	if err != nil {
		t.Fatal(err)
	}
	again, err := prepareBoundaryProbes(&req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if probes[0].token == "" || probes[0].probeURL != again[0].probeURL || req.InputRequests[0].URL != probes[0].probeURL {
		t.Fatal("runtime probe differs from recorded selection")
	}
	parsed, _ := url.Parse(probes[0].probeURL)
	callback, _ := url.Parse(parsed.Query().Get("url"))
	if callback.Query().Get("scan_token") != probes[0].token {
		t.Fatal("callback correlation was lost")
	}
}

func TestNextjsBoundaryManifestRejectsUncontrolledDestinationsAndAmbiguousInputs(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	req, _ := boundaryFixture(t, "https://app.test", cacheBoundaryManifest("https://app.test"), "")
	for _, mode := range []string{"not-isolated", "overlapping-markers", "different-bypass-path", "same-bypass-query", "unsafe-verify-get", "foreign-cleanup", "bodyless-put", "unsupported-field"} {
		t.Run(mode, func(t *testing.T) {
			f := cacheBoundaryManifest("https://app.test")
			switch mode {
			case "not-isolated":
				f.Isolated = false
			case "overlapping-markers":
				f.DeniedMarker = f.PrivateMarker
			case "different-bypass-path":
				f.BypassURL = "https://app.test/another?bypass=1"
			case "same-bypass-query":
				f.BypassURL = f.URL
			case "unsafe-verify-get":
				f.URL = "https://app.test/logout"
			case "foreign-cleanup":
				f.CleanupURL = "https://other.test/reset"
			case "bodyless-put":
				f.CleanupMethod = "PUT"
			}
			raw, _ := json.Marshal(f)
			if mode == "unsupported-field" {
				raw = append(raw[:len(raw)-1], []byte(`,"headers":{"Host":"other.test"}}`)...)
			}
			if _, err := ValidateNextjsBoundaryManifest(raw, req.Target, *req.AppScope); err == nil {
				t.Fatal("unsafe boundary manifest accepted")
			}
		})
	}
}

func TestNextjsBoundaryPlanningRequiresApprovalAndFingerprintsProbeKind(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	req, _ := boundaryFixture(t, "https://app.test", cacheBoundaryManifest("https://app.test"), "")
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeGrayBox, TestEnvironment: true, WorkflowVersion: "unified-v1", Types: []assessment.Type{assessment.TypeWebApplication}, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: req.Target}}, NextjsBoundaryApprovals: req.NextjsBoundaryApprovals, Access: []assessment.AccessBinding{{Identity: "owner", TargetIDs: []string{"app"}, Kind: assessment.AccessBearerToken, CredentialID: "owner"}}}
	plan := PlanAssessment(PlanInput{Config: cfg})
	if len(plan.Errors) > 0 {
		t.Fatal(plan.Errors)
	}
	found := false
	for _, job := range plan.Jobs {
		if job.Scanner == "nextjs-boundaries" {
			found = true
			if job.Stage != StageWrite || job.AuthContextID != "" {
				t.Fatalf("invalid boundary stage/identity routing: %+v", job)
			}
		}
	}
	if !found {
		t.Fatal("approved boundary job missing")
	}
	cfg.NextjsBoundaryApprovals[0].ID = "new-controlled-probe"
	changed := PlanAssessment(PlanInput{Config: cfg})
	if changed.Fingerprint == plan.Fingerprint {
		t.Fatal("boundary approval not fingerprinted")
	}
	cfg.NextjsBoundaryApprovals = nil
	cfg.Profile = ProfileNextjsDeep
	automatic := PlanAssessment(PlanInput{Config: cfg})
	for _, job := range automatic.Jobs {
		if job.Scanner == "nextjs-boundaries" {
			t.Fatal("deep profile silently authorized boundary probes")
		}
	}
}

func TestAssessmentExecutorRoutesControlledCacheProbeAndInputs(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	lab := &boundaryCacheLab{mode: "vulnerable"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { lab.handler(t, w, r) }))
	defer server.Close()
	req, cfg := boundaryFixture(t, server.URL, cacheBoundaryManifest(server.URL), "")
	cfg.KatanaPath, cfg.WebBrowser = "/nonexistent/katana", false
	cfg.AssessmentAuthContexts, cfg.APIFixtureDir = req.AuthContexts, req.APIFixtureDir
	target := assessment.Target{ID: "app", Kind: assessment.KindURL, Value: req.Target}
	plan := AssessmentPlan{Fingerprint: "controlled-cache", Config: assessment.AssessmentConfig{WorkflowVersion: "unified-v1", TestEnvironment: true, Targets: []assessment.Target{target}, Types: []assessment.Type{assessment.TypeWebApplication}, NextjsBoundaryApprovals: req.NextjsBoundaryApprovals}, Jobs: []PlanJob{{ID: "boundaries", Scanner: "nextjs-boundaries", TargetID: "app", Target: req.Target, Variant: "nextjs-boundaries", State: PlanSelected, Stage: StageWrite}}}
	pipeline := Pipeline{Config: cfg}
	for _, run := range pipeline.RunAssessmentJobs(t.Context(), plan, t.TempDir(), nil, nil) {
		if run.Scanner != "nextjs-boundaries" {
			continue
		}
		if run.Status != "completed" || len(run.AuthorizationResults) != 1 || run.AuthorizationResults[0].CacheAttribution != "confirmed" {
			t.Fatalf("executor lost boundary data: %+v", run)
		}
		raw, err := os.ReadFile(run.InputManifestPath)
		var inputs ScannerInputManifest
		if err != nil || json.Unmarshal(raw, &inputs) != nil || len(inputs.Requests) != 2 {
			t.Fatalf("boundary inputs missing: %s %v", raw, err)
		}
		return
	}
	t.Fatal("boundary runner missing")
}

func TestNextjsBoundaryExtendedScopeNeverAuthorizesTargetCredentialsForCollector(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("target credential request reached callback service")
	}))
	defer collector.Close()
	req, cfg := boundaryFixture(t, "https://app.test", NextjsBoundaryFixture{Kind: "proxy", URL: "https://app.test/proxy?url=%2Fsafe", Parameter: "url", CallbackURL: collector.URL + "/hit", EventsURL: collector.URL + "/events"}, collector.URL)
	file, err := os.CreateTemp(t.TempDir(), "events")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	auth, err := nextjsActionAuth(req, "owner")
	if err != nil {
		t.Fatal(err)
	}
	client := boundaryClient{ctx: t.Context(), req: req, cfg: cfg, events: file}
	_, err = client.send(ScannerRequestInput{EndpointID: "control"}, collector.URL+"/events", "GET", "verification", nil, "", auth, nil)
	if err == nil || !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("extended scope incorrectly authorized credentials: %v", err)
	}
}

func TestNextjsCacheBoundaryDetectsCrossRepresentationPrivateLeak(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	lab := &boundaryCacheLab{mode: "vulnerable"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { lab.handler(t, w, r) }))
	defer server.Close()
	manifest := cacheBoundaryManifest(server.URL)
	manifest.ConsumerRepresentation = "rsc"
	req, cfg := boundaryFixture(t, server.URL, manifest, "")
	run := (nextjsBoundariesRunner{}).Run(t.Context(), req, cfg, nil)
	findings, err := ParseRun(run)
	if err != nil || len(findings) != 1 || run.AuthorizationResults[0].CacheAttribution != "confirmed" {
		t.Fatalf("cross-representation disclosure missed: %+v findings=%+v err=%v", run, findings, err)
	}
}
