package scanner

import (
	"bytes"
	"context"
	"fmt"
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/credentials"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBrowserRuntimeAuthenticatedXHRAndExclusions(t *testing.T) {
	chrome := os.Getenv("XALGORIX_TEST_CHROMIUM")
	if chrome == "" {
		t.Skip("native Chromium fixture opt-in")
	}
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "session=fixture" {
			http.Error(w, "auth missing", 401)
			return
		}
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><body><a href="/next/">next</a><a href="/logout">logout</a><script>fetch('/xhr?x=1&x=2').then(r=>r.text());fetch('/write',{method:'POST',body:'x=1'});fetch('/graphql',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query:'query Read($secret: String){viewer}',variables:{secret:'fixture-browser-secret'}})});fetch('/graphql',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query:'mutation {deleteUser}'})});</script><form method="post" action="/write"><input name="x"></form><form method="get" action="/form-read?token=fixture-form-secret"><input name="token"></form></body></html>`))
			return
		}
		if r.URL.Path == "/graphql" {
			body, _ := io.ReadAll(r.Body)
			if r.Method != "POST" || strings.Contains(string(body), "mutation") {
				t.Errorf("forbidden GraphQL request %s %s", r.Method, body)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"data":{"viewer":"fixture"}}`))
			return
		}
		if r.URL.Path == "/write" || r.URL.Path == "/logout" {
			t.Errorf("forbidden browser request %s %s", r.Method, r.URL.Path)
		}
		w.Write([]byte("ok"))
	}))
	defer fixture.Close()
	origin, _ := assessment.ParseApprovedOrigin("app", fixture.URL)
	origin.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin}, assessment.Exclusion{Method: "*", PathPattern: "/logout"})
	store, err := credentials.NewReplayStore(filepath.Join(t.TempDir(), "replay"), bytes.Repeat([]byte{6}, credentials.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	req := Request{ReplayStore: store, ReplayScope: "app:fixture", Target: fixture.URL + "/", ScanDir: t.TempDir(), AppScope: &scope, TargetAuth: "Cookie: session=fixture", AuthRefresh: func(_ context.Context, h []string) ([]string, error) { return h, nil }}
	run := DiscoverBrowser(t.Context(), req, Config{KatanaChromePath: chrome, KatanaTimeout: 20 * time.Second, WebMaxEndpoints: 20})
	if run.Status != "completed" {
		t.Fatalf("browser: %+v", run)
	}
	data, err := os.ReadFile(run.ArtifactPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/xhr?x=1&x=2", "/next/", `"forms"`, `"body_digest"`, `/graphql`, `"location":"body"`} {
		if !strings.Contains(strings.ReplaceAll(string(data), `\u0026`, "&"), want) {
			t.Fatalf("missing %s: %s", want, data)
		}
	}
	surface, parseErr := ParseKatanaAttackSurfaceScoped(run.ArtifactPath, "app:fixture", fixture.URL, true, &scope)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	hydrateRequestReplay(surface, store, "app:fixture")
	found := false
	for _, ep := range surface.Endpoints {
		if ep.HasForm && ep.ReplayRef == "" && endpointStateDispatchable(ep.State) {
			t.Fatal("browser form was authorized for submission")
		}
		if ep.Method == "POST" && strings.Contains(ep.URL, "/graphql") {
			found = ep.ReadOnly && ep.ReplayRef != "" && strings.Contains(ep.ReplayBody, "fixture-browser-secret") && ep.ReplayHeaders["Cookie"] == "session=fixture"
		}
	}
	if !found {
		t.Fatalf("encrypted browser body/header replay missing: %+v", surface.Endpoints)
	}
	if strings.Contains(string(data), "session=fixture") || strings.Contains(string(data), "fixture-browser-secret") || strings.Contains(string(data), "fixture-form-secret") {
		t.Fatal("secret persisted")
	}
}

func TestBrowserRuntimeRequestBudgetIsExplicit(t *testing.T) {
	chrome := os.Getenv("XALGORIX_TEST_CHROMIUM")
	if chrome == "" {
		t.Skip("native Chromium fixture opt-in")
	}
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><script>fetch('/one');fetch('/two');</script></html>`))
	}))
	defer fixture.Close()
	origin, _ := assessment.ParseApprovedOrigin("app", fixture.URL)
	origin.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	run := DiscoverBrowser(t.Context(), Request{Target: fixture.URL + "/", ScanDir: t.TempDir(), AppScope: &scope}, Config{KatanaChromePath: chrome, KatanaTimeout: 20 * time.Second, WebMaxEndpoints: 1})
	if run.Completeness != "partial" || !strings.Contains(run.Reason, "HTTP request limit reached (1)") {
		t.Fatalf("request cap hidden: %+v", run)
	}
}

func TestBrowserRuntimeStorageAndProtectedCheckpoint(t *testing.T) {
	chrome := os.Getenv("XALGORIX_TEST_CHROMIUM")
	if chrome == "" {
		t.Skip("native Chromium fixture opt-in")
	}
	var aliasRequests atomic.Int32
	alias := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { aliasRequests.Add(1); w.Write([]byte("alias")) }))
	defer alias.Close()
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(fmt.Sprintf(`<html><body>Public<script>if(localStorage.getItem('token')==='browser-storage-secret'&&sessionStorage.getItem('role')==='reviewer')document.body.append(' Protected checkpoint');fetch('%s/alias?token='+localStorage.getItem('token'));</script><a href='/not-visited'>next</a></body></html>`, alias.URL)))
		if r.URL.Path == "/not-visited" {
			t.Error("access test crawled links")
		}
	}))
	defer fixture.Close()
	origin, _ := assessment.ParseApprovedOrigin("app", fixture.URL)
	origin.PathPrefix = "/"
	aliasOrigin, _ := assessment.ParseApprovedOrigin("app", alias.URL)
	aliasOrigin.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin, aliasOrigin})
	request := Request{Target: fixture.URL + "/", ScanDir: t.TempDir(), AppScope: &scope, BrowserStorage: &credentials.BrowserStorage{Local: map[string]string{"token": "browser-storage-secret"}, Session: map[string]string{"role": "reviewer"}}, BrowserAccessTest: true, BrowserCheckpointMarker: "Protected checkpoint"}
	cfg := Config{KatanaChromePath: chrome, KatanaTimeout: 20 * time.Second, WebMaxEndpoints: 20}
	positive := DiscoverBrowser(t.Context(), request, cfg)
	if positive.Status != "completed" || positive.AuthState != "verified" {
		t.Fatalf("browser storage/checkpoint failed: %+v", positive)
	}
	if aliasRequests.Load() != 0 {
		t.Fatal("storage-bound browser sent credential-derived request to alias")
	}
	data, _ := os.ReadFile(positive.ArtifactPath)
	if strings.Contains(string(data), "browser-storage-secret") {
		t.Fatal("browser storage persisted in artifact")
	}
	request.BrowserStorage = nil
	request.ScanDir = t.TempDir()
	negative := DiscoverBrowser(t.Context(), request, cfg)
	if negative.AuthState == "verified" || negative.Reason != "browser protected-route marker was not confirmed" {
		t.Fatalf("storage leaked across browser contexts: %+v", negative)
	}
}

func TestBrowserRuntimeNamedIdentitiesKeepIndependentReplay(t *testing.T) {
	chrome := os.Getenv("XALGORIX_TEST_CHROMIUM")
	if chrome == "" {
		t.Skip("native Chromium fixture opt-in")
	}
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer owner-fixture-secret" && r.Header.Get("Authorization") != "Bearer reader-fixture-secret" {
			t.Error("wrong identity credential")
			http.Error(w, "denied", 401)
			return
		}
		if r.URL.Path == "/api/read" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"value":"controlled"}`))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><script>fetch('/api/read').then(r=>r.json()).then(v=>document.body.append(v.value))</script></body></html>`))
	}))
	defer lab.Close()
	origin, _ := assessment.ParseApprovedOrigin("app", lab.URL)
	origin.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	store, err := credentials.NewReplayStore(filepath.Join(t.TempDir(), "private"), bytes.Repeat([]byte{7}, credentials.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{KatanaChromePath: chrome, KatanaTimeout: 20 * time.Second, WebMaxEndpoints: 50, Budget: NewAssessmentBudget(1000, 100, time.Minute)}
	for _, identity := range []string{"owner", "reader"} {
		cfg.AssessmentAuthContexts = append(cfg.AssessmentAuthContexts, AuthContext{ID: AuthenticationContextID("app", identity), TargetID: "app", Identity: identity, Role: identity, State: assessment.StateVerified, Headers: []string{"Authorization: Bearer " + identity + "-fixture-secret"}, Refresh: func(_ context.Context, headers []string) ([]string, error) { return headers, nil }})
	}
	request := Request{Target: lab.URL + "/", ScanDir: t.TempDir(), Scope: "discovery:app", AppScope: &scope, ReplayStore: store, ReplayScope: "app:app"}
	surface := NewSeedAttackSurface("app:app", request.Target)
	runs := discoverAdditionalIdentities(t.Context(), "app", request, cfg, surface)
	if len(runs) != 2 {
		t.Fatalf("identity runs: %+v", runs)
	}
	for _, run := range runs {
		if run.Status != "completed" || !run.Authenticated || run.AuthContextID != AuthenticationContextID("app", run.AuthIdentity) {
			t.Fatalf("identity discovery failed: %+v", run)
		}
		raw, _ := os.ReadFile(run.ArtifactPath)
		if strings.Contains(string(raw), "fixture-secret") {
			t.Fatal("credential leaked in identity discovery artifact")
		}
	}
	proof := BuildCoverageProof([]AttackSurface{*surface}, runs)
	if len(proof.IdentityDiscovery) != 2 {
		t.Fatalf("missing role discovery evidence: %+v", proof.IdentityDiscovery)
	}
	for _, identity := range proof.IdentityDiscovery {
		if identity.ObservedRequests < 2 || identity.AttemptID == "" || identity.AuthState != assessment.StateVerified {
			t.Fatalf("incomplete discovery context record: %+v", identity)
		}
	}
	variants := map[string]AttackSurfaceEndpoint{}
	for _, endpoint := range surface.Endpoints {
		if endpoint.URL == lab.URL+"/api/read" && endpoint.ObservedWithAuth {
			variants[endpoint.AuthContextID] = endpoint
		}
	}
	if len(variants) != 2 {
		t.Fatalf("role requests collapsed: %+v", variants)
	}
	for _, auth := range cfg.AssessmentAuthContexts {
		endpoint := variants[auth.ID]
		replay, err := store.Get(request.ReplayScope, auth.ID, endpoint.ReplayRef)
		if err != nil || replay.Headers["Authorization"] != auth.Headers[0][len("Authorization: "):] {
			t.Fatalf("identity replay: %+v %v", replay, err)
		}
		for _, other := range cfg.AssessmentAuthContexts {
			if other.ID != auth.ID {
				if _, err := store.Get(request.ReplayScope, other.ID, endpoint.ReplayRef); err == nil {
					t.Fatal("another role accessed replay record")
				}
			}
		}
	}
}

func TestBrowserRuntimeAttemptStopPublishesCancellation(t *testing.T) {
	chrome := os.Getenv("XALGORIX_TEST_CHROMIUM")
	if chrome == "" {
		t.Skip("native Chromium fixture opt-in")
	}
	stops := make(chan context.CancelFunc, 1)
	var stopOnce sync.Once
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stopOnce.Do(func() { stop := <-stops; stop() })
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>controlled</body></html>`))
	}))
	defer lab.Close()
	origin, _ := assessment.ParseApprovedOrigin("app", lab.URL)
	origin.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	var unregistered atomic.Bool
	var events []Event
	req := Request{Target: lab.URL + "/", ScanDir: t.TempDir(), Scope: "discovery:app", AppScope: &scope, PlanFingerprint: "accepted", BrowserEmit: func(event Event) { events = append(events, event) }, BrowserAttemptControl: func(id string, cancel context.CancelFunc) func() {
		if id == "" {
			t.Fatal("unidentified browser attempt")
		}
		stops <- cancel
		return func() { unregistered.Store(true) }
	}}
	run := DiscoverBrowser(t.Context(), req, Config{KatanaChromePath: chrome, KatanaTimeout: 20 * time.Second, WebMaxEndpoints: 20})
	if run.Status != "cancelled" || run.ExecutionOutcome != "CANCELLED" || run.Completeness != "partial" || !unregistered.Load() {
		t.Fatalf("browser stop did not finalize: %+v cleanup=%v", run, unregistered.Load())
	}
	if len(events) < 2 || events[0].Type != "scanner_started" || events[len(events)-1].Type != "scanner_failed" || events[len(events)-1].Run.AttemptID != events[0].Run.AttemptID || events[len(events)-1].Run.Status != "cancelled" {
		t.Fatalf("wrong lifecycle events: %+v", events)
	}
}
