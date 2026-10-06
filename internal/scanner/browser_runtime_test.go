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
