package scanner

import (
	"context"
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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
			w.Write([]byte(`<html><body><a href="/next/">next</a><a href="/logout">logout</a><script>fetch('/xhr?x=1&x=2').then(r=>r.text());fetch('/write',{method:'POST',body:'x=1'});fetch('/graphql',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query:'query Read($secret: String){viewer}',variables:{secret:'fixture-browser-secret'}})});fetch('/graphql',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query:'mutation {deleteUser}'})});</script><form method="post" action="/write"><input name="x"></form></body></html>`))
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
	req := Request{Target: fixture.URL + "/", ScanDir: t.TempDir(), AppScope: &scope, TargetAuth: "Cookie: session=fixture", AuthRefresh: func(_ context.Context, h []string) ([]string, error) { return h, nil }}
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
	if strings.Contains(string(data), "session=fixture") || strings.Contains(string(data), "fixture-browser-secret") {
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
