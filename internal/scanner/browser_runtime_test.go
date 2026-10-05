package scanner

import (
	"context"
	"github.com/xalgord/xalgorix/v4/internal/assessment"
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
			w.Write([]byte(`<html><body><a href="/next/">next</a><a href="/logout">logout</a><script>fetch('/xhr?x=1&x=2').then(r=>r.text());fetch('/write',{method:'POST',body:'x=1'});</script><form method="post" action="/write"><input name="x"></form></body></html>`))
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
	for _, want := range []string{"/xhr?x=1&x=2", "/next/", `"forms"`} {
		if !strings.Contains(strings.ReplaceAll(string(data), `\u0026`, "&"), want) {
			t.Fatalf("missing %s: %s", want, data)
		}
	}
	if strings.Contains(string(data), "session=fixture") {
		t.Fatal("secret persisted")
	}
}
