package scanner

import (
	"fmt"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestTrustedBrowserLocalOriginIsExplicitAndExact(t *testing.T) {
	for _, tc := range []struct{ configured, target, want string }{
		{"http://host.docker.internal:3003", "http://host.docker.internal:3003/sign-in", "http://host.docker.internal:3003"},
		{"http://localhost:3003/", "http://localhost:3003/path", "http://localhost:3003"},
		{"http://127.0.0.1:3003", "http://127.0.0.1:3003/", "http://127.0.0.1:3003"},
		{"", "http://host.docker.internal:3003/", ""},
		{"http://host.docker.internal:3003", "http://host.docker.internal:3004/", ""},
		{"http://host.docker.internal:3003", "https://host.docker.internal:3003/", ""},
		{"http://example.test:3003", "http://example.test:3003/", ""},
		{"http://192.168.1.1:3003", "http://192.168.1.1:3003/", ""},
		{"http://user:secret@localhost:3003", "http://localhost:3003/", ""},
		{"http://localhost:3003/path", "http://localhost:3003/", ""},
	} {
		t.Run(tc.configured+tc.target, func(t *testing.T) {
			if got := trustedBrowserLocalOrigin([]string{tc.configured}, tc.target); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
	origin, _ := assessment.ParseApprovedOrigin("app", "http://localhost:3003")
	origin.PathPrefix = "/workspace"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	if browserHMRAllowed(&scope, "http://localhost:3003") {
		t.Fatal("HMR escaped the path boundary")
	}
	origin.PathPrefix = "/"
	scope = assessment.NewAppScope([]assessment.ApprovedOrigin{origin}, assessment.Exclusion{Method: "GET", PathPattern: "/_next/hmr"})
	if browserHMRAllowed(&scope, "http://localhost:3003") {
		t.Fatal("HMR ignored exclusion")
	}
}

func TestCaptureBrowserLoginBlocksPasswordGETAndSubmitsOnce(t *testing.T) {
	chrome := os.Getenv("XALGORIX_TEST_CHROMIUM")
	if chrome == "" {
		t.Skip("native Chromium fixture opt-in")
	}
	for _, mode := range []string{"uninitialized", "post"} {
		t.Run(mode, func(t *testing.T) {
			var leakedGET, posts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("password") != "" {
					leakedGET.Add(1)
				}
				if r.Method == "POST" {
					posts.Add(1)
					http.SetCookie(w, &http.Cookie{Name: "session", Value: "synthetic-session", Path: "/"})
					http.Redirect(w, r, "/protected", 302)
					return
				}
				if r.URL.Path == "/protected" {
					fmt.Fprint(w, "<html><p>PROTECTED_SYNTHETIC_MARKER</p></html>")
					return
				}
				method := "get"
				if mode == "post" {
					method = "post"
				}
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprintf(w, `<html><form method="%s"><input name="username"><input type="password" name="password"><button type="submit">Sign in</button></form></html>`, method)
			}))
			defer server.Close()
			origin, _ := assessment.ParseApprovedOrigin("app", server.URL)
			origin.PathPrefix = "/"
			scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
			_, err := CaptureBrowserLogin(t.Context(), Config{KatanaChromePath: chrome}, t.TempDir(), BrowserLoginParams{AppScope: &scope, LoginURL: server.URL + "/login", VerifyURL: server.URL + "/protected", Marker: "PROTECTED_SYNTHETIC_MARKER", Username: "synthetic-user", Password: "synthetic-password"})
			if leakedGET.Load() != 0 {
				t.Fatal("password reached the server in a URL")
			}
			if mode == "uninitialized" {
				if err == nil || !strings.Contains(err.Error(), "kept out of the URL") || posts.Load() != 0 {
					t.Fatalf("uninitialized form not explained or refused: %v posts=%d", err, posts.Load())
				}
			} else if err != nil || posts.Load() != 1 {
				t.Fatalf("login did not submit exactly once: %v posts=%d", err, posts.Load())
			}
		})
	}
}

func TestCaptureBrowserLoginNeverSharesJarWithOtherOrigins(t *testing.T) {
	chrome := os.Getenv("XALGORIX_TEST_CHROMIUM")
	if chrome == "" {
		t.Skip("native Chromium fixture opt-in")
	}
	var foreignRequests, foreignCookies atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignRequests.Add(1)
		if r.Header.Get("Cookie") != "" {
			foreignCookies.Add(1)
		}
		fmt.Fprint(w, "public")
	}))
	defer foreign.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.Method == "POST" {
			http.SetCookie(w, &http.Cookie{Name: "private_session", Value: "synthetic-cookie", Path: "/"})
			fmt.Fprintf(w, `<html><h1>COOKIE_CAPTURE_MARKER</h1><img src="%s/observe"></html>`, foreign.URL)
			return
		}
		fmt.Fprint(w, `<html><form method="post"><input name="username"><input type="password" name="password"><button type="submit">Sign in</button></form></html>`)
	}))
	defer server.Close()
	origin, _ := assessment.ParseApprovedOrigin("app", server.URL)
	origin.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	_, err := CaptureBrowserLogin(t.Context(), Config{KatanaChromePath: chrome}, t.TempDir(), BrowserLoginParams{AppScope: &scope, LoginURL: server.URL + "/login", VerifyURL: server.URL + "/login", Marker: "COOKIE_CAPTURE_MARKER", Username: "synthetic", Password: "synthetic-password"})
	if err != nil {
		t.Fatal(err)
	}
	if foreignRequests.Load() == 0 || foreignCookies.Load() != 0 {
		t.Fatalf("cross-origin cookie boundary failed: requests=%d cookie requests=%d", foreignRequests.Load(), foreignCookies.Load())
	}
}

func TestBrowserDocumentSocketBoundary(t *testing.T) {
	chrome := os.Getenv("XALGORIX_TEST_CHROMIUM")
	if chrome == "" {
		t.Skip("native Chromium fixture opt-in")
	}
	launch := launcher.New().Context(t.Context()).Bin(chrome).UserDataDir(t.TempDir()).Headless(true).NoSandbox(true).Leakless(false)
	control, err := launch.Launch()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { launch.Kill(); launch.Cleanup() }()
	browser := rod.New().Context(t.Context()).ControlURL(control)
	if err := browser.Connect(); err != nil {
		t.Fatal(err)
	}
	defer browser.Close()
	page, err := browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := page.Eval(`script => {
  globalThis.WebSocket = class {constructor(url){this.url=url;}};
  globalThis.WebTransport = class {};
  eval(script);
  const cases = [
   ['ws://localhost:3003/_next/hmr',true],
   ['ws://localhost:3003/_next/webpack-hmr',true],
   ['ws://localhost:3003/private',false],
   ['ws://localhost:3004/_next/hmr',false],
   ['wss://localhost:3003/_next/hmr',false],
   ['ws://foreign.invalid/_next/hmr',false],
   ['ws://name:secret@localhost:3003/_next/hmr',false]
  ];
  const correct = cases.every(([url,want]) => {try {new WebSocket(url);return want;} catch {return !want;}});
  let transportBlocked=false;try {new WebTransport('https://localhost:3003')}catch{transportBlocked=true;}
  return correct && transportBlocked && globalThis.__xalgorixBlockedSocket === true;
 }`, browserSocketBoundaryScript("http://localhost:3003", true))
	if err != nil || !result.Value.Bool() {
		t.Fatalf("document socket boundary failed: %v", err)
	}
}
