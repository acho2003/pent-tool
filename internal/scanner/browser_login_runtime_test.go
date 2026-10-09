package scanner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

// CaptureBrowserLogin must drive a real login and come back with the session
// cookie the server set — the capability the hand-replayed HTTP form POST
// cannot provide for JS/redirect logins. Opt-in: needs Chromium.
//
// The fixture mimics the shape that defeats the HTTP replayer: the submit
// button is wired by a script (so the field values must be entered as real
// input events), and the protected marker is only present once the session
// cookie is set.
func TestCaptureBrowserLoginRecoversTheSessionCookie(t *testing.T) {
	chrome := os.Getenv("XALGORIX_TEST_CHROMIUM")
	if chrome == "" {
		t.Skip("requires Chromium")
	}
	const marker = "Workspace shortcuts"
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err == nil && r.PostForm.Get("email") == "operator@example.test" && r.PostForm.Get("password") == "s3cret-pass" {
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "valid-token", Path: "/"})
				http.Redirect(w, r, "/dashboard", http.StatusFound)
				return
			}
			http.Error(w, "bad credentials", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		// The button submits via a script handler, not a native submit, so the
		// values must be present as real input (not injected .value) to post.
		_, _ = w.Write([]byte(`<html><body><form id="f" method="post" action="/login">
<input name="email" type="email">
<input name="password" type="password">
<button type="button" id="go" onclick="document.getElementById('f').submit()">Sign in</button>
</form></body></html>`))
	})
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil || cookie.Value != "valid-token" {
			http.Error(w, "please sign in", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body><h1>" + marker + "</h1></body></html>"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	origin, _ := assessment.ParseApprovedOrigin("app", server.URL)
	origin.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})

	result, err := CaptureBrowserLogin(t.Context(), Config{KatanaChromePath: chrome}, t.TempDir(), BrowserLoginParams{
		AppScope:      &scope,
		LoginURL:      server.URL + "/login",
		VerifyURL:     server.URL + "/dashboard",
		Marker:        marker,
		Username:      "operator@example.test",
		Password:      "s3cret-pass",
		UsernameField: "email",
		PasswordField: "password",
	})
	if err != nil {
		t.Fatalf("browser login capture failed: %v", err)
	}
	if !strings.Contains(result.CookieHeader, "session=valid-token") {
		t.Fatalf("captured cookie header did not contain the session cookie: %q", result.CookieHeader)
	}
	t.Logf("captured %d-byte session cookie header via real browser login", len(result.CookieHeader))

	// Wrong password must not yield a session — the capture reports failure
	// rather than returning an empty or anonymous "session".
	_, err = CaptureBrowserLogin(t.Context(), Config{KatanaChromePath: chrome}, t.TempDir(), BrowserLoginParams{
		AppScope:      &scope,
		LoginURL:      server.URL + "/login",
		VerifyURL:     server.URL + "/dashboard",
		Marker:        marker,
		Username:      "operator@example.test",
		Password:      "wrong-pass",
		UsernameField: "email",
		PasswordField: "password",
	})
	if err == nil {
		t.Fatal("a wrong password was accepted as a successful login")
	}
}

// The credential boundary: if the login page tries to send the password to a
// different origin, that request is blocked and no session is produced.
func TestCaptureBrowserLoginBlocksCrossOriginCredentialSubmission(t *testing.T) {
	chrome := os.Getenv("XALGORIX_TEST_CHROMIUM")
	if chrome == "" {
		t.Skip("requires Chromium")
	}
	// A separate origin that would gladly accept the credentials; the capture
	// must never let the browser reach it.
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "leaked", Path: "/"})
		w.WriteHeader(http.StatusOK)
	}))
	defer foreign.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><form id="f" method="post" action="` + foreign.URL + `/login">
<input name="email" type="email"><input name="password" type="password">
<button type="button" onclick="document.getElementById('f').submit()">Sign in</button>
</form></body></html>`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	origin, _ := assessment.ParseApprovedOrigin("app", server.URL)
	origin.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})

	_, err := CaptureBrowserLogin(t.Context(), Config{KatanaChromePath: chrome}, t.TempDir(), BrowserLoginParams{
		AppScope:      &scope,
		LoginURL:      server.URL + "/login",
		Username:      "operator@example.test",
		Password:      "s3cret-pass",
		UsernameField: "email",
		PasswordField: "password",
	})
	if err == nil {
		t.Fatal("cross-origin credential submission was not blocked")
	}
}

// Reproduces the Auth.js/NextAuth failure: the sign-in is a fetch() POST that
// returns 200 and sets the session cookie on that response (no redirect). When
// the intercepted response's Set-Cookie is not persisted by the browser, the
// intercepting client's own cookie jar must still carry the session into the
// later dashboard navigation so the protected marker renders. Opt-in: Chromium.
func TestCaptureBrowserLoginHandlesFetchSetCookieSessions(t *testing.T) {
	chrome := os.Getenv("XALGORIX_TEST_CHROMIUM")
	if chrome == "" {
		t.Skip("requires Chromium")
	}
	const marker = "Welcome back"
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Inputs are not in a form; sign-in is a fetch() that sets the cookie via
		// a 200 response, then client-side-navigates — the Auth.js shape.
		_, _ = w.Write([]byte(`<html><body>
<input id="email" name="email" type="email">
<input id="password" name="password" type="password">
<button type="button" onclick="fetch('/api/auth/callback/credentials',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:document.getElementById('email').value,password:document.getElementById('password').value})}).then(r=>{if(r.ok)location.href='/dashboard/overview'})">Sign in</button>
</body></html>`))
	})
	mux.HandleFunc("/api/auth/callback/credentials", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Email, Password string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Email != "u@example.test" || body.Password != "p@ss" {
			http.Error(w, "bad", http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "__Secure-authjs.session-token", Value: "sess-123", Path: "/", HttpOnly: true})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/dashboard/overview", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("__Secure-authjs.session-token"); err != nil || c.Value != "sess-123" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body><h1>" + marker + ", operator</h1></body></html>"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	origin, _ := assessment.ParseApprovedOrigin("app", server.URL)
	origin.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})

	result, err := CaptureBrowserLogin(t.Context(), Config{KatanaChromePath: chrome}, t.TempDir(), BrowserLoginParams{
		AppScope:      &scope,
		LoginURL:      server.URL + "/login",
		VerifyURL:     server.URL + "/dashboard/overview",
		Marker:        marker,
		Username:      "u@example.test",
		Password:      "p@ss",
		UsernameField: "email",
		PasswordField: "password",
	})
	if err != nil {
		t.Fatalf("fetch-set-cookie login capture failed: %v", err)
	}
	if !strings.Contains(result.CookieHeader, "__Secure-authjs.session-token=sess-123") {
		t.Fatalf("session cookie not captured from the fetch login: %q", result.CookieHeader)
	}
}
