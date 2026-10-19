package web

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/credentials"
)

// A long dashboard body so the markerless landing check clears its minimum
// content threshold, as a real authenticated page would.
const markerlessDashboard = "<h1>Operations console</h1><p>" +
	"Welcome back. Review outstanding approvals, recent sign-ins, and the service health summary. " +
	"Everything below loads only for an authenticated operator session and never for an anonymous visitor. " +
	"Use the navigation to open reports, manage members, and export the monthly activity record.</p>"

// markerlessLoginFixture serves a NextAuth-shaped app: /login is a form, a valid
// post sets the session cookie and redirects to /home, and /home is gated. When
// gate is true, an anonymous visitor to /home is bounced to /login (the real
// pattern); when false, /home renders the same page to everyone (the same-shell
// case the strict negative control must reject).
func markerlessLoginFixture(gate bool) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err == nil && r.PostForm.Get("email") == "u@example.test" && r.PostForm.Get("password") == "p@ss" {
				http.SetCookie(w, &http.Cookie{Name: "sid", Value: "ok", Path: "/"})
				http.Redirect(w, r, "/home", http.StatusFound)
				return
			}
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<form id="f" method="post" action="/login"><input name="email" type="email"><input name="password" type="password"><button type="button" onclick="document.getElementById('f').submit()">in</button></form>`))
	})
	mux.HandleFunc("/home", func(w http.ResponseWriter, r *http.Request) {
		if gate {
			if c, err := r.Cookie("sid"); err != nil || c.Value != "ok" {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, "<html><body>%s</body></html>", markerlessDashboard)
	})
	return httptest.NewServer(mux)
}

func markerlessTestServer(t *testing.T, chrome string) *Server {
	t.Helper()
	s := newTestServer(t, nil)
	s.cfg.AllowLocalTargets = true
	s.cfg.BrowserPath = chrome
	keyPath := filepath.Join(t.TempDir(), "credential-key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x55}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XALGORIX_CREDENTIAL_KEY_FILE", keyPath)
	return s
}

func markerlessFormCredential(t *testing.T, s *Server, loginURL string) string {
	t.Helper()
	vault, err := s.credentialVault()
	if err != nil {
		t.Fatal(err)
	}
	meta, err := vault.Create(credentials.Record{Name: "form", Kind: assessment.AccessFormLogin, TargetIDs: []string{"target-1"}, Values: map[string]string{
		"login_url": loginURL, "username": "u@example.test", "password": "p@ss",
		"username_field": "email", "password_field": "password", "submit_format": "browser",
	}})
	if err != nil {
		t.Fatal(err)
	}
	return meta.ID
}

// A gated app (anonymous bounced to the login page) verifies with no marker: the
// authenticated session stays on the protected page while the anonymous control
// is redirected away. This is the scenario a NextAuth login produces.
func TestMarkerlessBrowserLoginVerifiesByRedirect(t *testing.T) {
	chrome := os.Getenv("XALGORIX_TEST_CHROMIUM")
	if chrome == "" {
		t.Skip("requires Chromium")
	}
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	app := markerlessLoginFixture(true)
	defer app.Close()
	s := markerlessTestServer(t, chrome)
	id := markerlessFormCredential(t, s, app.URL+"/login")

	// No verify_marker: markerless verification.
	body := fmt.Sprintf(`{"target_id":"target-1","target_url":%q,"verify_url":%q,"verify_marker":""}`, app.URL, app.URL+"/home")
	rr := httptest.NewRecorder()
	s.handleCredentialDetail(rr, httptest.NewRequest(http.MethodPost, "/api/credentials/"+id+"/test", strings.NewReader(body)))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"verified":true`) {
		t.Fatalf("markerless browser login did not verify: status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "p@ss") || strings.Contains(rr.Body.String(), "sid=ok") {
		t.Fatalf("response leaked credential/session values: %s", rr.Body.String())
	}
}

// An ungated app (the same page for everyone) must NOT verify markerless: the
// anonymous negative control reaches the same page, so the session is not
// proven. Strict mode refuses rather than claim a false authentication.
func TestMarkerlessBrowserLoginRejectsSameShellForEveryone(t *testing.T) {
	chrome := os.Getenv("XALGORIX_TEST_CHROMIUM")
	if chrome == "" {
		t.Skip("requires Chromium")
	}
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	app := markerlessLoginFixture(false)
	defer app.Close()
	s := markerlessTestServer(t, chrome)
	id := markerlessFormCredential(t, s, app.URL+"/login")

	body := fmt.Sprintf(`{"target_id":"target-1","target_url":%q,"verify_url":%q,"verify_marker":""}`, app.URL, app.URL+"/home")
	rr := httptest.NewRecorder()
	s.handleCredentialDetail(rr, httptest.NewRequest(http.MethodPost, "/api/credentials/"+id+"/test", strings.NewReader(body)))
	if strings.Contains(rr.Body.String(), `"verified":true`) {
		t.Fatalf("markerless verification passed for an ungated app: %s", rr.Body.String())
	}
}
