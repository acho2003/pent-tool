package scanner

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

// A body long enough to clear the markerless content threshold.
const markerlessDashboardRunes = "<h1>Operations console</h1><p>Welcome back. Review approvals, recent sign-ins and service health. This content loads only for an authenticated operator and never for an anonymous visitor. Open reports, manage members and export the monthly activity record.</p>"

func markerlessScope(t *testing.T) *assessment.AppScope {
	t.Helper()
	origin, err := assessment.ParseApprovedOrigin("app", "https://app.example.test/")
	if err != nil {
		t.Fatalf("origin: %v", err)
	}
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	return &scope
}

func TestBrowserAuthLandingMarkerless(t *testing.T) {
	scope := markerlessScope(t)
	cases := []struct {
		name       string
		finalURL   string
		hasPwInput bool
		runes      int
		want       bool
	}{
		{"authenticated dashboard", "https://app.example.test/dashboard/overview", false, 1184, true},
		{"bounced to signin route", "https://app.example.test/api/auth/signin?callbackUrl=%2Fdashboard", false, 1184, false},
		{"login form on protected url", "https://app.example.test/dashboard/overview", true, 1184, false},
		{"empty shell", "https://app.example.test/dashboard/overview", false, 42, false},
		{"redirected off scope", "https://sso.other.test/login", false, 1184, false},
		{"login path even with content", "https://app.example.test/login", false, 1184, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := browserAuthLanding(scope, tc.finalURL, tc.hasPwInput, tc.runes)
			if got != tc.want {
				t.Fatalf("browserAuthLanding(%q, pw=%v, runes=%d) = %v, want %v", tc.finalURL, tc.hasPwInput, tc.runes, got, tc.want)
			}
		})
	}
}

// Markerless CaptureBrowserLogin must still reject a failed login: a wrong
// password leaves the browser on the sign-in form, which the landing check sees
// as a password field on an auth route and refuses, so no anonymous "session"
// is ever returned.
func TestCaptureBrowserLoginMarkerlessRejectsWrongPassword(t *testing.T) {
	chrome := os.Getenv("XALGORIX_TEST_CHROMIUM")
	if chrome == "" {
		t.Skip("requires Chromium")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err == nil && r.PostForm.Get("email") == "op@example.test" && r.PostForm.Get("password") == "right" {
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "valid", Path: "/"})
				http.Redirect(w, r, "/dashboard", http.StatusFound)
				return
			}
			http.Error(w, "bad credentials", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<form id="f" method="post" action="/login"><input name="email" type="email"><input name="password" type="password"><button type="button" onclick="document.getElementById('f').submit()">Sign in</button></form>`))
	})
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err != nil || c.Value != "valid" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>" + markerlessDashboardRunes + "</body></html>"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	origin, _ := assessment.ParseApprovedOrigin("app", server.URL)
	origin.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	base := BrowserLoginParams{
		AppScope: &scope, LoginURL: server.URL + "/login", VerifyURL: server.URL + "/dashboard",
		Marker: "", Username: "op@example.test", UsernameField: "email", PasswordField: "password",
	}

	// Correct password: markerless capture succeeds and returns the session.
	ok := base
	ok.Password = "right"
	result, err := CaptureBrowserLogin(t.Context(), Config{KatanaChromePath: chrome}, t.TempDir(), ok)
	if err != nil {
		t.Fatalf("markerless capture with the correct password failed: %v", err)
	}
	if !strings.Contains(result.CookieHeader, "session=valid") {
		t.Fatalf("captured cookie header missing session: %q", result.CookieHeader)
	}

	// Wrong password: the browser stays on the sign-in form, so markerless
	// verification must fail rather than return an anonymous session.
	bad := base
	bad.Password = "wrong"
	if _, err := CaptureBrowserLogin(t.Context(), Config{KatanaChromePath: chrome}, t.TempDir(), bad); err == nil {
		t.Fatal("a wrong password was accepted as a markerless login")
	}
}
