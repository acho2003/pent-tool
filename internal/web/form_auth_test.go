package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/credentials"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

func TestVerifyFormSessionHandlesCSRFAndRejectsInvalidLogin(t *testing.T) {
	var outsideRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/login":
			if r.Method == http.MethodGet {
				fmtForm := `<form method="post" action="/app/login"><input type="hidden" name="csrf" value="form-token"><input name="username"><input name="password" type="password"></form>`
				_, _ = w.Write([]byte(fmtForm))
				return
			}
			if r.PostFormValue("csrf") != "form-token" || r.PostFormValue("username") != "operator" || r.PostFormValue("password") != "private-password" {
				http.Error(w, "invalid login", http.StatusForbidden)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "lab_session", Value: "session-value", Path: "/app", HttpOnly: true})
			http.Redirect(w, r, "/app/private", http.StatusSeeOther)
		case "/app/private":
			cookie, err := r.Cookie("lab_session")
			if err != nil || cookie.Value != "session-value" {
				http.Error(w, "not authenticated", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte("LAB_AUTHENTICATED_MARKER"))
		case "/outside":
			outsideRequests.Add(1)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	values := map[string]string{"login_url": server.URL + "/app/login", "username": "operator", "password": "private-password", "csrf_field": "csrf"}
	got, err := verifyFormSession(context.Background(), server.URL+"/app", server.URL+"/app/private", "LAB_AUTHENTICATED_MARKER", values)
	if err != nil || got != "Cookie: lab_session=session-value" {
		t.Fatalf("form session = %q, err %v", got, err)
	}
	values["password"] = "wrong-secret"
	if _, err := verifyFormSession(context.Background(), server.URL+"/app", server.URL+"/app/private", "LAB_AUTHENTICATED_MARKER", values); err == nil || strings.Contains(err.Error(), values["password"]) {
		t.Fatalf("invalid credential error leaked secret or succeeded: %v", err)
	}
	values["password"] = "private-password"
	if _, err := verifyFormSession(context.Background(), server.URL+"/app", server.URL+"/outside", "LAB_AUTHENTICATED_MARKER", values); err == nil || outsideRequests.Load() != 0 {
		t.Fatalf("out-of-scope verification was contacted: %v, count=%d", err, outsideRequests.Load())
	}
}

func TestPrepareAssessmentAuthenticationWithFormCredential(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/login":
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`<form method="post" action="/app/login"><input type="hidden" name="csrf" value="token"><input name="username"><input name="password" type="password"></form>`))
				return
			}
			if r.PostFormValue("csrf") != "token" || r.PostFormValue("password") != "secret-password" {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "opaque", Path: "/app"})
			http.Redirect(w, r, "/app/verify", http.StatusSeeOther)
		case "/app/verify":
			if cookie, err := r.Cookie("session"); err != nil || cookie.Value != "opaque" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte("Account dashboard"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	s := newTestServer(t, nil)
	keyPath := t.TempDir() + "/credential.key"
	if err := os.WriteFile(keyPath, []byte("01234567890123456789012345678901"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XALGORIX_CREDENTIAL_KEY_FILE", keyPath)
	vault, err := s.credentialVault()
	if err != nil {
		t.Fatal(err)
	}
	meta, err := vault.Create(credentials.Record{Name: "form", Kind: assessment.AccessFormLogin, TargetIDs: []string{"app"}, Values: map[string]string{"login_url": server.URL + "/app/login", "username": "operator", "password": "secret-password", "csrf_field": "csrf"}})
	if err != nil {
		t.Fatal(err)
	}
	plan := &scanner.AssessmentPlan{
		Config:       assessment.AssessmentConfig{Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: server.URL + "/app"}}, Access: []assessment.AccessBinding{{Kind: assessment.AccessFormLogin, TargetIDs: []string{"app"}, CredentialID: meta.ID, VerifyURL: server.URL + "/app/verify", VerifyMarker: "Account dashboard"}}},
		Capabilities: []assessment.CapabilityEvidence{{Capability: assessment.CapAuthWeb, TargetID: "app", State: assessment.StateAvailable}},
		Jobs:         []scanner.PlanJob{{Scanner: "zap", TargetID: "app", State: scanner.PlanSelected}},
	}
	headers, err := s.prepareAssessmentAuthentication(context.Background(), plan)
	if err != nil || len(headers["app"]) != 1 || headers["app"][0] != "Cookie: session=opaque" || plan.Capabilities[0].State != assessment.StateVerified || plan.Jobs[0].ExecutionMode != "authenticated" {
		t.Fatalf("form credential was not verified and scoped: headers=%v plan=%+v err=%v", headers, plan, err)
	}
	encoded, _ := json.Marshal(plan)
	if strings.Contains(string(encoded), "secret-password") || strings.Contains(string(encoded), "session=opaque") {
		t.Fatal("form password or session cookie entered the persisted assessment plan")
	}
}

func TestFormLoginNeverPostsCredentialsOutsideApplication(t *testing.T) {
	var foreignRequests atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignRequests.Add(1)
	}))
	defer foreign.Close()
	var redirectAfterPost atomic.Bool
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app/login" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			action := foreign.URL + "/receive"
			if redirectAfterPost.Load() {
				action = "/app/login"
			}
			_, _ = w.Write([]byte(`<form method="post" action="` + action + `"><input name="username"><input name="password" type="password"></form>`))
			return
		}
		http.Redirect(w, r, foreign.URL+"/receive", http.StatusSeeOther)
	}))
	defer app.Close()
	values := map[string]string{"login_url": app.URL + "/app/login", "username": "operator", "password": "secret-password"}
	if _, err := verifyFormSession(context.Background(), app.URL+"/app", app.URL+"/app/login", "marker", values); err == nil || foreignRequests.Load() != 0 {
		t.Fatalf("foreign form action received credentials: err=%v requests=%d", err, foreignRequests.Load())
	}
	redirectAfterPost.Store(true)
	if _, err := verifyFormSession(context.Background(), app.URL+"/app", app.URL+"/app/login", "marker", values); err == nil || foreignRequests.Load() != 0 {
		t.Fatalf("foreign login redirect was followed: err=%v requests=%d", err, foreignRequests.Load())
	}
}

// spaLoginServer mimics a React/Next sign-in: the page's form is submitted by
// script as JSON to an API route, which sets the session cookie.
func spaLoginServer(t *testing.T, foreignHits *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/sign-in":
			_, _ = w.Write([]byte(`<form class="space-y-5"><input name="cidNo"><input name="password" type="password"></form>`))
		case "/app/api/auth/login":
			var body map[string]string
			if r.Method != http.MethodPost || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") || json.NewDecoder(r.Body).Decode(&body) != nil {
				http.Error(w, "json required", http.StatusBadRequest)
				return
			}
			if body["cidNo"] != "11111111111" || body["password"] != "spa-secret" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"Invalid credentials"}`))
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "app_access_token", Value: "jwt-value", Path: "/", HttpOnly: true})
			_, _ = w.Write([]byte(`{"message":"Logged in"}`))
		case "/app/dashboard":
			if c, err := r.Cookie("app_access_token"); err != nil || c.Value != "jwt-value" {
				http.Redirect(w, r, "/app/sign-in", http.StatusTemporaryRedirect)
				return
			}
			_, _ = w.Write([]byte("<button>Sign out</button>"))
		case "/outside":
			if foreignHits != nil {
				foreignHits.Add(1)
			}
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestVerifyFormSessionSubmitsJSONForScriptDrivenLogin(t *testing.T) {
	server := spaLoginServer(t, nil)
	defer server.Close()
	values := map[string]string{
		"login_url": server.URL + "/app/sign-in", "submit_url": server.URL + "/app/api/auth/login", "submit_format": "json",
		"username": "11111111111", "password": "spa-secret", "username_field": "cidNo", "password_field": "password",
	}
	got, err := verifyFormSession(context.Background(), server.URL+"/app", server.URL+"/app/dashboard", "Sign out", values)
	if err != nil || got != "Cookie: app_access_token=jwt-value" {
		t.Fatalf("json form session = %q, err %v", got, err)
	}
	values["password"] = "wrong-secret"
	_, err = verifyFormSession(context.Background(), server.URL+"/app", server.URL+"/app/dashboard", "Sign out", values)
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") || strings.Contains(err.Error(), "wrong-secret") {
		t.Fatalf("rejected json login should report the status without the secret: %v", err)
	}
	// The same app submitted as an HTML form never logs in; the reason names
	// where verification ended up instead of a generic failure.
	delete(values, "submit_format")
	delete(values, "submit_url")
	values["password"] = "spa-secret"
	_, err = verifyFormSession(context.Background(), server.URL+"/app", server.URL+"/app/dashboard", "Sign out", values)
	if err == nil || !strings.Contains(err.Error(), "/app/sign-in") {
		t.Fatalf("html submission against a json-only login should fail at the sign-in bounce: %v", err)
	}
}

func TestVerifyFormSessionJSONSubmitStaysInScope(t *testing.T) {
	var foreignHits atomic.Int32
	server := spaLoginServer(t, &foreignHits)
	defer server.Close()
	base := map[string]string{"login_url": server.URL + "/app/sign-in", "submit_format": "json", "username": "11111111111", "password": "spa-secret", "username_field": "cidNo"}
	cases := map[string]map[string]string{
		"outside submit url": {"submit_url": server.URL + "/outside"},
		"unknown format":     {"submit_format": "xml", "submit_url": server.URL + "/app/api/auth/login"},
		"csrf with json":     {"csrf_field": "csrf", "submit_url": server.URL + "/app/api/auth/login"},
	}
	for name, extra := range cases {
		values := map[string]string{}
		for k, v := range base {
			values[k] = v
		}
		for k, v := range extra {
			values[k] = v
		}
		if _, err := verifyFormSession(context.Background(), server.URL+"/app", server.URL+"/app/dashboard", "Sign out", values); err == nil {
			t.Fatalf("%s: expected rejection", name)
		}
	}
	if foreignHits.Load() != 0 {
		t.Fatalf("credentials were sent outside the application: %d requests", foreignHits.Load())
	}
}

func TestPrepareAssessmentAuthenticationReportsFormLoginReason(t *testing.T) {
	server := spaLoginServer(t, nil)
	defer server.Close()
	s := newTestServer(t, nil)
	keyPath := t.TempDir() + "/credential.key"
	if err := os.WriteFile(keyPath, []byte("01234567890123456789012345678901"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XALGORIX_CREDENTIAL_KEY_FILE", keyPath)
	vault, err := s.credentialVault()
	if err != nil {
		t.Fatal(err)
	}
	meta, err := vault.Create(credentials.Record{Name: "spa", Kind: assessment.AccessFormLogin, TargetIDs: []string{"app"}, Values: map[string]string{
		"login_url": server.URL + "/app/sign-in", "submit_url": server.URL + "/app/api/auth/login", "submit_format": "json",
		"username": "11111111111", "password": "not-the-password", "username_field": "cidNo",
	}})
	if err != nil {
		t.Fatal(err)
	}
	plan := &scanner.AssessmentPlan{
		Config:       assessment.AssessmentConfig{Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: server.URL + "/app"}}, Access: []assessment.AccessBinding{{Kind: assessment.AccessFormLogin, TargetIDs: []string{"app"}, CredentialID: meta.ID, VerifyURL: server.URL + "/app/dashboard", VerifyMarker: "Sign out"}}},
		Capabilities: []assessment.CapabilityEvidence{{Capability: assessment.CapAuthWeb, TargetID: "app", State: assessment.StateAvailable}},
	}
	if _, err := s.prepareAssessmentAuthentication(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	reason := plan.Capabilities[0].Reason
	if plan.Capabilities[0].State != assessment.StateUnavailable || !strings.Contains(reason, "form login was rejected (HTTP 401)") || strings.Contains(reason, "not-the-password") {
		t.Fatalf("capability reason should explain the rejection without secrets: %q", reason)
	}
}

func TestFormSessionRenewsOnceAndStopsOnSecondExpiry(t *testing.T) {
	var generation atomic.Int32
	var logins atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/login":
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`<form method="post" action="/app/login"><input name="username"><input name="password" type="password"></form>`))
				return
			}
			if r.PostFormValue("password") != "renew-secret" {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			logins.Add(1)
			http.SetCookie(w, &http.Cookie{Name: "session", Value: fmt.Sprint(generation.Load()), Path: "/app"})
			_, _ = w.Write([]byte("logged in"))
		case "/app/verify":
			cookie, err := r.Cookie("session")
			if err != nil || cookie.Value != fmt.Sprint(generation.Load()) {
				http.Error(w, "expired", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte("private marker"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	s := newTestServer(t, nil)
	keyPath := t.TempDir() + "/credential.key"
	if err := os.WriteFile(keyPath, []byte("01234567890123456789012345678901"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XALGORIX_CREDENTIAL_KEY_FILE", keyPath)
	vault, err := s.credentialVault()
	if err != nil {
		t.Fatal(err)
	}
	meta, err := vault.Create(credentials.Record{Name: "renew", Kind: assessment.AccessFormLogin, TargetIDs: []string{"app"}, Values: map[string]string{"login_url": server.URL + "/app/login", "username": "operator", "password": "renew-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	plan := &scanner.AssessmentPlan{Config: assessment.AssessmentConfig{Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: server.URL + "/app"}}, Access: []assessment.AccessBinding{{Kind: assessment.AccessFormLogin, TargetIDs: []string{"app"}, CredentialID: meta.ID, VerifyURL: server.URL + "/app/verify", VerifyMarker: "private marker"}}}, Capabilities: []assessment.CapabilityEvidence{{Capability: assessment.CapAuthWeb, TargetID: "app", State: assessment.StateAvailable}}}
	headers, err := s.prepareAssessmentAuthentication(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	refreshers, err := s.assessmentAuthRefreshers(plan, headers)
	if err != nil {
		t.Fatal(err)
	}
	current := headers["app"]
	if _, err := refreshers["app"](context.Background(), current); err != nil {
		t.Fatal(err)
	}
	generation.Add(1)
	renewed, err := refreshers["app"](context.Background(), current)
	if err != nil || renewed[0] != "Cookie: session=1" || logins.Load() != 2 {
		t.Fatalf("first expiry did not renew once: headers=%v logins=%d err=%v", renewed, logins.Load(), err)
	}
	generation.Add(1)
	if _, err := refreshers["app"](context.Background(), renewed); err == nil || strings.Contains(err.Error(), "renew-secret") || logins.Load() != 2 {
		t.Fatalf("second expiry did not stop securely: logins=%d err=%v", logins.Load(), err)
	}
}
