package web

import (
	"context"
	"encoding/json"
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
