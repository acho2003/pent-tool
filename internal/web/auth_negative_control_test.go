package web

import (
	"context"
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

// authTestVault points the server at a fresh credential key and returns the
// vault so a test can store a target-bound credential.
func authTestVault(t *testing.T, s *Server) *credentials.Vault {
	t.Helper()
	keyPath := t.TempDir() + "/credential.key"
	if err := os.WriteFile(keyPath, []byte("01234567890123456789012345678901"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XALGORIX_CREDENTIAL_KEY_FILE", keyPath)
	vault, err := s.credentialVault()
	if err != nil {
		t.Fatal(err)
	}
	return vault
}

// headerAuthPlan is one URL target with a header credential and authenticated
// zap/nuclei jobs that depend on the verification outcome.
func headerAuthPlan(appURL, credentialID, verifyURL, marker string) *scanner.AssessmentPlan {
	return &scanner.AssessmentPlan{
		Config: assessment.AssessmentConfig{
			Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: appURL}},
			Access:  []assessment.AccessBinding{{TargetIDs: []string{"app"}, Kind: assessment.AccessApplicationHeaders, CredentialID: credentialID, VerifyURL: verifyURL, VerifyMarker: marker}},
		},
		Capabilities: []assessment.CapabilityEvidence{{Capability: assessment.CapAuthWeb, TargetID: "app", State: assessment.StateAvailable, Provenance: "credential_ref"}},
		Jobs:         []scanner.PlanJob{{Scanner: "zap", TargetID: "app", State: scanner.PlanSelected}, {Scanner: "nuclei", TargetID: "app", State: scanner.PlanSelected}},
	}
}

func appScopeFor(appURL string) assessment.AppScope {
	return assessment.AppScopeForTarget(assessment.AssessmentConfig{Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: appURL}}}, "app")
}

func TestNegativeControlFailsWhenMarkerPublic(t *testing.T) {
	const secret = "Bearer PUBLIC-PAGE-SECRET"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The marker is shown to everybody, so a matching positive check proves
		// nothing about the credential.
		_, _ = w.Write([]byte("Account dashboard"))
	}))
	defer server.Close()
	if err := verifyNegativeControl(context.Background(), appScopeFor(server.URL+"/app"), server.URL+"/app/verify", "Account dashboard"); err == nil {
		t.Fatal("negative control passed although the marker is public")
	}
	s := newTestServer(t, nil)
	vault := authTestVault(t, s)
	meta, err := vault.Create(credentials.Record{Name: "public", Kind: assessment.AccessApplicationHeaders, TargetIDs: []string{"app"}, Values: map[string]string{"Authorization": secret}})
	if err != nil {
		t.Fatal(err)
	}
	plan := headerAuthPlan(server.URL+"/app", meta.ID, server.URL+"/app/verify", "Account dashboard")
	headers, err := s.prepareAssessmentAuthentication(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	evidence := plan.Capabilities[0]
	if len(headers["app"]) != 0 || evidence.State != assessment.StateFailed || !strings.Contains(evidence.Reason, "without credentials") || strings.Contains(evidence.Reason, secret) {
		t.Fatalf("public marker did not fail verification: headers=%v evidence=%+v", headers, evidence)
	}
	for _, job := range plan.Jobs {
		if job.State != scanner.PlanSkipped || job.ExecutionMode == "authenticated" {
			t.Fatalf("%s ran despite a failed negative control: %+v", job.Scanner, job)
		}
	}
}

func TestNegativeControlPassesWhenMarkerRequiresAuth(t *testing.T) {
	const secret = "Bearer PRIVATE-PAGE-SECRET"
	var foreignHits atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignHits.Add(1)
		_, _ = w.Write([]byte("Account dashboard"))
	}))
	defer foreign.Close()
	var anonymousCredentialLeak atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authed := r.Header.Get("Authorization") == secret
		if !authed && (r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "") {
			anonymousCredentialLeak.Store(true)
		}
		switch r.URL.Path {
		case "/app/verify":
			if !authed {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte("Account dashboard"))
		case "/app/redirecting":
			if !authed {
				http.Redirect(w, r, "/app/sign-in", http.StatusFound)
				return
			}
			_, _ = w.Write([]byte("Account dashboard"))
		case "/app/sign-in":
			_, _ = w.Write([]byte("Please sign in"))
		case "/app/foreign":
			http.Redirect(w, r, foreign.URL+"/landing", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	scope := appScopeFor(server.URL + "/app")
	for _, path := range []string{"/app/verify", "/app/redirecting", "/app/foreign"} {
		if err := verifyNegativeControl(context.Background(), scope, server.URL+path, "Account dashboard"); err != nil {
			t.Fatalf("negative control at %s rejected a protected marker: %v", path, err)
		}
	}
	if foreignHits.Load() != 0 {
		t.Fatalf("negative control followed an out-of-scope redirect: %d requests", foreignHits.Load())
	}
	if err := verifyNegativeControl(context.Background(), scope, foreign.URL+"/landing", "Account dashboard"); err == nil || foreignHits.Load() != 0 {
		t.Fatalf("negative control contacted an out-of-scope verification URL: err=%v hits=%d", err, foreignHits.Load())
	}

	s := newTestServer(t, nil)
	vault := authTestVault(t, s)
	meta, err := vault.Create(credentials.Record{Name: "private", Kind: assessment.AccessApplicationHeaders, TargetIDs: []string{"app"}, Values: map[string]string{"Authorization": secret}})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/app/verify", "/app/redirecting"} {
		plan := headerAuthPlan(server.URL+"/app", meta.ID, server.URL+path, "Account dashboard")
		headers, err := s.prepareAssessmentAuthentication(context.Background(), plan)
		if err != nil {
			t.Fatal(err)
		}
		evidence := plan.Capabilities[0]
		if len(headers["app"]) != 1 || evidence.State != assessment.StateVerified || !strings.Contains(evidence.Reason, "negative control") || evidence.Provenance != authVerificationProvenance {
			t.Fatalf("%s: protected marker was not verified: headers=%v evidence=%+v", path, headers, evidence)
		}
		for _, job := range plan.Jobs {
			if job.State != scanner.PlanSelected || job.ExecutionMode != "authenticated" {
				t.Fatalf("%s: verified job was not authenticated: %+v", path, job)
			}
		}
	}
	if anonymousCredentialLeak.Load() {
		t.Fatal("the unauthenticated negative control carried credentials")
	}
}

func TestNegativeControlUsesNegativeMarkerWhenSupplied(t *testing.T) {
	const secret = "Bearer NEGATIVE-MARKER-SECRET"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == secret {
			_, _ = w.Write([]byte("Welcome back. Sign out"))
			return
		}
		_, _ = w.Write([]byte("Welcome visitor. Sign in"))
	}))
	defer server.Close()
	s := newTestServer(t, nil)
	vault := authTestVault(t, s)
	meta, err := vault.Create(credentials.Record{Name: "negative", Kind: assessment.AccessApplicationHeaders, TargetIDs: []string{"app"}, Values: map[string]string{"Authorization": secret}})
	if err != nil {
		t.Fatal(err)
	}
	plan := headerAuthPlan(server.URL+"/app", meta.ID, server.URL+"/app/home", "Welcome")
	if _, err := s.prepareAssessmentAuthentication(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if plan.Capabilities[0].State != assessment.StateFailed {
		t.Fatalf("a verify marker shown anonymously must fail without a negative marker: %+v", plan.Capabilities[0])
	}
	plan = headerAuthPlan(server.URL+"/app", meta.ID, server.URL+"/app/home", "Welcome")
	plan.Config.Access[0].NegativeMarker = "Sign out"
	if _, err := s.prepareAssessmentAuthentication(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if plan.Capabilities[0].State != assessment.StateVerified {
		t.Fatalf("the supplied negative marker was not used: %+v", plan.Capabilities[0])
	}
}

func TestHeaderCookieAuthCanAutoVerifyTargetWithLoginRedirect(t *testing.T) {
	const cookieValue = "session=valid"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/login" {
			_, _ = w.Write([]byte("Sign in"))
			return
		}
		if r.Header.Get("Cookie") == cookieValue {
			_, _ = w.Write([]byte("Private dashboard"))
			return
		}
		http.Redirect(w, r, "/app/login", http.StatusFound)
	}))
	defer server.Close()
	s := newTestServer(t, nil)
	vault := authTestVault(t, s)
	meta, err := vault.Create(credentials.Record{Name: "cookie", Kind: assessment.AccessApplicationHeaders, TargetIDs: []string{"app"}, Values: map[string]string{"Cookie": cookieValue}})
	if err != nil {
		t.Fatal(err)
	}
	plan := headerAuthPlan(server.URL+"/app", meta.ID, "", "")
	plan.Config.Access[0].VerifyURL = ""
	plan.Config.Access[0].VerifyMarker = ""
	headers, err := s.prepareAssessmentAuthentication(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(headers["app"]) != 1 || headers["app"][0] != "Cookie: "+cookieValue || plan.Capabilities[0].State != assessment.StateVerified {
		t.Fatalf("cookie was not auto-verified: headers=%v evidence=%+v", headers, plan.Capabilities[0])
	}
	refreshers, err := s.assessmentAuthRefreshers(plan, headers)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed, err := refreshers["app"](context.Background(), headers["app"]); err != nil || len(refreshed) != 1 || refreshed[0] != headers["app"][0] {
		t.Fatalf("authentication prerequisite could not re-verify the cookie: headers=%v err=%v", refreshed, err)
	}
}

func TestHeaderCredentialAutoVerificationRejectsIdenticalPublicResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Public single-page app"))
	}))
	defer server.Close()
	s := newTestServer(t, nil)
	vault := authTestVault(t, s)
	meta, err := vault.Create(credentials.Record{Name: "cookie", Kind: assessment.AccessApplicationHeaders, TargetIDs: []string{"app"}, Values: map[string]string{"Cookie": "session=invalid"}})
	if err != nil {
		t.Fatal(err)
	}
	plan := headerAuthPlan(server.URL+"/app", meta.ID, "", "")
	plan.Config.Access[0].VerifyURL = ""
	plan.Config.Access[0].VerifyMarker = ""
	if headers, err := s.prepareAssessmentAuthentication(context.Background(), plan); err != nil {
		t.Fatal(err)
	} else if len(headers["app"]) != 0 || plan.Capabilities[0].State != assessment.StateFailed || !strings.Contains(plan.Capabilities[0].Reason, "look the same") {
		t.Fatalf("identical public response incorrectly verified credentials: headers=%v evidence=%+v", headers, plan.Capabilities[0])
	}
}

func TestNegativeControlRunsOncePerVerificationNotPerRefresh(t *testing.T) {
	const secret = "Bearer REFRESH-COUNT-SECRET"
	var anonymous, authenticated atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app/verify" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != secret {
			anonymous.Add(1)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		authenticated.Add(1)
		_, _ = w.Write([]byte("Account dashboard"))
	}))
	defer server.Close()
	s := newTestServer(t, nil)
	vault := authTestVault(t, s)
	meta, err := vault.Create(credentials.Record{Name: "count", Kind: assessment.AccessApplicationHeaders, TargetIDs: []string{"app"}, Values: map[string]string{"Authorization": secret}})
	if err != nil {
		t.Fatal(err)
	}
	plan := headerAuthPlan(server.URL+"/app", meta.ID, server.URL+"/app/verify", "Account dashboard")
	headers, err := s.prepareAssessmentAuthentication(context.Background(), plan)
	if err != nil || plan.Capabilities[0].State != assessment.StateVerified {
		t.Fatalf("verification failed: %+v err=%v", plan.Capabilities[0], err)
	}
	if anonymous.Load() != 1 || authenticated.Load() != 1 {
		t.Fatalf("verification = %d anonymous / %d authenticated requests, want 1/1", anonymous.Load(), authenticated.Load())
	}
	refreshers, err := s.assessmentAuthRefreshers(plan, headers)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := refreshers["app"](context.Background(), headers["app"]); err != nil {
			t.Fatalf("refresh %d failed: %v", i, err)
		}
	}
	if anonymous.Load() != 1 || authenticated.Load() != 4 {
		t.Fatalf("refreshes spent extra requests: %d anonymous / %d authenticated, want 1/4", anonymous.Load(), authenticated.Load())
	}
}

func TestFailedVerificationSetsStateFailedVaultProblemSetsUnavailable(t *testing.T) {
	const secret = "Bearer STATE-SECRET"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/login":
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`<form method="post" action="/app/login"><input name="username"><input name="password" type="password"></form>`))
				return
			}
			http.Error(w, "invalid login", http.StatusForbidden)
		default:
			if r.Header.Get("Authorization") != secret {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte("Account dashboard"))
		}
	}))
	defer server.Close()
	s := newTestServer(t, nil)
	vault := authTestVault(t, s)
	header, err := vault.Create(credentials.Record{Name: "header", Kind: assessment.AccessApplicationHeaders, TargetIDs: []string{"app"}, Values: map[string]string{"Authorization": secret}})
	if err != nil {
		t.Fatal(err)
	}
	form, err := vault.Create(credentials.Record{Name: "form", Kind: assessment.AccessFormLogin, TargetIDs: []string{"app"}, Values: map[string]string{"login_url": server.URL + "/app/login", "username": "operator", "password": "wrong-password"}})
	if err != nil {
		t.Fatal(err)
	}
	outsideLogin, err := vault.Create(credentials.Record{Name: "outside", Kind: assessment.AccessFormLogin, TargetIDs: []string{"app"}, Values: map[string]string{"login_url": server.URL + "/elsewhere/login", "username": "operator", "password": "wrong-password"}})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*assessment.AccessBinding)
		want   assessment.EvidenceState
	}{
		{"wrong marker ran and was rejected", func(b *assessment.AccessBinding) { b.VerifyMarker = "wrong marker" }, assessment.StateFailed},
		{"form login ran and was refused", func(b *assessment.AccessBinding) {
			b.Kind, b.CredentialID = assessment.AccessFormLogin, form.ID
		}, assessment.StateFailed},
		{"unresolved credential", func(b *assessment.AccessBinding) { b.CredentialID = "missing-credential" }, assessment.StateUnavailable},
		{"out-of-scope verification URL", func(b *assessment.AccessBinding) { b.VerifyURL = server.URL + "/elsewhere/verify" }, assessment.StateUnavailable},
		{"form login URL outside the application", func(b *assessment.AccessBinding) {
			b.Kind, b.CredentialID = assessment.AccessFormLogin, outsideLogin.ID
		}, assessment.StateUnavailable},
	}
	for _, tc := range cases {
		plan := headerAuthPlan(server.URL+"/app", header.ID, server.URL+"/app/verify", "Account dashboard")
		tc.mutate(&plan.Config.Access[0])
		headers, err := s.prepareAssessmentAuthentication(context.Background(), plan)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if plan.Capabilities[0].State != tc.want || len(headers["app"]) != 0 || strings.Contains(plan.Capabilities[0].Reason, secret) || strings.Contains(plan.Capabilities[0].Reason, "wrong-password") {
			t.Fatalf("%s: state=%q want %q (reason %q, headers %v)", tc.name, plan.Capabilities[0].State, tc.want, plan.Capabilities[0].Reason, headers)
		}
		for _, job := range plan.Jobs {
			if job.State != scanner.PlanSkipped {
				t.Fatalf("%s: %s was not skipped: %+v", tc.name, job.Scanner, job)
			}
		}
	}

	t.Setenv("XALGORIX_CREDENTIAL_KEY_FILE", t.TempDir()+"/missing.key")
	plan := headerAuthPlan(server.URL+"/app", header.ID, server.URL+"/app/verify", "Account dashboard")
	if _, err := s.prepareAssessmentAuthentication(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if plan.Capabilities[0].State != assessment.StateUnavailable || plan.Jobs[0].State != scanner.PlanSkipped || plan.Jobs[1].State != scanner.PlanSkipped {
		t.Fatalf("vault problem was not reported as unavailable: %+v", plan)
	}
}

func TestFailedOrExpiredAuthStillSkipsAuthenticatedZapNuclei(t *testing.T) {
	for state, blocking := range map[assessment.EvidenceState]bool{
		assessment.StateUnavailable: true, assessment.StateFailed: true, assessment.StateExpired: true,
		assessment.StateVerified: false, assessment.StateAvailable: false, assessment.StateDeclared: false,
	} {
		evidence := []assessment.CapabilityEvidence{{Capability: assessment.CapAuthWeb, TargetID: "app", State: state, Reason: "reason for " + string(state)}}
		if hasBlockingAuth(evidence, "app") != blocking {
			t.Errorf("hasBlockingAuth(%s) = %v, want %v", state, !blocking, blocking)
		}
		if blocking && blockingAuthReason(evidence, "app") != "reason for "+string(state) {
			t.Errorf("blockingAuthReason(%s) = %q", state, blockingAuthReason(evidence, "app"))
		}
		if hasBlockingAuth(evidence, "other") {
			t.Errorf("blocking state of %s leaked to another target", state)
		}
	}

	const secret = "Bearer EXPIRED-SECRET"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != secret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("Account dashboard"))
	}))
	defer server.Close()
	s := newTestServer(t, nil)
	vault := authTestVault(t, s)
	meta, err := vault.Create(credentials.Record{Name: "failed", Kind: assessment.AccessApplicationHeaders, TargetIDs: []string{"app"}, Values: map[string]string{"Authorization": secret}})
	if err != nil {
		t.Fatal(err)
	}
	plan := headerAuthPlan(server.URL+"/app", meta.ID, server.URL+"/app/verify", "wrong marker")
	plan.Config.Targets = append(plan.Config.Targets, assessment.Target{ID: "old", Kind: assessment.KindURL, Value: server.URL + "/old"})
	plan.Capabilities = append(plan.Capabilities, assessment.CapabilityEvidence{Capability: assessment.CapAuthWeb, TargetID: "old", State: assessment.StateExpired, Reason: "authenticated session expired during scanning"})
	plan.Jobs = append(plan.Jobs, scanner.PlanJob{Scanner: "zap", TargetID: "old", State: scanner.PlanSelected, ExecutionMode: "authenticated"}, scanner.PlanJob{Scanner: "nuclei", TargetID: "old", State: scanner.PlanSelected, ExecutionMode: "authenticated"})
	headers, err := s.prepareAssessmentAuthentication(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(headers) != 0 || plan.Capabilities[0].State != assessment.StateFailed || plan.Capabilities[1].State != assessment.StateExpired {
		t.Fatalf("unexpected authentication outcome: headers=%v capabilities=%+v", headers, plan.Capabilities)
	}
	for _, job := range plan.Jobs {
		if job.State != scanner.PlanSkipped || job.ExecutionMode == "authenticated" || !strings.HasPrefix(job.Reason, "authenticated scan skipped") {
			t.Fatalf("%s for %s would run anonymously after a failed or expired session: %+v", job.Scanner, job.TargetID, job)
		}
	}
}
