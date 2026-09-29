package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/credentials"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

func TestVerifyHeaderSessionRequiresMarkerAndKeepsRedirectInScope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/private" && r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/app/private" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("Account dashboard"))
	}))
	defer server.Close()

	lines := []string{"Authorization: Bearer test-token"}
	if err := verifyHeaderSession(context.Background(), server.URL+"/app/ok", "Account dashboard", lines, server.URL+"/app/"); err != nil {
		t.Fatalf("valid verification failed: %v", err)
	}
	if err := verifyHeaderSession(context.Background(), server.URL+"/app/ok", "wrong marker", lines, server.URL+"/app/"); err == nil {
		t.Fatal("verification succeeded without the expected marker")
	}
	if err := verifyHeaderSession(context.Background(), server.URL+"/app/private", "Account dashboard", lines, server.URL+"/app/"); err == nil {
		t.Fatal("verification followed an out-of-scope redirect")
	}
	if err := verifyHeaderSession(context.Background(), server.URL+"/outside", "Account dashboard", lines, server.URL+"/app/"); err == nil {
		t.Fatal("verification accepted an out-of-scope URL")
	}
}

func TestPrepareAssessmentAuthenticationVerifiesAndScopesHeaders(t *testing.T) {
	const secret = "Bearer AUTH-ONLY-AT-RUNTIME"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != secret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("Account dashboard"))
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
	meta, err := vault.Create(credentials.Record{Name: "test", Kind: assessment.AccessApplicationHeaders, TargetIDs: []string{"app"}, Values: map[string]string{"Authorization": secret}})
	if err != nil {
		t.Fatal(err)
	}
	plan := &scanner.AssessmentPlan{
		Config: assessment.AssessmentConfig{
			Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: server.URL + "/app/"}},
			Access:  []assessment.AccessBinding{{TargetIDs: []string{"app"}, Kind: assessment.AccessApplicationHeaders, CredentialID: meta.ID, VerifyURL: server.URL + "/app/verify", VerifyMarker: "Account dashboard"}},
		},
		Capabilities: []assessment.CapabilityEvidence{{Capability: assessment.CapAuthWeb, TargetID: "app", State: assessment.StateAvailable}},
		Jobs:         []scanner.PlanJob{{Scanner: "zap", TargetID: "app", State: scanner.PlanSelected, ExecutionMode: "unauthenticated"}},
		Decisions:    []scanner.PlanDecision{{Scanner: "zap", TargetID: "app", ExecutionMode: "unauthenticated"}},
	}
	got, err := s.prepareAssessmentAuthentication(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(got["app"]) != 1 || got["app"][0] != "Authorization: "+secret || plan.Capabilities[0].State != assessment.StateVerified || plan.Jobs[0].ExecutionMode != "authenticated" || plan.Decisions[0].ExecutionMode != "authenticated" {
		t.Fatalf("authentication preparation did not verify the target: headers=%v plan=%+v", got, plan)
	}
	encoded, _ := json.Marshal(plan)
	if strings.Contains(string(encoded), secret) {
		t.Fatal("runtime secret was copied into the assessment plan")
	}

	plan.Config.Access[0].VerifyMarker = "wrong marker"
	failed, err := s.prepareAssessmentAuthentication(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(failed["app"]) != 0 || plan.Jobs[0].State != scanner.PlanSkipped || plan.Capabilities[0].State != assessment.StateUnavailable {
		t.Fatalf("failed verification did not block authenticated job: headers=%v plan=%+v", failed, plan)
	}
}

func TestCredentialHeaderConversionAndApplicationURLBoundaries(t *testing.T) {
	lines, err := credentialHeaderLines(assessment.AccessBearerToken, map[string]string{"token": "secret"})
	if err != nil || len(lines) != 1 || lines[0] != "Authorization: Bearer secret" {
		t.Fatalf("bearer conversion = %v, %v", lines, err)
	}
	if _, err := credentialHeaderLines(assessment.AccessApplicationHeaders, map[string]string{"X-Test": "bad\r\nInjected: yes"}); err == nil {
		t.Fatal("accepted a CRLF header injection")
	}
	if !urlWithinApplication("https://app.example.test/Portal/Case", "https://app.example.test/Portal/Case/verify") {
		t.Fatal("in-scope path rejected")
	}
	for _, candidate := range []string{
		"https://app.example.test/Portal/CaseOther/verify",
		"https://app.example.test:8443/Portal/Case/verify",
		"https://other.example.test/Portal/Case/verify",
	} {
		if urlWithinApplication("https://app.example.test/Portal/Case", candidate) {
			t.Errorf("accepted out-of-scope URL %s", candidate)
		}
	}
}

func TestVerificationErrorsDoNotIncludeCredentials(t *testing.T) {
	const secret = "PRIVATE-BEARER-SECRET"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "failure", http.StatusInternalServerError)
	}))
	defer server.Close()
	err := verifyHeaderSession(context.Background(), server.URL+"/app/", "marker", []string{"Authorization: Bearer " + secret}, server.URL+"/app/")
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe verification error: %v", err)
	}
}
