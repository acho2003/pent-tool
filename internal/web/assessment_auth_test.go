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
	if len(failed["app"]) != 0 || plan.Jobs[0].State != scanner.PlanSkipped || plan.Capabilities[0].State != assessment.StateFailed {
		t.Fatalf("failed verification did not block authenticated job: headers=%v plan=%+v", failed, plan)
	}
	plan.Fingerprint = "sha256:failed-auth"
	plan.Jobs[0].Target = server.URL + "/app/"
	plan.Jobs[0].Variant = "zap"
	runs := scanner.NewPipeline(scanner.Config{}).RunAssessmentJobs(context.Background(), *plan, t.TempDir(), nil, nil)
	if len(runs) != 1 || runs[0].Status != "skipped" || runs[0].TranscriptPath == "" {
		t.Fatalf("failed login has no ZAP terminal transcript: %+v", runs)
	}
	terminal, err := os.ReadFile(runs[0].TranscriptPath)
	if err != nil || !strings.Contains(string(terminal), "Authentication failed:") || strings.Contains(string(terminal), secret) {
		t.Fatalf("failed login terminal output is missing or unsafe: %q, err=%v", terminal, err)
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

func TestURLWithinApplicationDefaultPort(t *testing.T) {
	for _, tc := range []struct {
		app, candidate string
		want           bool
	}{
		{"https://app.example.test/portal", "https://app.example.test:443/portal/me", true},
		{"https://app.example.test:443/portal", "https://app.example.test/portal/me", true},
		{"http://app.example.test/portal", "http://app.example.test:80/portal", true},
		{"https://APP.example.test/portal", "https://app.example.test/portal/me", true},
		{"https://app.example.test/portal", "https://app.example.test:8443/portal/me", false},
		{"https://app.example.test/portal", "http://app.example.test:443/portal/me", false},
		{"https://app.example.test/portal", "https://app.example.test/portal/../admin", false},
		{"https://app.example.test/portal", "https://user@app.example.test/portal/me", false},
		{"https://app.example.test/portal", "https://app.example.test/portal/me?next=1", false},
		{"https://app.example.test/portal", "https://app.example.test/portal/me#top", false},
		{"app.example.test", "https://app.example.test/", false},
	} {
		if got := urlWithinApplication(tc.app, tc.candidate); got != tc.want {
			t.Errorf("urlWithinApplication(%q, %q) = %v, want %v", tc.app, tc.candidate, got, tc.want)
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

func TestAssessmentHostAliasesRequireBoundSafeCredential(t *testing.T) {
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
	meta, err := vault.Create(credentials.Record{Name: "host", Kind: assessment.AccessSSH, TargetIDs: []string{"host"}, Values: map[string]string{"ssh_alias": "audit-host", "gvm_credential_id": "58ff2793-2dc7-43fe-85f9-20bfac5a87e4", "gvm_ssh_port": "2222"}})
	if err != nil {
		t.Fatal(err)
	}
	plan := &scanner.AssessmentPlan{Config: assessment.AssessmentConfig{Access: []assessment.AccessBinding{{Kind: assessment.AccessSSH, CredentialID: meta.ID, TargetIDs: []string{"host"}}}}}
	aliases, err := s.assessmentHostAliases(plan)
	if err != nil || aliases["host"] != "audit-host" {
		t.Fatalf("bound SSH alias not resolved: %v %v", aliases, err)
	}
	gvm, requested := s.assessmentGVMSSHCredentials(plan)
	if !requested["host"] || gvm["host"].ID != "58ff2793-2dc7-43fe-85f9-20bfac5a87e4" || gvm["host"].Port != 2222 {
		t.Fatalf("bound Greenbone SSH credential not resolved: %+v %+v", gvm, requested)
	}
	plan.Config.Access[0].TargetIDs = []string{"other"}
	aliases, err = s.assessmentHostAliases(plan)
	if err != nil || len(aliases) != 0 {
		t.Fatalf("SSH alias crossed target boundary: %v %v", aliases, err)
	}
	gvm, _ = s.assessmentGVMSSHCredentials(plan)
	if len(gvm) != 0 {
		t.Fatalf("Greenbone credential crossed target boundary: %+v", gvm)
	}
}
