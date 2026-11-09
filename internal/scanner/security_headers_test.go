package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func runSecurityHeaders(t *testing.T, set func(http.Header)) []Finding {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		set(w.Header())
		w.Write([]byte("ok"))
	}))
	defer server.Close()
	cfg := assessment.AssessmentConfig{Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: server.URL + "/"}}}
	scope := assessment.AppScopeForTarget(cfg, "app")
	run := (securityHeadersRunner{}).Run(context.Background(), Request{Target: server.URL + "/", ScanDir: t.TempDir(), Scope: "assessment:app", TypedAssessment: true, AppScope: &scope}, Config{Budget: NewAssessmentBudget(0, 50, 0)}, nil)
	if run.Status != "completed" {
		t.Fatalf("status=%q reason=%q", run.Status, run.Reason)
	}
	findings, err := ParseRun(run)
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func ruleIDs(findings []Finding) map[string]Finding {
	out := map[string]Finding{}
	for _, f := range findings {
		out[f.RuleID] = f
	}
	return out
}

func TestSecurityHeadersFlagsMissingHeaders(t *testing.T) {
	// A bare HTTP response (httptest is HTTP, so HSTS is not expected) with no
	// security headers and a version banner.
	got := ruleIDs(runSecurityHeaders(t, func(h http.Header) {
		h.Set("Server", "nginx/1.25.3")
	}))
	for _, rule := range []string{"security-header-csp-missing", "security-header-clickjacking", "security-header-nosniff", "security-header-referrer-policy", "security-header-version-disclosure-server"} {
		if _, ok := got[rule]; !ok {
			t.Errorf("expected %s", rule)
		}
	}
	// No HSTS finding over plain HTTP (it only applies to https).
	if _, ok := got["security-header-hsts-missing"]; ok {
		t.Error("HSTS must not be flagged on an HTTP target")
	}
}

func TestSecurityHeadersAcceptsStrongHeaders(t *testing.T) {
	got := ruleIDs(runSecurityHeaders(t, func(h http.Header) {
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; script-src 'self'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	}))
	for rule := range got {
		if rule != "security-header-hsts-missing" { // n/a over http anyway
			t.Errorf("unexpected finding on a well-configured response: %s", rule)
		}
	}
}

func TestSecurityHeadersFlagsWeakCSP(t *testing.T) {
	got := ruleIDs(runSecurityHeaders(t, func(h http.Header) {
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
	}))
	f, ok := got["security-header-csp-weak"]
	if !ok || f.Severity != "low" {
		t.Fatalf("weak CSP not reported: %v", got)
	}
	if _, present := got["security-header-csp-missing"]; present {
		t.Error("a present-but-weak CSP must not also be reported as missing")
	}
}
