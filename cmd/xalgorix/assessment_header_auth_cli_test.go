package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestParseAuthHeaderFlags(t *testing.T) {
	got := parseCLIArgs([]string{
		"--run-assessment", "--target", "https://dev-emis.systems.gov.bt",
		"--auth-header-file", "cookie.txt",
		"--auth-verify-url=https://dev-emis.systems.gov.bt/dashboard/overview",
		"--auth-verify-marker", "Overview",
	})
	if got.authHeaderFile != "cookie.txt" {
		t.Fatalf("authHeaderFile = %q", got.authHeaderFile)
	}
	if got.authVerifyURL != "https://dev-emis.systems.gov.bt/dashboard/overview" {
		t.Fatalf("authVerifyURL = %q", got.authVerifyURL)
	}
	if got.authVerifyMarker != "Overview" {
		t.Fatalf("authVerifyMarker = %q", got.authVerifyMarker)
	}
	if !headerAuthRequested(got) || !cliAuthRequested(got) {
		t.Fatalf("headerAuthRequested/cliAuthRequested should be true")
	}
}

func TestApplyHeaderFileAuthWholeOriginCookie(t *testing.T) {
	dir := t.TempDir()
	cookiePath := filepath.Join(dir, "cookie.txt")
	const secret = "__Secure-next-auth.session-token=SUPERSECRETCOOKIEVALUE123456"
	os.WriteFile(cookiePath, []byte("Cookie: "+secret+"\n"), 0600)

	// A bare origin --target keeps whole-origin scope (no path).
	cfg := assessment.AssessmentConfig{
		Mode:    assessment.ModeGrayBox,
		Types:   []assessment.Type{assessment.TypeWebApplication},
		Targets: []assessment.Target{{ID: "target-1", Kind: assessment.KindURL, Value: "https://dev-emis.systems.gov.bt"}},
	}
	args := cliArgs{
		authHeaderFile:   cookiePath,
		authVerifyURL:    "https://dev-emis.systems.gov.bt/dashboard/overview",
		authVerifyMarker: "Overview",
	}
	vault, err := applyHeaderFileAuthToConfig(&cfg, args)
	if err != nil {
		t.Fatalf("applyHeaderFileAuthToConfig: %v", err)
	}
	if vault == nil {
		t.Fatalf("expected a transient vault")
	}
	if len(cfg.Access) != 1 {
		t.Fatalf("expected 1 access binding, got %d", len(cfg.Access))
	}
	b := cfg.Access[0]
	if b.Kind != assessment.AccessApplicationHeaders || b.TargetIDs[0] != "target-1" {
		t.Fatalf("unexpected binding: %+v", b)
	}
	if b.VerifyURL != "https://dev-emis.systems.gov.bt/dashboard/overview" || b.VerifyMarker != "Overview" {
		t.Fatalf("verify fields not set: %+v", b)
	}
	if cfg.WorkflowVersion != "unified-v1" {
		t.Fatalf("WorkflowVersion = %q", cfg.WorkflowVersion)
	}
	// The original target scope is untouched (no /svc rewrite).
	if cfg.Targets[0].Value != "https://dev-emis.systems.gov.bt" {
		t.Fatalf("target scope was rewritten: %q", cfg.Targets[0].Value)
	}
	// The cookie value must never appear in the serialized config.
	blob, _ := json.Marshal(cfg)
	if strings.Contains(string(blob), "SUPERSECRETCOOKIEVALUE123456") {
		t.Fatalf("cookie value leaked into config JSON")
	}
}

func TestApplyHeaderFileAuthBareTokenWrapped(t *testing.T) {
	dir := t.TempDir()
	tokPath := filepath.Join(dir, "tok.txt")
	os.WriteFile(tokPath, []byte("abc123\n"), 0600)
	cfg := assessment.AssessmentConfig{
		Targets: []assessment.Target{{ID: "target-1", Kind: assessment.KindURL, Value: "https://app.test"}},
	}
	vault, err := applyHeaderFileAuthToConfig(&cfg, cliArgs{authHeaderFile: tokPath})
	if err != nil {
		t.Fatalf("applyHeaderFileAuthToConfig: %v", err)
	}
	rec, getErr := vault.Get(cfg.Access[0].CredentialID, "target-1")
	if getErr != nil {
		t.Fatalf("credential not found in vault: %v", getErr)
	}
	if rec.Values["Authorization"] != "Bearer abc123" {
		t.Fatalf("bare token not wrapped as bearer: %v", rec.Values)
	}
}

func TestApplyHeaderFileAuthRequiresURLTarget(t *testing.T) {
	dir := t.TempDir()
	tokPath := filepath.Join(dir, "tok.txt")
	os.WriteFile(tokPath, []byte("Cookie: s=1\n"), 0600)
	// A source target (not URL) gives nothing to bind to.
	cfg := assessment.AssessmentConfig{
		Targets: []assessment.Target{{ID: "source", Kind: assessment.KindLocalSourcePath, Value: "./app"}},
	}
	if _, err := applyHeaderFileAuthToConfig(&cfg, cliArgs{authHeaderFile: tokPath}); err == nil {
		t.Fatalf("expected error with no HTTP(S) target")
	}
}

func TestApplyHeaderFileAuthRejectsExistingAccess(t *testing.T) {
	dir := t.TempDir()
	tokPath := filepath.Join(dir, "tok.txt")
	os.WriteFile(tokPath, []byte("Cookie: s=1\n"), 0600)
	cfg := assessment.AssessmentConfig{
		Targets: []assessment.Target{{ID: "target-1", Kind: assessment.KindURL, Value: "https://app.test"}},
		Access:  []assessment.AccessBinding{{TargetIDs: []string{"target-1"}, Kind: assessment.AccessApplicationHeaders}},
	}
	if _, err := applyHeaderFileAuthToConfig(&cfg, cliArgs{authHeaderFile: tokPath}); err == nil {
		t.Fatalf("expected rejection when config already has access bindings")
	}
}
