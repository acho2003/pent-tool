package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestParseSharedTokenFlags(t *testing.T) {
	got := parseCLIArgs([]string{
		"--run-assessment", "--system-template", "emis.json",
		"--services", "common,academic", "--services=student",
		"--base-override", "https://staging.test", "--shared-token-file=tok.txt",
	})
	if got.systemTemplate != "emis.json" || got.baseOverride != "https://staging.test" || got.sharedTokenFile != "tok.txt" {
		t.Fatalf("unexpected flags: %+v", got)
	}
	if len(got.services) != 3 || got.services[0] != "common" || got.services[2] != "student" {
		t.Fatalf("services = %v", got.services)
	}
	if !sharedTokenRequested(got) {
		t.Fatalf("sharedTokenRequested should be true")
	}
}

func TestParseSharedTokenFileFormats(t *testing.T) {
	dir := t.TempDir()
	// Bare token wrapped with header name/prefix.
	bare := filepath.Join(dir, "bare.txt")
	os.WriteFile(bare, []byte("abc123\n"), 0600)
	values, err := parseSharedTokenFile(bare, "Authorization", "Bearer ")
	if err != nil {
		t.Fatal(err)
	}
	if values["Authorization"] != "Bearer abc123" {
		t.Fatalf("bare token not wrapped: %v", values)
	}
	// Explicit header lines.
	hdr := filepath.Join(dir, "hdr.txt")
	os.WriteFile(hdr, []byte("# comment\nAuthorization: Bearer xyz\nCookie: s=1\n"), 0600)
	values, err = parseSharedTokenFile(hdr, "Authorization", "Bearer ")
	if err != nil {
		t.Fatal(err)
	}
	if values["Authorization"] != "Bearer xyz" || values["Cookie"] != "s=1" {
		t.Fatalf("header lines not parsed: %v", values)
	}
	// Empty file is rejected.
	empty := filepath.Join(dir, "empty.txt")
	os.WriteFile(empty, []byte("\n  \n"), 0600)
	if _, err := parseSharedTokenFile(empty, "Authorization", "Bearer "); err == nil {
		t.Fatalf("expected error for empty token file")
	}
}

func writeTemplate(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "emis.json")
	body := `{"name":"EMIS","base_url":"https://dev-emis.systems.gov.bt","path_template":"/svc/{name}","verify_template":"/svc/{name}/health"}`
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExpandSystemTemplateIntoConfigStagesToken(t *testing.T) {
	dir := t.TempDir()
	tplPath := writeTemplate(t, dir)
	tokPath := filepath.Join(dir, "tok.txt")
	os.WriteFile(tokPath, []byte("SUPERSECRETTOKENVALUE123456\n"), 0600)

	cfg := assessment.AssessmentConfig{Mode: assessment.ModeGrayBox, Types: []assessment.Type{assessment.TypeAPI}}
	args := cliArgs{systemTemplate: tplPath, services: []string{"common", "academic"}, sharedTokenFile: tokPath}
	vault, err := expandSystemTemplateIntoConfig(&cfg, args)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if vault == nil {
		t.Fatalf("expected a transient vault")
	}
	if len(cfg.Targets) != 2 || len(cfg.Services) != 2 || len(cfg.Access) != 2 {
		t.Fatalf("expected 2 targets/services/access, got %d/%d/%d", len(cfg.Targets), len(cfg.Services), len(cfg.Access))
	}
	if cfg.WorkflowVersion != "unified-v1" {
		t.Fatalf("WorkflowVersion = %q", cfg.WorkflowVersion)
	}
	if cfg.Access[0].VerifyURL != "https://dev-emis.systems.gov.bt/svc/common/health" {
		t.Fatalf("unexpected verify URL %q", cfg.Access[0].VerifyURL)
	}

	// The token value must never appear in the serialized config.
	blob, _ := json.Marshal(cfg)
	if strings.Contains(string(blob), "SUPERSECRETTOKENVALUE123456") {
		t.Fatalf("token value leaked into config JSON")
	}
}

func TestExpandSystemTemplateIntoConfigNoTokenIsUnauthenticated(t *testing.T) {
	dir := t.TempDir()
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeGrayBox, Types: []assessment.Type{assessment.TypeAPI}}
	args := cliArgs{systemTemplate: writeTemplate(t, dir), services: []string{"common"}}
	vault, err := expandSystemTemplateIntoConfig(&cfg, args)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if vault != nil {
		t.Fatalf("expected no vault without a token file")
	}
	if len(cfg.Targets) != 1 || len(cfg.Access) != 0 {
		t.Fatalf("expected 1 target and no access bindings, got %d/%d", len(cfg.Targets), len(cfg.Access))
	}
}

func TestExpandSystemTemplateIntoConfigRejectsExistingAccess(t *testing.T) {
	dir := t.TempDir()
	cfg := assessment.AssessmentConfig{Access: []assessment.AccessBinding{{TargetIDs: []string{"x"}, Kind: assessment.AccessApplicationHeaders}}}
	args := cliArgs{systemTemplate: writeTemplate(t, dir), services: []string{"common"}}
	if _, err := expandSystemTemplateIntoConfig(&cfg, args); err == nil {
		t.Fatalf("expected rejection when config already has access bindings")
	}
}
