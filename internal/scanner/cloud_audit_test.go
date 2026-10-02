package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func awsCred() CloudCredential {
	return CloudCredential{Provider: "aws", Env: map[string]string{
		"AWS_ACCESS_KEY_ID":     "AKIAEXAMPLE",
		"AWS_SECRET_ACCESS_KEY": "supersecretvalue",
	}}
}

func TestBuildProwler_CredsViaEnvNotArgv(t *testing.T) {
	req := Request{ScanDir: t.TempDir(), CloudCredential: awsCred()}
	spec := buildProwler(req, Config{ProwlerPath: "/usr/bin/prowler", ProwlerTimeout: time.Minute})
	if spec.notApp != "" {
		t.Fatalf("unexpected notApp: %s", spec.notApp)
	}
	// Secret must be in env, never in argv.
	joined := strings.Join(spec.args, " ")
	if strings.Contains(joined, "supersecretvalue") || strings.Contains(joined, "AKIAEXAMPLE") {
		t.Errorf("credentials leaked into argv: %s", joined)
	}
	foundSecretEnv := false
	for _, e := range spec.env {
		if e == "AWS_SECRET_ACCESS_KEY=supersecretvalue" {
			foundSecretEnv = true
		}
	}
	if !foundSecretEnv {
		t.Errorf("credential not passed via env: %v", spec.env)
	}
	if !hasArg(spec.args, "aws") || !hasArg(spec.args, "json-ocsf") {
		t.Errorf("expected read-only aws json-ocsf run; args=%v", spec.args)
	}
}

func TestBuildProwler_NotApplicableWithoutCreds(t *testing.T) {
	spec := buildProwler(Request{ScanDir: t.TempDir()}, Config{ProwlerPath: "prowler", ProwlerTimeout: time.Minute})
	if spec.notApp == "" {
		t.Error("expected notApp without a resolved cloud credential")
	}
}

func TestCredentialSecretValues_ForRedaction(t *testing.T) {
	vals := credentialSecretValues(awsCred())
	if len(vals) != 2 {
		t.Fatalf("want 2 secret values, got %v", vals)
	}
	joined := strings.Join(vals, " ")
	if !strings.Contains(joined, "supersecretvalue") {
		t.Errorf("secret value missing from redaction set: %v", vals)
	}
}

func TestParseProwler_OnlyFailFindings(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "results.ocsf.json")
	body := `[
	  {"status_code":"FAIL","severity":"High","finding_info":{"title":"S3 bucket public","uid":"s3_bucket_public"},"remediation":{"desc":"block public access"},"resources":[{"uid":"arn:aws:s3:::demo"}]},
	  {"status_code":"PASS","severity":"High","finding_info":{"title":"IAM MFA","uid":"iam_mfa"}}
	]`
	if err := os.WriteFile(art, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := parseProwler(art)
	if err != nil {
		t.Fatalf("parseProwler: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding (FAIL only), got %d", len(findings))
	}
	f := findings[0]
	if f.Scanner != "prowler" || f.Severity != "high" || f.Endpoint != "arn:aws:s3:::demo" {
		t.Errorf("unexpected finding: %+v", f)
	}
}

func TestBuildScoutSuite_ProviderAndEnv(t *testing.T) {
	spec := buildScoutSuite(Request{ScanDir: t.TempDir(), CloudCredential: awsCred()}, Config{ScoutSuitePath: "/usr/bin/scout", ScoutSuiteTimeout: time.Minute})
	if spec.notApp != "" {
		t.Fatalf("unexpected notApp: %s", spec.notApp)
	}
	if !hasArg(spec.args, "aws") || !hasArg(spec.args, "--no-browser") {
		t.Errorf("expected read-only aws --no-browser run; args=%v", spec.args)
	}
	if strings.Contains(strings.Join(spec.args, " "), "supersecretvalue") {
		t.Errorf("credential leaked into argv")
	}
}

func TestBuildScoutSuite_UnsupportedProvider(t *testing.T) {
	spec := buildScoutSuite(Request{ScanDir: t.TempDir(), CloudCredential: CloudCredential{Provider: "oracle", Env: map[string]string{"X": "y"}}}, Config{ScoutSuitePath: "scout", ScoutSuiteTimeout: time.Minute})
	if spec.notApp == "" {
		t.Error("expected notApp for an unsupported provider")
	}
}

func TestParseScoutSuite_FlaggedFindings(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "scoutsuite_results_aws.js")
	// Includes the JS variable prefix to exercise the stripping path.
	body := `scoutsuite_results =
{"services":{"s3":{"findings":{"s3-bucket-world-listing":{"description":"World-listable bucket","rationale":"public","remediation":"restrict ACL","level":"danger","flagged_items":3},"s3-noissue":{"description":"none","level":"warning","flagged_items":0}}}}}`
	if err := os.WriteFile(art, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := parseScoutSuite(art)
	if err != nil {
		t.Fatalf("parseScoutSuite: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 flagged finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Scanner != "scoutsuite" || f.Severity != "high" || f.Endpoint != "s3" {
		t.Errorf("unexpected finding: %+v", f)
	}
}
