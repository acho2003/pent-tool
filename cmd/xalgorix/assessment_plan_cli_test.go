package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestParseAssessmentPlanFlags(t *testing.T) {
	got := parseCLIArgs([]string{"--plan", "--assessment-mode", "GRAY_BOX", "--assessment-type=API,WEB_APPLICATION", "--assessment-config", "plan.json", "--target", "https://example.test/Case"})
	if !got.plan || got.assessmentMode != "GRAY_BOX" || got.assessmentConfig != "plan.json" {
		t.Fatalf("unexpected plan flags: %+v", got)
	}
	if len(got.assessmentTypes) != 2 || got.assessmentTypes[0] != "API" || got.assessmentTypes[1] != "WEB_APPLICATION" {
		t.Fatalf("assessment types = %v", got.assessmentTypes)
	}
	if len(got.targets) != 1 || got.targets[0] != "https://example.test/Case" {
		t.Fatalf("targets = %v", got.targets)
	}
}

func TestParseTypedAssessmentExecutionFlag(t *testing.T) {
	got := parseCLIArgs([]string{"--run-assessment", "--assessment-config=assessment.json"})
	if !got.runAssessment || got.assessmentConfig != "assessment.json" {
		t.Fatalf("unexpected typed execution flags: %+v", got)
	}
}

func TestExecuteAssessmentCLIUsesPlannerRunnerAndStructuredOutput(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "nuclei-fixture")
	script := `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-jle" ]; then
    shift
    printf '%s\n' '{"template-id":"fixture-xss","matched-at":"https://192.0.2.1/","host":"192.0.2.1","info":{"name":"Fixture XSS","severity":"high"}}' > "$1"
  fi
  shift
done
`
	if err := os.WriteFile(tool, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "assessment.json")
	assessmentJSON := `{"assessment_mode":"BLACK_BOX","assessment_types":["WEB_APPLICATION"],"assessment_targets":[{"id":"app","type":"URL","value":"https://192.0.2.1/"}]}`
	if err := os.WriteFile(configPath, []byte(assessmentJSON), 0600); err != nil {
		t.Fatal(err)
	}
	appConfig := &config.Config{DataDir: filepath.Join(dir, "data"), NucleiPath: tool, RateLimitRPS: 2, ScannerMaxOutputBytes: 1 << 20, NucleiTimeoutSec: 30}
	var output bytes.Buffer
	err := executeAssessmentCLI(cliArgs{assessmentConfig: configPath}, appConfig, &output)
	if err != nil {
		t.Fatal(err)
	}
	var result assessmentCLIResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON result: %v\n%s", err, output.String())
	}
	if result.State != "complete" || len(result.Runs) != 1 || result.Runs[0].Scanner != "nuclei" || result.Runs[0].Status != "completed" || len(result.Findings) != 1 || result.Findings[0].Title != "Fixture XSS" {
		t.Fatalf("unexpected CLI assessment result: %+v", result)
	}
	if !strings.HasPrefix(result.Runs[0].Scope, "app:") || result.Plan.Fingerprint == "" {
		t.Fatalf("assessment output lost application scope or plan identity: %+v", result)
	}
}

func TestExecuteAssessmentCLIRefusesLocalAndCredentialedTargets(t *testing.T) {
	dir := t.TempDir()
	writeConfig := func(name, contents string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	appConfig := &config.Config{DataDir: filepath.Join(dir, "data"), AllowLocalTargets: false}
	local := writeConfig("local.json", `{"assessment_mode":"BLACK_BOX","assessment_types":["WEB_APPLICATION"],"assessment_targets":[{"id":"app","type":"URL","value":"http://127.0.0.1/"}]}`)
	if err := executeAssessmentCLI(cliArgs{assessmentConfig: local}, appConfig, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "local-target policy") {
		t.Fatalf("local target error = %v", err)
	}
	credentialed := writeConfig("credentialed.json", `{"assessment_mode":"GRAY_BOX","assessment_types":["WEB_APPLICATION"],"assessment_targets":[{"id":"app","type":"URL","value":"https://192.0.2.1/"}],"access":[{"target_ids":["app"],"kind":"APPLICATION_HEADERS","credential_id":"cred"}]}`)
	if err := executeAssessmentCLI(cliArgs{assessmentConfig: credentialed}, appConfig, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "cannot resolve credential references") {
		t.Fatalf("credential config error = %v", err)
	}
}

func TestInferAssessmentTargetKindPreservesApplicationURLs(t *testing.T) {
	cases := map[string]assessment.TargetKind{
		"https://example.test:8443/Portal/Case": assessment.KindURL,
		"192.0.2.8":                             assessment.KindIP,
		"192.0.2.0/24":                          assessment.KindCIDR,
		"app.example.test":                      assessment.KindDomain,
	}
	for input, want := range cases {
		if got := inferAssessmentTargetKind(input); got != want {
			t.Errorf("inferAssessmentTargetKind(%q) = %s, want %s", input, got, want)
		}
	}
}
