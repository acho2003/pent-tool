package scanner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func writeSourceTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestCodeQLDetectsOnlyBuildlessLanguagesAndReportsTheRest(t *testing.T) {
	root := writeSourceTree(t, map[string]string{
		"web/app.ts": "x", "web/util.js": "x", "api/main.py": "x", "svc/Main.java": "x",
		"native/lib.c": "x", "cmd/main.go": "x", ".github/workflows/ci.yml": "on: push",
		"node_modules/dep/index.js": "x", "vendor/lib/x.py": "x",
	})
	detection := detectCodeQLLanguages(root)
	want := map[string]int{"javascript-typescript": 2, "python": 1, "java-kotlin": 1, "actions": 1}
	for language, count := range want {
		if detection.Supported[language] != count {
			t.Errorf("%s: got %d want %d (%+v)", language, detection.Supported[language], count, detection.Supported)
		}
	}
	if len(detection.Supported) != len(want) {
		t.Errorf("unexpected languages, vendored code must be skipped: %+v", detection.Supported)
	}
	if detection.Gaps["C/C++"] != 1 || detection.Gaps["Go"] != 1 {
		t.Errorf("languages that need a build must be reported as gaps: %+v", detection.Gaps)
	}
}

func TestCodeQLIsUnavailableWithoutBinaryOrLicense(t *testing.T) {
	found := func(string) (string, error) { return "/opt/codeql/codeql", nil }
	missing := func(string) (string, error) { return "", errors.New("not found") }
	if reason := CodeQLUnavailableReason("codeql", true, missing); !strings.Contains(reason, "not bundled") {
		t.Fatalf("missing binary: %q", reason)
	}
	if reason := CodeQLUnavailableReason("codeql", false, found); !strings.Contains(reason, "XALGORIX_CODEQL_LICENSE_ACCEPTED") {
		t.Fatalf("an unconfirmed license must keep CodeQL unavailable: %q", reason)
	}
	if reason := CodeQLUnavailableReason("codeql", true, found); reason != "" {
		t.Fatalf("binary plus confirmed license is available: %q", reason)
	}
	run := codeqlRunner{}.Run(context.Background(), Request{Target: t.TempDir(), ScanDir: t.TempDir()}, Config{CodeQLPath: "/bin/sh"}, nil)
	if run.Status != "not_applicable" || !strings.Contains(run.Reason, "LICENSE_ACCEPTED") {
		t.Fatalf("the runner itself must refuse without the license confirmation: %s %s", run.Status, run.Reason)
	}
}

// fakeCodeQL creates a database directory on "create" and writes a SARIF
// document on "analyze"; it fails creation for Java to exercise a gap.
func fakeCodeQL(t *testing.T) string {
	t.Helper()
	script := filepath.Join(t.TempDir(), "codeql")
	sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL","rules":[{"id":"js/sql-injection","name":"js/sql-injection","shortDescription":{"text":"Database query built from user-controlled sources"},"fullDescription":{"text":"Building a database query from user-controlled sources is vulnerable to insertion of malicious code by the user."},"properties":{"security-severity":"8.8","precision":"high","tags":["security","external/cwe/cwe-089","external/cwe/cwe-090"]}}]}},"results":[{"ruleId":"js/sql-injection","ruleIndex":0,"level":"error","message":{"text":"This query string depends on a user-provided value."},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"web/app.js"},"region":{"startLine":12}}}]}]}]}`
	body := `#!/bin/sh
case "$1 $2" in
"database create")
  case "$*" in *--language=java-kotlin*) echo "extractor failed" >&2; exit 32;; esac
  mkdir -p "$3"; echo created; exit 0;;
"database analyze")
  for arg in "$@"; do case "$arg" in --output=*) out="${arg#--output=}";; esac; done
  [ -d "$3" ] || { echo "no database" >&2; exit 2; }
  printf '%s' '` + sarif + `' > "$out"; exit 0;;
esac
exit 1
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return script
}

func TestCodeQLRunnerAnalyzesEachLanguageAndRecordsGaps(t *testing.T) {
	source := writeSourceTree(t, map[string]string{"web/app.js": "x", "svc/Main.java": "x", "cmd/main.go": "x"})
	scanDir := t.TempDir()
	run := codeqlRunner{}.Run(context.Background(), Request{Target: source, ScanDir: scanDir, Scope: "source:repo"}, Config{CodeQLPath: fakeCodeQL(t), CodeQLLicenseAccepted: true}, nil)
	if run.Status != "completed" || run.Completeness != "partial" || run.Outcome != "PARTIAL" {
		t.Fatalf("one analyzed language with gaps is a partial completed run: %s %s %s %s", run.Status, run.Completeness, run.Outcome, run.Reason)
	}
	reasons := ""
	for _, limitation := range run.Limitations {
		reasons += limitation.Reason + "\n"
	}
	if !strings.Contains(reasons, "java-kotlin database creation failed") || !strings.Contains(reasons, "Go (1 files) needs a build toolchain") {
		t.Fatalf("failed and unsupported languages must be explicit gaps: %s", reasons)
	}
	findings, err := ParseRun(run)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected the JavaScript result: %+v", findings)
	}
	f := findings[0]
	if f.Severity != "high" || f.CWE != "CWE-89" || f.SourceLocation != "web/app.js:12" || f.RuleID != "js/sql-injection" || f.Title != "Database query built from user-controlled sources" || f.Confidence != "high" {
		t.Fatalf("SARIF result mapped incorrectly: %+v", f)
	}
	matches, _ := filepath.Glob(filepath.Join(scanDir, "scanner-output", "codeql", "db-*"))
	if len(matches) != 0 {
		t.Fatalf("databases hold a full source copy and must be removed: %v", matches)
	}
}

func TestCodeQLSeverityFollowsSecuritySeverity(t *testing.T) {
	for _, tc := range []struct{ score, level, want string }{
		{"9.8", "error", "critical"}, {"7.5", "warning", "high"}, {"5.0", "error", "medium"}, {"2.0", "note", "low"},
		{"", "error", "medium"}, {"", "warning", "low"}, {"", "note", "info"},
	} {
		if got := codeqlSeverity(tc.score, tc.level); got != tc.want {
			t.Errorf("%q/%q: got %s want %s", tc.score, tc.level, got, tc.want)
		}
	}
}

func TestCodeQLIsSelectedOnlyWhenTheOperatorEnabledIt(t *testing.T) {
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeWhiteBox, Types: []assessment.Type{assessment.TypeSourceCode},
		Targets: []assessment.Target{{ID: "repo", Kind: assessment.KindRepository, Value: "https://example.test/org/repo.git"}}}
	stateOf := func(available bool) PlanState {
		plan := PlanAssessment(PlanInput{Config: cfg, Availability: map[string]bool{"codeql": available}})
		for _, decision := range plan.Decisions {
			if decision.Scanner == "codeql" && decision.TargetID == "repo" {
				return decision.State
			}
		}
		t.Fatalf("no CodeQL decision: errors=%+v", plan.Errors)
		return ""
	}
	if state := stateOf(false); state != PlanUnavailable {
		t.Fatalf("without the operator's CLI and license CodeQL is unavailable, got %q", state)
	}
	if state := stateOf(true); state != PlanSelected {
		t.Fatalf("an enabled CodeQL must be selected for source assessments, got %q", state)
	}
}
