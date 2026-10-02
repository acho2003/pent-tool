package scanner

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

// fakeGit puts a stub `git` first on PATH that records its argv and GIT_*
// environment, then either creates the checkout (.git) or fails with stderr.
func fakeGit(t *testing.T, exitCode int, stderr string) string {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "git.log")
	script := fmt.Sprintf(`#!/bin/sh
{ echo "ARGS: $*"; env | grep -E '^(GIT_|GCM_)'; } >> %q
if [ %d -ne 0 ]; then echo %q >&2; exit %d; fi
for last; do :; done
mkdir -p "$last/.git"
`, logPath, exitCode, stderr, exitCode)
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

func TestCloneRepositoryTargetPassesTokenOnlyAsHostScopedHeader(t *testing.T) {
	logPath := fakeGit(t, 0, "")
	dest := filepath.Join(t.TempDir(), "checkout")
	dir, reason := cloneRepositoryTarget(context.Background(), dest, "https://github.com/org/private.git", RepoCredential{Token: "ghp_secretvalue"})
	if reason != "" || dir != dest {
		t.Fatalf("clone = %q, %q", dir, reason)
	}
	log, _ := os.ReadFile(logPath)
	args := ""
	for _, line := range strings.Split(string(log), "\n") {
		if strings.HasPrefix(line, "ARGS: ") {
			args = line
		}
	}
	if !strings.Contains(args, "clone --depth 1") || strings.Contains(args, "ghp_secretvalue") {
		t.Fatalf("token must not be in argv: %q", args)
	}
	basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:ghp_secretvalue"))
	for _, want := range []string{"GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_KEY_0=http.https://github.com/.extraheader", "GIT_CONFIG_VALUE_0=Authorization: Basic " + basic} {
		if !strings.Contains(string(log), want) {
			t.Fatalf("git env missing %q:\n%s", want, log)
		}
	}
}

func TestCloneRepositoryTargetRejectsListsAndUnsafeURLs(t *testing.T) {
	logPath := fakeGit(t, 0, "")
	for _, raw := range []string{
		"https://github.com/a/one.git, https://github.com/a/two.git",
		"https://user:token@github.com/a/one.git",
		"git@github.com:a/one.git",
		"http://github.com/a/one.git",
	} {
		if _, reason := cloneRepositoryTarget(context.Background(), filepath.Join(t.TempDir(), "checkout"), raw, RepoCredential{}); reason == "" {
			t.Fatalf("unsafe repository was cloned: %q", raw)
		}
	}
	if _, err := os.Stat(logPath); err == nil {
		t.Fatal("git ran for a rejected repository URL")
	}
}

func TestCloneRepositoryTargetExplainsRefusalWithoutSecret(t *testing.T) {
	fakeGit(t, 128, "fatal: could not read Username for 'https://github.com': terminal prompts disabled")
	dest := filepath.Join(t.TempDir(), "checkout")
	if _, reason := cloneRepositoryTarget(context.Background(), dest, "https://github.com/org/private.git", RepoCredential{}); !strings.Contains(reason, "add a read-only access token") {
		t.Fatalf("anonymous refusal reason = %q", reason)
	}
	fakeGit(t, 128, "remote: Repository not found.")
	_, reason := cloneRepositoryTarget(context.Background(), dest, "https://github.com/org/private.git", RepoCredential{Token: "ghp_secretvalue"})
	if !strings.Contains(reason, "access token cannot read") || strings.Contains(reason, "ghp_secretvalue") {
		t.Fatalf("token refusal reason = %q", reason)
	}
	if _, err := os.Stat(dest); err == nil {
		t.Fatal("failed clone left a partial checkout behind")
	}
}

type targetCaptureRunner struct {
	name    string
	targets []string
}

func (r *targetCaptureRunner) Name() string { return r.name }
func (r *targetCaptureRunner) Descriptor() Descriptor {
	return Descriptor{Name: r.name, Phase: PhaseSAST, Weight: WeightLight}
}
func (r *targetCaptureRunner) Run(_ context.Context, req Request, _ Config, _ EmitFunc) Run {
	r.targets = append(r.targets, req.Target)
	return Run{Scanner: r.name, Target: req.Target, Status: "completed"}
}

func TestRunAssessmentJobsClonesRepositoryOnceForSourceScanners(t *testing.T) {
	logPath := fakeGit(t, 0, "")
	repo := "https://github.com/org/private.git"
	trivy, gitleaks := &targetCaptureRunner{name: "trivy"}, &targetCaptureRunner{name: "gitleaks"}
	pipeline := &Pipeline{Runners: []Runner{trivy, gitleaks}, Config: Config{AssessmentRepoCreds: map[string]RepoCredential{"repo": {Token: "ghp_secretvalue"}}}}
	plan := AssessmentPlan{
		Config:      assessment.AssessmentConfig{Mode: assessment.ModeWhiteBox, Targets: []assessment.Target{{ID: "repo", Kind: assessment.KindRepository, Value: repo}}},
		Fingerprint: "sha256:repo",
		Jobs: []PlanJob{
			{ID: "trivy:repo", Scanner: "trivy", TargetID: "repo", Target: repo, Variant: "trivy", State: PlanConditional},
			{ID: "gitleaks:repo", Scanner: "gitleaks", TargetID: "repo", Target: repo, Variant: "gitleaks", State: PlanConditional},
		},
	}
	root := t.TempDir()
	runs := pipeline.RunAssessmentJobs(t.Context(), plan, root, nil, nil)
	checkout := repositoryCheckoutDir(root, "repo")
	if len(runs) != 2 {
		t.Fatalf("runs = %+v", runs)
	}
	for i, runner := range []*targetCaptureRunner{trivy, gitleaks} {
		if len(runner.targets) != 1 || runner.targets[0] != checkout {
			t.Fatalf("%s scanned %v, want the checkout %s", runner.name, runner.targets, checkout)
		}
		if runs[i].Status != "completed" || runs[i].Target != repo {
			t.Fatalf("run should report the repository URL for coverage: %+v", runs[i])
		}
	}
	log, _ := os.ReadFile(logPath)
	if n := strings.Count(string(log), "ARGS: "); n != 1 {
		t.Fatalf("repository cloned %d times, want once", n)
	}
}

func TestRunAssessmentJobsReportsRepositoryCloneRefusal(t *testing.T) {
	fakeGit(t, 128, "fatal: could not read Username for 'https://github.com': terminal prompts disabled")
	repo := "https://github.com/org/private.git"
	trivy := &targetCaptureRunner{name: "trivy"}
	pipeline := &Pipeline{Runners: []Runner{trivy}}
	plan := AssessmentPlan{
		Config:      assessment.AssessmentConfig{Mode: assessment.ModeWhiteBox, Targets: []assessment.Target{{ID: "repo", Kind: assessment.KindRepository, Value: repo}}},
		Fingerprint: "sha256:repo-refused",
		Jobs:        []PlanJob{{ID: "trivy:repo", Scanner: "trivy", TargetID: "repo", Target: repo, Variant: "trivy", State: PlanConditional}},
	}
	runs := pipeline.RunAssessmentJobs(t.Context(), plan, t.TempDir(), nil, nil)
	if len(trivy.targets) != 0 || len(runs) != 1 || !strings.Contains(runs[0].Reason, "private or does not exist") {
		t.Fatalf("refused clone should explain itself without running the scanner: calls=%d runs=%+v", len(trivy.targets), runs)
	}
}
