package scanner

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

type assessmentJobRunner struct {
	calls  int
	target string
	scope  string
	dir    string
	delay  time.Duration
}

func (r *assessmentJobRunner) Name() string { return "assessment-test" }
func (r *assessmentJobRunner) Descriptor() Descriptor {
	return Descriptor{Name: r.Name(), Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightLight}
}
func (r *assessmentJobRunner) Run(_ context.Context, req Request, _ Config, _ EmitFunc) Run {
	r.calls++
	r.target, r.scope, r.dir = req.Target, req.Scope, req.ScanDir
	if r.delay > 0 {
		time.Sleep(r.delay)
	}
	if req.ApplicationURL != req.Target {
		return Run{Scanner: r.Name(), Target: req.Target, Status: "failed", Reason: "exact URL not passed"}
	}
	artifact := filepath.Join(req.ScanDir, "result.json")
	if err := os.WriteFile(artifact, []byte(`{"ok":true}`), 0600); err != nil {
		return Run{Scanner: r.Name(), Target: req.Target, Status: "failed", Reason: err.Error()}
	}
	return finalizeRun(Run{Scanner: r.Name(), Target: req.Target, Scope: req.Scope, Status: "completed", ArtifactPath: artifact})
}

func TestRunAssessmentJobsUsesExactApplicationURLAndChecksumResume(t *testing.T) {
	target := "https://Example.test:8443/Portal/CaseSensitive"
	runner := &assessmentJobRunner{}
	pipeline := &Pipeline{Runners: []Runner{runner}}
	plan := AssessmentPlan{Config: assessmentConfigForTest(), Fingerprint: "sha256:plan-a", Jobs: []PlanJob{{ID: "assessment-test:app:assessment-test", State: PlanSelected, Scanner: runner.Name(), TargetID: "app", Target: target, AssessmentType: assessment.TypeWebApplication, AssessmentTypes: []assessment.Type{assessment.TypeWebApplication, assessment.TypeAPI}, Variant: runner.Name()}}}
	root := t.TempDir()
	first := pipeline.RunAssessmentJobs(context.Background(), plan, root, nil, nil)
	if len(first) != 1 || first[0].Status != "completed" {
		t.Fatalf("first execution = %+v", first)
	}
	if runner.target != target || runner.scope != "app:app" || strings.Contains(runner.dir, "Example.test") {
		t.Fatalf("application target was not preserved and isolated: target=%q scope=%q dir=%q", runner.target, runner.scope, runner.dir)
	}
	if first[0].Variant != runner.Name() {
		t.Fatalf("run variant = %q, want %q", first[0].Variant, runner.Name())
	}
	if first[0].AttemptID == "" || first[0].PlanFingerprint != plan.Fingerprint || !slices.Equal(first[0].AssessmentTypes, []assessment.Type{assessment.TypeWebApplication, assessment.TypeAPI}) {
		t.Fatalf("run lacks plan, attempt, or coverage identity: %+v", first[0])
	}
	second := pipeline.RunAssessmentJobs(context.Background(), plan, root, first, nil)
	if len(second) != 1 || second[0].Status != "completed" || runner.calls != 1 {
		t.Fatalf("valid completed job was not resumed: runs=%+v calls=%d", second, runner.calls)
	}
	changedPlan := plan
	changedPlan.Fingerprint = "sha256:changed-configuration"
	changed := pipeline.RunAssessmentJobs(context.Background(), changedPlan, root, first, nil)
	if len(changed) != 1 || runner.calls != 2 || changed[0].PlanFingerprint != changedPlan.Fingerprint {
		t.Fatalf("changed plan incorrectly reused prior evidence: runs=%+v calls=%d", changed, runner.calls)
	}

	data, err := os.ReadFile(first[0].ArtifactPath)
	if err != nil {
		t.Fatal(err)
	}
	data[0] = ' '
	if err := os.WriteFile(first[0].ArtifactPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	third := pipeline.RunAssessmentJobs(context.Background(), plan, root, first, nil)
	if len(third) != 1 || runner.calls != 3 || third[0].ArtifactPath == first[0].ArtifactPath {
		t.Fatalf("checksum mismatch did not rerun job: runs=%+v calls=%d", third, runner.calls)
	}
	if _, err := os.Stat(first[0].ArtifactPath); err != nil {
		t.Fatalf("retry overwrote or removed prior evidence: %v", err)
	}
}

func TestTypedPlannerAdapterAvailabilityExcludesLegacyReconStubs(t *testing.T) {
	for _, id := range []string{"subfinder", "httpx", "nmap"} {
		if HasAssessmentRunner(id) {
			t.Fatalf("%s unexpectedly has a direct typed assessment adapter", id)
		}
	}
	for _, id := range []string{"nuclei", "zap", "testssl", "trivy", "semgrep", "gitleaks", "osv"} {
		if !HasAssessmentRunner(id) {
			t.Fatalf("%s should have a typed assessment adapter", id)
		}
	}
}

func TestRunAssessmentJobsDoesNotRunConditionalJobsBeforePreparation(t *testing.T) {
	runner := &assessmentJobRunner{}
	pipeline := &Pipeline{Runners: []Runner{runner}}
	plan := AssessmentPlan{Config: assessmentConfigForTest(), Fingerprint: "sha256:conditional", Jobs: []PlanJob{{ID: "assessment-test:app:WEB_APPLICATION", State: PlanConditional, Scanner: runner.Name(), TargetID: "app", Target: "https://app.example.test/", Variant: runner.Name()}}}
	runs := pipeline.RunAssessmentJobs(context.Background(), plan, t.TempDir(), nil, nil)
	if len(runs) != 1 || runs[0].Status != "skipped" || !strings.Contains(runs[0].Reason, "preparation") || runner.calls != 0 {
		t.Fatalf("conditional job ran before preparation: runs=%+v calls=%d", runs, runner.calls)
	}
}

func TestRunAssessmentJobsStopsPerTargetAtWebBudget(t *testing.T) {
	runner := &assessmentJobRunner{delay: 15 * time.Millisecond}
	pipeline := &Pipeline{Config: Config{WebBudget: 5 * time.Millisecond}, Runners: []Runner{runner}}
	plan := AssessmentPlan{Config: assessmentConfigForTest(), Fingerprint: "sha256:budget", Jobs: []PlanJob{
		{ID: "first", State: PlanSelected, Scanner: runner.Name(), TargetID: "app", Target: "https://app.example.test/", Variant: "first"},
		{ID: "second", State: PlanSelected, Scanner: runner.Name(), TargetID: "app", Target: "https://app.example.test/", Variant: "second"},
	}}
	plan.Config.Profile = "" // preserve the injected short budget for this test
	runs := pipeline.RunAssessmentJobs(context.Background(), plan, t.TempDir(), nil, nil)
	if len(runs) != 2 || runs[0].Reason != "web profile time budget exhausted; assessment coverage is partial" || runs[1].Status != "skipped" || !strings.Contains(runs[1].Reason, "budget exhausted") || runner.calls != 1 {
		t.Fatalf("web budget was not enforced for the full target stage: runs=%+v calls=%d", runs, runner.calls)
	}
}

func assessmentConfigForTest() assessment.AssessmentConfig {
	return assessment.AssessmentConfig{Profile: ProfileGentle}
}
