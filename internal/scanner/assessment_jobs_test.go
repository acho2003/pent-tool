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

type resourceJobRunner struct {
	calls       int
	name, alias string
	gvmID       string
}

type budgetAwareJobRunner struct{ calls int }

func (r *budgetAwareJobRunner) Name() string { return "budget-aware" }
func (r *budgetAwareJobRunner) Descriptor() Descriptor {
	return Descriptor{Name: r.Name(), Phase: PhaseWeb, Tracks: []Track{TrackWeb}}
}
func (r *budgetAwareJobRunner) Run(ctx context.Context, req Request, _ Config, _ EmitFunc) Run {
	r.calls++
	<-ctx.Done()
	return Run{Scanner: r.Name(), Target: req.Target, Status: "cancelled", Reason: ctx.Err().Error()}
}

func (r *resourceJobRunner) Name() string {
	if r.name != "" {
		return r.name
	}
	return "trivy"
}
func (r *resourceJobRunner) Descriptor() Descriptor {
	return Descriptor{Name: r.Name(), Phase: PhaseSAST, Weight: WeightLight}
}
func (r *resourceJobRunner) Run(_ context.Context, req Request, _ Config, _ EmitFunc) Run {
	r.calls++
	r.alias = req.VulsSSHHost
	r.gvmID = req.GVMSSHCredentialID
	return Run{Scanner: r.Name(), Target: req.Target, Status: "completed"}
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
	for _, id := range []string{"nuclei", "zap", "testssl", "trivy", "semgrep", "gitleaks", "osv", "masscan", "nikto", "lynis"} {
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

func TestWhiteBoxResourcePreparationAndTrivyVariants(t *testing.T) {
	source := t.TempDir()
	sbom := filepath.Join(t.TempDir(), "bom.json")
	if err := os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if reason := prepareLocalAssessmentResource(assessment.ModeWhiteBox, assessment.KindLocalSourcePath, source, "trivy"); reason != "" {
		t.Fatalf("source was skipped: %s", reason)
	}
	if reason := prepareLocalAssessmentResource(assessment.ModeWhiteBox, assessment.KindSBOM, sbom, "trivy"); reason != "" {
		t.Fatalf("SBOM was skipped: %s", reason)
	}
	if reason := prepareLocalAssessmentResource(assessment.ModeWhiteBox, assessment.KindDockerImage, "registry.test/app@sha256:"+strings.Repeat("a", 64), "trivy"); reason != "" {
		t.Fatalf("digest-pinned image was skipped: %s", reason)
	}
	for _, tc := range []struct {
		kind  assessment.TargetKind
		value string
		mode  assessment.Mode
	}{
		{assessment.KindLocalSourcePath, source, assessment.ModeBlackBox},
		{assessment.KindLocalSourcePath, filepath.Join(source, "missing"), assessment.ModeWhiteBox},
		{assessment.KindSBOM, source, assessment.ModeWhiteBox},
		{assessment.KindDockerImage, "registry.test/app:latest", assessment.ModeWhiteBox},
	} {
		if reason := prepareLocalAssessmentResource(tc.mode, tc.kind, tc.value, "trivy"); reason == "" {
			t.Fatalf("unsafe resource was prepared: %+v", tc)
		}
	}
	image := buildTrivy(Request{Target: "registry.test/app@sha256:" + strings.Repeat("a", 64), TypedAssessment: true, Artifact: Artifact{Kind: "image", Ref: "registry.test/app@sha256:" + strings.Repeat("a", 64)}, ScanDir: t.TempDir()}, Config{TrivyPath: "trivy"})
	if len(image.args) == 0 || image.args[0] != "image" {
		t.Fatalf("image used wrong command: %+v", image)
	}
	sbomCommand := buildTrivy(Request{Target: sbom, TypedAssessment: true, Artifact: Artifact{Kind: "sbom", Ref: sbom}, ScanDir: t.TempDir()}, Config{TrivyPath: "trivy"})
	if len(sbomCommand.args) == 0 || sbomCommand.args[0] != "sbom" {
		t.Fatalf("SBOM used wrong command: %+v", sbomCommand)
	}
}

func TestConditionalWhiteBoxSourceRunsAfterLocalPreparation(t *testing.T) {
	source := t.TempDir()
	runner := &resourceJobRunner{}
	pipeline := &Pipeline{Runners: []Runner{runner}}
	plan := AssessmentPlan{Config: assessment.AssessmentConfig{Mode: assessment.ModeWhiteBox, Targets: []assessment.Target{{ID: "src", Kind: assessment.KindLocalSourcePath, Value: source}}}, Fingerprint: "sha256:source", Jobs: []PlanJob{{ID: "trivy:src", Scanner: "trivy", TargetID: "src", Target: source, Variant: "trivy", State: PlanConditional}}}
	runs := pipeline.RunAssessmentJobs(t.Context(), plan, t.TempDir(), nil, nil)
	if runner.calls != 1 || len(runs) != 1 || runs[0].Status != "completed" {
		t.Fatalf("prepared source was not scanned: calls=%d runs=%+v", runner.calls, runs)
	}
	plan.Jobs[0].Target = filepath.Join(source, "missing")
	runs = pipeline.RunAssessmentJobs(t.Context(), plan, t.TempDir(), nil, nil)
	if runner.calls != 1 || len(runs) != 1 || runs[0].Status != "skipped" {
		t.Fatalf("missing source was scanned: calls=%d runs=%+v", runner.calls, runs)
	}
}

func TestTypedVulsRequiresTargetBoundSSHAlias(t *testing.T) {
	runner := &resourceJobRunner{name: "vuls"}
	plan := AssessmentPlan{Config: assessment.AssessmentConfig{Mode: assessment.ModeWhiteBox, Targets: []assessment.Target{{ID: "host", Kind: assessment.KindHost, Value: "host.example.test"}}}, Fingerprint: "sha256:ssh", Jobs: []PlanJob{{ID: "vuls:host", Scanner: "vuls", TargetID: "host", Target: "host.example.test", Variant: "vuls", State: PlanSelected}}}
	pipeline := &Pipeline{Runners: []Runner{runner}}
	runs := pipeline.RunAssessmentJobs(t.Context(), plan, t.TempDir(), nil, nil)
	if runner.calls != 0 || runs[0].Status != "skipped" {
		t.Fatalf("unbound host audit ran: %+v", runs)
	}
	pipeline.Config.AssessmentSSHAliases = map[string]string{"host": "audit-host"}
	runs = pipeline.RunAssessmentJobs(t.Context(), plan, t.TempDir(), nil, nil)
	if runner.calls != 1 || runner.alias != "audit-host" || runs[0].Status != "completed" {
		t.Fatalf("bound host audit failed: %+v alias=%s", runs, runner.alias)
	}
}

func TestTypedOpenVASDoesNotDowngradeRequestedHostCredentials(t *testing.T) {
	runner := &resourceJobRunner{name: "openvas"}
	plan := AssessmentPlan{Config: assessment.AssessmentConfig{Mode: assessment.ModeWhiteBox, Targets: []assessment.Target{{ID: "host", Kind: assessment.KindHost, Value: "host.example.test"}}}, Fingerprint: "sha256:gvm", Jobs: []PlanJob{{ID: "openvas:host", Scanner: "openvas", TargetID: "host", Target: "host.example.test", Variant: "openvas", State: PlanSelected}}}
	pipeline := &Pipeline{Config: Config{AssessmentSSHRequested: map[string]bool{"host": true}}, Runners: []Runner{runner}}
	runs := pipeline.RunAssessmentJobs(t.Context(), plan, t.TempDir(), nil, nil)
	if runner.calls != 0 || runs[0].Status != "skipped" || !strings.Contains(runs[0].Reason, "credential") {
		t.Fatalf("OpenVAS silently downgraded: %+v", runs)
	}
	pipeline.Config.AssessmentGVMSSH = map[string]GVMSSHCredential{"host": {ID: "58ff2793-2dc7-43fe-85f9-20bfac5a87e4", Port: 2222}}
	runs = pipeline.RunAssessmentJobs(t.Context(), plan, t.TempDir(), nil, nil)
	if runner.calls != 1 || runs[0].Status != "completed" || runner.gvmID != "58ff2793-2dc7-43fe-85f9-20bfac5a87e4" {
		t.Fatalf("credentialed OpenVAS job did not run: %+v", runs)
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

func TestRunAssessmentJobsSharesWebBudgetAcrossPendingStages(t *testing.T) {
	runner := &budgetAwareJobRunner{}
	pipeline := &Pipeline{Config: Config{WebBudget: 180 * time.Millisecond}, Runners: []Runner{runner}}
	plan := AssessmentPlan{Config: assessment.AssessmentConfig{}, Fingerprint: "sha256:shared-budget", Jobs: []PlanJob{
		{ID: "a", State: PlanSelected, Scanner: runner.Name(), TargetID: "app", Target: "https://app.example.test/", Variant: "a"},
		{ID: "b", State: PlanSelected, Scanner: runner.Name(), TargetID: "app", Target: "https://app.example.test/", Variant: "b"},
		{ID: "c", State: PlanSelected, Scanner: runner.Name(), TargetID: "app", Target: "https://app.example.test/", Variant: "c"},
	}}
	runs := pipeline.RunAssessmentJobs(t.Context(), plan, t.TempDir(), nil, nil)
	if runner.calls != 3 || len(runs) != 3 {
		t.Fatalf("pending stages were starved: calls=%d runs=%+v", runner.calls, runs)
	}
	for _, run := range runs[:2] {
		if run.Status != "failed" || !strings.Contains(run.Reason, "scanner stage time budget reached") {
			t.Fatalf("stage budget not recorded as partial: %+v", run)
		}
	}
}

func assessmentConfigForTest() assessment.AssessmentConfig {
	return assessment.AssessmentConfig{Profile: ProfileGentle}
}
