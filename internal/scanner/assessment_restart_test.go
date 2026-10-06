package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

type restartFixtureRunner struct {
	name          string
	calls         int
	interrupt     context.CancelFunc
	checkpointDir string
	t             *testing.T
}

func (r *restartFixtureRunner) Name() string { return r.name }
func (r *restartFixtureRunner) Descriptor() Descriptor {
	return Descriptor{Name: r.name, Phase: PhaseWeb}
}
func (r *restartFixtureRunner) Run(ctx context.Context, req Request, _ Config, _ EmitFunc) Run {
	r.calls++
	if r.checkpointDir != "" {
		manifest, ok := LoadWorkflowManifest(r.checkpointDir)
		if !ok {
			r.t.Fatal("completed job checkpoint absent during next job")
		}
		stage, ok := manifest.Stage(StageTemplates)
		if !ok || stage.Status != StageStatusRunning || len(stage.OutputChecksums) != 1 {
			r.t.Fatalf("unfinished stage claimed complete: %+v", stage)
		}
	}
	if r.interrupt != nil {
		r.interrupt()
		return Run{Scanner: r.name, Status: "cancelled", Reason: ctx.Err().Error()}
	}
	artifact := filepath.Join(req.ScanDir, "result.json")
	if err := os.WriteFile(artifact, []byte(`{"fixture":"saved native record"}`), 0600); err != nil {
		r.t.Fatal(err)
	}
	return finalizeRun(Run{Scanner: r.name, Status: "completed", ArtifactPath: artifact, Target: req.Target, Scope: req.Scope})
}

func TestExpandedExecutionRestartUsesOnlySealedCompletedAttempts(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	root := t.TempDir()
	plan := AssessmentPlan{Fingerprint: "sha256:restart-fixture", RegistryVersion: PlanRegistryVersion, Config: assessment.AssessmentConfig{WorkflowVersion: "unified-v1"}}
	for _, name := range []string{"fixture-first", "fixture-second", "fixture-third"} {
		plan.Jobs = append(plan.Jobs, PlanJob{ID: name, Scanner: name, TargetID: "app", Target: "https://local-fixture.invalid/", Variant: name, Stage: StageTemplates, State: PlanSelected})
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	first := &restartFixtureRunner{name: "fixture-first", t: t}
	second := &restartFixtureRunner{name: "fixture-second", t: t, interrupt: cancel, checkpointDir: root}
	third := &restartFixtureRunner{name: "fixture-third", t: t}
	pipeline := &Pipeline{Config: Config{KatanaPath: "/nonexistent/katana"}, Runners: []Runner{first, second, third}}
	interrupted := pipeline.RunAssessmentJobs(ctx, plan, root, nil, nil)
	if len(interrupted) != 3 || first.calls != 1 || second.calls != 1 || third.calls != 0 {
		t.Fatalf("interruption: %+v calls %d/%d/%d", interrupted, first.calls, second.calls, third.calls)
	}
	snapshot := filepath.Join(root, "saved-runs.json")
	data, err := json.Marshal(interrupted)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(snapshot, data, 0600); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var restored []Run
	if err = json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	freshFirst := &restartFixtureRunner{name: "fixture-first", t: t}
	freshSecond := &restartFixtureRunner{name: "fixture-second", t: t}
	freshThird := &restartFixtureRunner{name: "fixture-third", t: t}
	restarted := &Pipeline{Config: Config{KatanaPath: "/nonexistent/katana"}, Runners: []Runner{freshFirst, freshSecond, freshThird}}
	resumed := restarted.RunAssessmentJobs(t.Context(), plan, root, restored, nil)
	if freshFirst.calls != 0 || freshSecond.calls != 1 || freshThird.calls != 1 || resumed[0].AttemptID != restored[0].AttemptID || resumed[1].AttemptID == restored[1].AttemptID {
		t.Fatalf("invalid attempt reuse: %+v", resumed)
	}
	for _, run := range resumed {
		if run.Status != "completed" || VerifyChecksum(run) != nil {
			t.Fatalf("unsealed completion: %+v", run)
		}
	}
	manifest, ok := LoadWorkflowManifest(root)
	stage, _ := manifest.Stage(StageTemplates)
	if !ok || stage.Status != StageStatusCompleted || len(stage.OutputChecksums) != 3 {
		t.Fatalf("resumed manifest: %+v", manifest)
	}
}

func TestWorkflowCheckpointFailureStopsRemainingExecution(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(WorkflowManifestPath(root), 0700); err != nil {
		t.Fatal(err)
	}
	one := &restartFixtureRunner{name: "fixture-one", t: t}
	two := &restartFixtureRunner{name: "fixture-two", t: t}
	plan := AssessmentPlan{Fingerprint: "sha256:checkpoint-failure", Jobs: []PlanJob{{ID: "one", Scanner: one.name, TargetID: "app", Variant: one.name, Target: "https://local-fixture.invalid/", Stage: StageTemplates, State: PlanSelected}, {ID: "two", Scanner: two.name, TargetID: "app", Variant: two.name, Target: "https://local-fixture.invalid/", Stage: StageTemplates, State: PlanSelected}}}
	runs := (&Pipeline{Runners: []Runner{one, two}}).RunAssessmentJobs(t.Context(), plan, root, nil, nil)
	if len(runs) != 2 || one.calls != 1 || two.calls != 0 {
		t.Fatalf("checkpoint failure did not stop execution: %+v", runs)
	}
	for _, run := range runs {
		if run.GapKind != GapInterruptedWrite || run.Status == "completed" {
			t.Fatalf("unpersisted completion: %+v", run)
		}
	}
}
