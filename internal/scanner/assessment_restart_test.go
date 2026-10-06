package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// This helper executes in a separate OS process so no executor memory survives.
func TestWorkflowProcessRecoveryHelper(t *testing.T) {
	root := os.Getenv("XALGORIX_RECOVERY_FIXTURE_ROOT")
	if root == "" {
		t.Skip("subprocess fixture")
	}
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	plan := AssessmentPlan{Fingerprint: "sha256:process-recovery", RegistryVersion: PlanRegistryVersion, Config: assessment.AssessmentConfig{WorkflowVersion: "unified-v1"}}
	runners := []Runner{}
	for _, name := range []string{"process-first", "process-second", "process-third"} {
		plan.Jobs = append(plan.Jobs, PlanJob{ID: name, Scanner: name, TargetID: "app", Target: "https://local-fixture.invalid/", Variant: name, Stage: StageTemplates, State: PlanSelected})
		runners = append(runners, &processRecoveryRunner{name: name, root: root, t: t})
	}
	var saved []Run
	path := filepath.Join(root, "persisted-runs.json")
	if data, err := os.ReadFile(path); err == nil {
		if err = json.Unmarshal(data, &saved); err != nil {
			t.Fatal(err)
		}
	}
	pipeline := &Pipeline{Config: Config{KatanaPath: "/nonexistent/katana"}, Runners: runners}
	emit := func(event Event) {
		if event.Type != "scanner_completed" {
			return
		}
		found := false
		for i := range saved {
			if saved[i].Scanner == event.Scanner {
				saved[i] = event.Run
				found = true
			}
		}
		if !found {
			saved = append(saved, event.Run)
		}
		data, _ := json.Marshal(saved)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	result := pipeline.RunAssessmentJobs(t.Context(), plan, root, saved, emit)
	data, _ := json.Marshal(result)
	if err := os.WriteFile(filepath.Join(root, "resumed-runs.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

type processRecoveryRunner struct {
	name, root string
	t          *testing.T
}

func (r *processRecoveryRunner) Name() string { return r.name }
func (r *processRecoveryRunner) Descriptor() Descriptor {
	return Descriptor{Name: r.name, Phase: PhaseWeb}
}
func (r *processRecoveryRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	file, err := os.OpenFile(filepath.Join(r.root, r.name+".calls"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		r.t.Fatal(err)
	}
	fmt.Fprintln(file, req.AttemptID)
	file.Close()
	if r.name == "process-second" && os.Getenv("XALGORIX_RECOVERY_FIXTURE_PAUSE") == "1" {
		if err := os.WriteFile(filepath.Join(r.root, "worker-paused"), []byte(req.AttemptID), 0600); err != nil {
			r.t.Fatal(err)
		}
		<-ctx.Done()
		return Run{Scanner: r.name, Status: "cancelled"}
	}
	path := filepath.Join(req.ScanDir, "result.json")
	if err := os.WriteFile(path, []byte(`{"fixture":"complete"}`), 0600); err != nil {
		r.t.Fatal(err)
	}
	return finalizeRun(Run{Scanner: r.name, Status: "completed", ArtifactPath: path, Target: req.Target, Scope: req.Scope})
}

func TestExpandedWorkflowRecoversAfterWorkerProcessIsKilled(t *testing.T) {
	root := t.TempDir()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := func(pause bool) *exec.Cmd {
		cmd := exec.CommandContext(t.Context(), binary, "-test.run=^TestWorkflowProcessRecoveryHelper$", "-test.timeout=30s")
		cmd.Env = append(os.Environ(), "XALGORIX_RECOVERY_FIXTURE_ROOT="+root)
		if pause {
			cmd.Env = append(cmd.Env, "XALGORIX_RECOVERY_FIXTURE_PAUSE=1")
		}
		return cmd
	}
	child := command(true)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill() }()
	deadline := time.After(15 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	ready := false
	for !ready {
		select {
		case <-deadline:
			t.Fatal("worker did not reach interrupted job")
		case <-tick.C:
			_, err := os.Stat(filepath.Join(root, "worker-paused"))
			ready = err == nil
		}
	}
	manifest, ok := LoadWorkflowManifest(root)
	stage, _ := manifest.Stage(StageTemplates)
	if !ok || stage.Status != StageStatusRunning || len(stage.OutputChecksums) != 1 {
		t.Fatalf("checkpoint before kill: %+v", stage)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err == nil {
		t.Fatal("worker was not killed")
	}
	if output, err := command(false).CombinedOutput(); err != nil {
		t.Fatalf("fresh process recovery: %v %s", err, output)
	}
	for name, count := range map[string]int{"process-first": 1, "process-second": 2, "process-third": 1} {
		data, err := os.ReadFile(filepath.Join(root, name+".calls"))
		if err != nil || len(strings.Fields(string(data))) != count {
			t.Fatalf("unexpected execution after process kill: %s %s %v", name, data, err)
		}
	}
	data, err := os.ReadFile(filepath.Join(root, "resumed-runs.json"))
	if err != nil {
		t.Fatal(err)
	}
	var runs []Run
	if err := json.Unmarshal(data, &runs); err != nil {
		t.Fatal(err)
	}
	if len(runs) != 3 {
		t.Fatal("missing recovered jobs")
	}
	for _, run := range runs {
		if run.Status != "completed" || VerifyChecksum(run) != nil {
			t.Fatalf("unsealed recovered result: %+v", run)
		}
	}
	manifest, ok = LoadWorkflowManifest(root)
	stage, _ = manifest.Stage(StageTemplates)
	if !ok || stage.Status != StageStatusCompleted || len(stage.OutputChecksums) != 3 {
		t.Fatalf("recovered stage: %+v", stage)
	}
}
