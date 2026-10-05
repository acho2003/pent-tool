package scanner

import (
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"testing"
)

func TestLegacyExecutorDoesNotAcquireExpandedInputsOnRollout(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	surface := NewSeedAttackSurface("app:test", "https://app.test/")
	if got := dispatchTargetsWithPolicy(surface, "zap", 100, nil, nil, false); len(got) != 0 {
		t.Fatal("legacy ZAP inputs expanded", got)
	}
	if got := dispatchTargetsWithPolicy(surface, "zap", 100, nil, nil, true); len(got) != 1 {
		t.Fatal("expanded ZAP input missing", got)
	}
	if expandedWorkflowRequest(Request{}) || !expandedWorkflowRequest(Request{WorkflowVersion: "unified-v1"}) {
		t.Fatal("request rollout marker ignored")
	}
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "0")
	pipeline := Pipeline{}
	runs := pipeline.RunAssessmentJobs(t.Context(), AssessmentPlan{Fingerprint: "plan", Config: assessment.AssessmentConfig{WorkflowVersion: "unified-v1"}, Jobs: []PlanJob{{Scanner: "zap", TargetID: "app", Target: "https://app.test/", State: PlanSelected}}}, t.TempDir(), nil, nil)
	if len(runs) != 1 || runs[0].Status != "failed" {
		t.Fatal("disabled expanded executor was silently downgraded", runs)
	}
}

func TestCoverageUsesSavedWorkflowRatherThanRolloutFlag(t *testing.T) {
	surface := NewSeedAttackSurface("app:test", "https://app.test/")
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	legacy := BuildCoverageProof([]AttackSurface{*surface}, nil)
	if legacy.ExpandedEnabled {
		t.Fatal("rollout changed legacy coverage", legacy)
	}
	surface.WorkflowVersion = "unified-v1"
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "0")
	expanded := BuildCoverageProof([]AttackSurface{*surface}, nil)
	if !expanded.ExpandedEnabled {
		t.Fatal("disabled rollout erased accepted coverage", expanded)
	}
}
