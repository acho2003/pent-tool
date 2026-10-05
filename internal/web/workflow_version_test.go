package web

import (
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"testing"
)

func TestWorkflowRolloutMarksNewPlansWithoutUpgradingSavedPlans(t *testing.T) {
	server := newTestServer(t, nil)
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeBlackBox, Types: []assessment.Type{assessment.TypeWebApplication}, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://inside.example.test/"}}}
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "0")
	old := server.buildAssessmentPlan(cfg)
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	revalidated := server.buildAssessmentPlan(cfg)
	if revalidated.Config.WorkflowVersion != "" || revalidated.Fingerprint != old.Fingerprint {
		t.Fatal("saved legacy executor changed during rollout")
	}
	marked := newAssessmentWorkflowConfig(cfg)
	if marked.WorkflowVersion != "unified-v1" || cfg.WorkflowVersion != "" {
		t.Fatal("new plan marker was not isolated")
	}
	next := server.buildAssessmentPlan(marked)
	if next.Fingerprint == old.Fingerprint {
		t.Fatal("workflow version missing from plan fingerprint")
	}
	source := newAssessmentWorkflowConfig(assessment.AssessmentConfig{Types: []assessment.Type{assessment.TypeSourceCode}})
	if source.WorkflowVersion != "" {
		t.Fatal("source workflow changed")
	}
}
