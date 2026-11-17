package scanner

import (
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

// The New Scan page describes optional tools as additions to the automatic
// selection. Auto mode with variants must therefore keep every automatic
// scanner and add the named optional ones, while custom mode stays exact.
func TestAutoSelectionWithOptionalVariantsKeepsAutomaticScanners(t *testing.T) {
	base := assessment.AssessmentConfig{Mode: assessment.ModeBlackBox, Types: []assessment.Type{assessment.TypeWebApplication}, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.example.test/"}}}
	availability := map[string]bool{"dalfox": true, "nikto": true}
	state := func(plan AssessmentPlan, id string) PlanState {
		for _, d := range plan.Decisions {
			if d.Scanner == id && d.TargetID == "app" {
				return d.State
			}
		}
		return ""
	}

	additive := base
	additive.ScannerSelection = assessment.ScannerSelection{Mode: "auto", Variants: []string{"dalfox"}}
	plan := PlanAssessment(PlanInput{Config: additive, Availability: availability})
	if len(plan.Errors) != 0 {
		t.Fatalf("unexpected errors: %+v", plan.Errors)
	}
	if got := state(plan, "dalfox"); got != PlanSelected {
		t.Fatalf("dalfox state=%s, want selected", got)
	}
	for _, id := range []string{"zap", "nuclei", "security-headers", "api-docs", "httpx"} {
		if got := state(plan, id); got != PlanSelected && got != PlanConditional {
			t.Errorf("automatic scanner %s state=%s after adding an optional tool", id, got)
		}
	}
	if got := state(plan, "nikto"); got != PlanOptional {
		t.Errorf("unrequested optional nikto state=%s, want optional", got)
	}

	exact := base
	exact.ScannerSelection = assessment.ScannerSelection{Mode: "custom", Variants: []string{"dalfox"}}
	custom := PlanAssessment(PlanInput{Config: exact, Availability: availability})
	if got := state(custom, "security-headers"); got != PlanSkipped {
		t.Errorf("custom mode must stay exact: security-headers state=%s", got)
	}

	unknown := base
	unknown.ScannerSelection = assessment.ScannerSelection{Mode: "auto", Variants: []string{"does-not-exist"}}
	if bad := PlanAssessment(PlanInput{Config: unknown}); len(bad.Errors) == 0 {
		t.Error("unknown additive variant was accepted")
	}
}
