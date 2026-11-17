package scanner

import (
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

// The read-only exposure catalogs and Dalfox's GET-parameter XSS checks run by
// default for a web target; they were opt-in and so rarely ran.
func TestWebDefaultsIncludeExposureCatalogsAndDalfox(t *testing.T) {
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeBlackBox, Types: []assessment.Type{assessment.TypeWebApplication}, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.example.test/"}}}
	plan := PlanAssessment(PlanInput{Config: cfg, Availability: map[string]bool{"dalfox": true}})
	if len(plan.Errors) != 0 {
		t.Fatalf("unexpected errors: %+v", plan.Errors)
	}
	for _, id := range []string{"exposed-files", "vcs-exposure", "actuator", "api-docs", "dalfox"} {
		var got PlanState
		for _, d := range plan.Decisions {
			if d.Scanner == id && d.TargetID == "app" {
				got = d.State
			}
		}
		if got != PlanSelected {
			t.Errorf("%s state=%q, want selected by default", id, got)
		}
	}
	// Dalfox without its binary stays visibly unavailable rather than planned.
	missing := PlanAssessment(PlanInput{Config: cfg, Availability: map[string]bool{"dalfox": false}})
	for _, d := range missing.Decisions {
		if d.Scanner == "dalfox" && d.TargetID == "app" && d.State != PlanUnavailable {
			t.Errorf("dalfox without binary state=%s, want unavailable", d.State)
		}
	}
}
