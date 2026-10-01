package scanner

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestMasscanCapabilityReason(t *testing.T) {
	if got := masscanCapabilityReason("CapEff:\t0000000000003000\n"); got != "" {
		t.Fatalf("both capabilities should be available: %q", got)
	}
	for _, tc := range []struct{ status, want string }{
		{"CapEff:\t0000000000002000\n", "NET_ADMIN"},
		{"CapEff:\t0000000000001000\n", "NET_RAW"},
		{"CapEff:\t0000000000000000\n", "NET_ADMIN and NET_RAW"},
		{"CapEff:\tbroken\n", "parse CapEff"},
		{"Name:\txalgorix\n", "no CapEff"},
	} {
		if got := masscanCapabilityReason(tc.status); !strings.Contains(got, tc.want) {
			t.Errorf("%q: reason %q does not contain %q", tc.status, got, tc.want)
		}
	}
}

func TestMasscanCapabilityGapAppearsInAssessmentPlan(t *testing.T) {
	plan := PlanAssessment(PlanInput{
		Config: assessment.AssessmentConfig{Mode: assessment.ModeBlackBox,
			Types:   []assessment.Type{assessment.TypeNetwork},
			Targets: []assessment.Target{{ID: "net", Kind: assessment.KindIP, Value: "192.0.2.1"}}},
		Availability:          map[string]bool{"masscan": false},
		UnavailabilityReasons: map[string]string{"masscan": "NET_ADMIN is required"},
	})
	for _, decision := range plan.Decisions {
		if decision.Scanner == "masscan" && decision.TargetID == "net" {
			if decision.State != PlanUnavailable || decision.ReasonCode != "scanner.capability_unavailable" || !strings.Contains(decision.Reason, "NET_ADMIN") {
				t.Fatalf("capability gap was hidden: %+v", decision)
			}
			return
		}
	}
	t.Fatal("masscan decision missing")
}
