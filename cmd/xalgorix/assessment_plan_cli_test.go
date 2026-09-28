package main

import (
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestParseAssessmentPlanFlags(t *testing.T) {
	got := parseCLIArgs([]string{"--plan", "--assessment-mode", "GRAY_BOX", "--assessment-type=API,WEB_APPLICATION", "--assessment-config", "plan.json", "--target", "https://example.test/Case"})
	if !got.plan || got.assessmentMode != "GRAY_BOX" || got.assessmentConfig != "plan.json" {
		t.Fatalf("unexpected plan flags: %+v", got)
	}
	if len(got.assessmentTypes) != 2 || got.assessmentTypes[0] != "API" || got.assessmentTypes[1] != "WEB_APPLICATION" {
		t.Fatalf("assessment types = %v", got.assessmentTypes)
	}
	if len(got.targets) != 1 || got.targets[0] != "https://example.test/Case" {
		t.Fatalf("targets = %v", got.targets)
	}
}

func TestInferAssessmentTargetKindPreservesApplicationURLs(t *testing.T) {
	cases := map[string]assessment.TargetKind{
		"https://example.test:8443/Portal/Case": assessment.KindURL,
		"192.0.2.8":                             assessment.KindIP,
		"192.0.2.0/24":                          assessment.KindCIDR,
		"app.example.test":                      assessment.KindDomain,
	}
	for input, want := range cases {
		if got := inferAssessmentTargetKind(input); got != want {
			t.Errorf("inferAssessmentTargetKind(%q) = %s, want %s", input, got, want)
		}
	}
}
