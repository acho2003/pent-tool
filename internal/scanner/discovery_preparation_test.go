package scanner

import (
	"slices"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestApprovedDiscoveryPreparationSurvivesCustomScannerSelection(t *testing.T) {
	cfg := assessment.AssessmentConfig{WorkflowVersion: "unified-v1", ParentPlanFingerprint: "parent", Mode: assessment.ModeBlackBox, Types: []assessment.Type{assessment.TypeWebApplication, assessment.TypeNetwork}, Targets: []assessment.Target{{ID: "discovered-fixture", Kind: assessment.KindHost, Value: "api.example.test"}}, ScannerSelection: assessment.ScannerSelection{Mode: "custom", Variants: []string{"nuclei"}}}
	input := PlanInput{Config: cfg, Availability: map[string]bool{"dnsx": true, "httpx": true, "katana": true, "nuclei": true}}
	plan := PlanAssessment(input)
	if len(plan.Errors) > 0 {
		t.Fatal(plan.Errors)
	}
	for _, name := range []string{"dnsx", "httpx"} {
		if !slices.ContainsFunc(plan.Jobs, func(job PlanJob) bool { return job.Scanner == name && job.State == PlanSelected }) {
			t.Fatalf("approved prerequisite missing %s: %+v", name, plan.Jobs)
		}
	}
	if slices.ContainsFunc(plan.Jobs, func(job PlanJob) bool { return job.Scanner == "nmap" }) {
		t.Fatal("unselected port discovery added")
	}
	for _, job := range plan.Jobs {
		if job.Scanner == "katana" && !slices.Contains(job.Dependencies, "httpx:discovered-fixture:httpx") {
			t.Fatal("crawl does not wait for HTTP evidence", job)
		}
	}
	input.Config.WorkflowVersion = ""
	legacy := PlanAssessment(input)
	if slices.ContainsFunc(legacy.Jobs, func(job PlanJob) bool { return job.Scanner == "dnsx" || job.Scanner == "httpx" }) {
		t.Fatal("legacy custom plan upgraded")
	}
	input.Config = cfg
	input.Availability["dnsx"] = false
	unavailable := PlanAssessment(input)
	if !slices.ContainsFunc(unavailable.Jobs, func(job PlanJob) bool { return job.Scanner == "dnsx" && job.State == PlanUnavailable }) {
		t.Fatal("missing binary hidden", unavailable.Jobs)
	}
}
func TestDiscoveryActionsBindApprovalFingerprint(t *testing.T) {
	plan := AssessmentPlan{Fingerprint: "parent", Config: assessment.AssessmentConfig{Types: []assessment.Type{assessment.TypeWebApplication}, ScannerSelection: assessment.ScannerSelection{Mode: "custom", Variants: []string{"nuclei"}}}}
	runs := []Run{{Scanner: "subfinder", CandidateHosts: []string{"api.example.test"}}}
	initial := BuildDiscoveryPreview(plan, runs, nil)
	if len(initial.Candidates) != 1 || len(initial.Candidates[0].Actions) != 2 {
		t.Fatal(initial)
	}
	plan.Config.ScannerSelection.Variants = append(plan.Config.ScannerSelection.Variants, "nmap")
	changed := BuildDiscoveryPreview(plan, runs, nil)
	if changed.Fingerprint == initial.Fingerprint || len(changed.Candidates[0].Actions) != 3 {
		t.Fatal("changed active actions did not invalidate preview", changed)
	}
}

func TestDiscoveryRetainsSameOriginPathExpansionForApproval(t *testing.T) {
	origin := assessment.ApprovedOrigin{TargetID: "app", Scheme: "https", Host: "app.example.test", Port: 443, PathPrefix: "/approved/"}
	plan := AssessmentPlan{Fingerprint: "bounded", Config: assessment.AssessmentConfig{Types: []assessment.Type{assessment.TypeWebApplication}, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.example.test/approved/"}}, ApprovedOrigins: []assessment.ApprovedOrigin{origin}}}
	surface := AttackSurface{Endpoints: []AttackSurfaceEndpoint{{URL: "https://app.example.test/outside/", State: EndpointStateOutOfScope}}}
	preview := BuildDiscoveryPreview(plan, nil, []AttackSurface{surface})
	if len(preview.Candidates) != 1 || preview.Candidates[0].Value != "https://app.example.test" {
		t.Fatal("path expansion suppressed by existing origin", preview)
	}
}
