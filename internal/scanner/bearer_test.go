package scanner

import (
	"testing"
	"time"

	"github.com/acho2003/pent-tool/internal/assessment"
)

func TestBuildBearerCommand(t *testing.T) {
	spec := buildBearer(Request{Target: "/src/app", ScanDir: t.TempDir()}, Config{BearerPath: "bearer", BearerTimeout: time.Minute})
	if spec.path != "bearer" {
		t.Fatalf("path=%q", spec.path)
	}
	joined := ""
	for _, a := range spec.args {
		joined += a + " "
	}
	for _, want := range []string{"scan", "/src/app", "--format json", "--exit-code 0", "--output"} {
		if !contains(joined, want) {
			t.Fatalf("missing %q in %v", want, spec.args)
		}
	}
	if s := buildBearer(Request{ScanDir: t.TempDir()}, Config{BearerPath: "bearer"}); s.notApp == "" {
		t.Fatal("expected notApp without a source path")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestBearerPlannedForSourceTargets(t *testing.T) {
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeWhiteBox, Types: []assessment.Type{assessment.TypeSourceCode}, Targets: []assessment.Target{{ID: "src", Kind: assessment.KindLocalSourcePath, Value: "/src/api"}}}
	plan := PlanAssessment(PlanInput{Config: cfg})
	found := false
	for _, j := range plan.Jobs {
		if j.Scanner == "bearer" && (j.State == PlanSelected || j.State == PlanConditional) {
			found = true
		}
	}
	if !found {
		t.Fatalf("bearer not planned for source target: %+v", plan.Decisions)
	}
	if !HasAssessmentRunner("bearer") {
		t.Fatal("bearer has no runner")
	}
}
