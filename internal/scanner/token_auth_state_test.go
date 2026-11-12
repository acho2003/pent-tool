package scanner

import (
	"context"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestUnverifiedTokenTargetAuthRunIsAvailableNotVerified(t *testing.T) {
	target := "http://127.0.0.1:9/"
	plan := AssessmentPlan{
		Fingerprint: "sha256:token-state",
		Config: assessment.AssessmentConfig{
			Targets: []assessment.Target{{ID: "svc", Kind: assessment.KindURL, Value: target}},
			Access:  []assessment.AccessBinding{{Kind: assessment.AccessTokenLogin, CredentialID: "cred", TargetIDs: []string{"svc"}}},
		},
		Capabilities: []assessment.CapabilityEvidence{{Capability: assessment.CapAuthWeb, TargetID: "svc", AccessKind: assessment.AccessTokenLogin, State: assessment.StateAvailable, Reason: "token applied; access not verified"}},
		Jobs:         []PlanJob{{ID: "auth:svc:auth", Scanner: "auth", TargetID: "svc", Target: target, Variant: "auth", State: PlanSelected, Stage: StageAuth}},
	}
	headers := []string{"Authorization: Bearer fixture"}
	p := NewPipeline(Config{
		AssessmentAuthHeaders: map[string][]string{"svc": headers},
		AssessmentAuthRefresh: map[string]func(context.Context, []string) ([]string, error){"svc": func(_ context.Context, current []string) ([]string, error) { return current, nil }},
	})
	runs := p.RunAssessmentJobs(context.Background(), plan, t.TempDir(), nil, nil)
	if len(runs) != 1 || runs[0].Status != "completed" || runs[0].AuthState != assessment.StateAvailable || runs[0].Reason == "" {
		t.Fatalf("unverified token auth run: %+v", runs)
	}
	plan.Capabilities[0].State = assessment.StateVerified
	runs = p.RunAssessmentJobs(context.Background(), plan, t.TempDir(), nil, nil)
	if len(runs) != 1 || runs[0].AuthState != assessment.StateVerified {
		t.Fatalf("verified token auth run: %+v", runs)
	}
}
