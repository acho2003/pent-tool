package scanner

import (
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"testing"
)

func TestDiscoveryRequiresFreshExplicitApprovalAndIsolatesCredentials(t *testing.T) {
	plan := AssessmentPlan{Fingerprint: "original", Config: assessment.AssessmentConfig{Mode: assessment.ModeGrayBox, Types: []assessment.Type{assessment.TypeWebApplication}, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.test/"}}, Access: []assessment.AccessBinding{{Kind: assessment.AccessApplicationHeaders, TargetIDs: []string{"app"}, CredentialID: "secret"}}}}
	preview := BuildDiscoveryPreview(plan, []Run{{Scanner: "subfinder", CandidateHosts: []string{"api.app.test", "app.test"}}}, nil)
	if len(preview.Candidates) != 1 {
		t.Fatal(preview)
	}
	if _, err := ApproveDiscoveryConfig(plan, preview, "stale", []string{preview.Candidates[0].ID}); err == nil {
		t.Fatal("stale preview accepted")
	}
	cfg, err := ApproveDiscoveryConfig(plan, preview, preview.Fingerprint, []string{preview.Candidates[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Targets) != 2 || len(cfg.Access[0].TargetIDs) != 1 || len(plan.Config.Targets) != 1 {
		t.Fatalf("approval mutated scope/auth %+v", cfg)
	}
	revised := AssessmentPlan{Fingerprint: "new", Config: cfg}
	revision := DiscoveryRevision{Plan: revised, ParentFingerprint: plan.Fingerprint, PreviewFingerprint: preview.Fingerprint}
	if err := SaveDiscoveryRevision(t.TempDir(), revision); err != nil {
		t.Fatal(err)
	}
}
