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

func TestAcceptedRevisionCannotBeOverwritten(t *testing.T) {
	dir := t.TempDir()
	revision := DiscoveryRevision{ParentFingerprint: "parent", PreviewFingerprint: "preview", Plan: AssessmentPlan{Fingerprint: "accepted"}}
	if err := SaveDiscoveryRevision(dir, revision); err != nil {
		t.Fatal(err)
	}
	saved, err := LoadDiscoveryRevision(dir, "accepted")
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveDiscoveryRevision(dir, revision); err != nil {
		t.Fatal("duplicate approval should be idempotent", err)
	}
	revision.ParentFingerprint = "changed"
	if err := SaveDiscoveryRevision(dir, revision); err == nil {
		t.Fatal("accepted revision overwritten")
	}
	after, err := LoadDiscoveryRevision(dir, "accepted")
	if err != nil || after.ParentFingerprint != saved.ParentFingerprint || after.AcceptedAt != saved.AcceptedAt {
		t.Fatal(after, err)
	}
}

func TestDiscoveryApprovalDoesNotRenewWriteConsent(t *testing.T) {
	original := assessment.WriteApproval{TargetID: "app", Method: "POST", Path: "/items", OperationID: "create"}
	plan := AssessmentPlan{Fingerprint: "parent", Config: assessment.AssessmentConfig{Mode: assessment.ModeGrayBox, Types: []assessment.Type{assessment.TypeWebApplication}, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.test/"}}, WriteApprovals: []assessment.WriteApproval{original}, FuzzApprovals: []assessment.FuzzApproval{{WriteApproval: original, Scanner: "wapiti", RequestLimit: 3, RepeatTestingApproved: true}}}}
	preview := BuildDiscoveryPreview(plan, []Run{{Scanner: "subfinder", CandidateHosts: []string{"api.app.test"}}}, nil)
	cfg, err := ApproveDiscoveryConfig(plan, preview, preview.Fingerprint, []string{preview.Candidates[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.WriteApprovals) != 0 || len(cfg.FuzzApprovals) != 0 || len(plan.Config.FuzzApprovals) != 1 || len(plan.Config.WriteApprovals) != 1 {
		t.Fatal("discovery approval renewed state-changing consent or changed parent")
	}
}
