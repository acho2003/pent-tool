package assessment

import (
	"strings"
	"testing"
)

func validActionConfig() AssessmentConfig {
	return AssessmentConfig{Mode: ModeGrayBox, TestEnvironment: true, WorkflowVersion: "unified-v1", Types: []Type{TypeWebApplication}, Targets: []Target{{ID: "app", Kind: KindURL, Value: "https://app.test/"}}, Access: []AccessBinding{{TargetIDs: []string{"app"}, Identity: "owner", Kind: AccessBearerToken, CredentialID: "test"}}, NextjsActionApprovals: []NextjsActionApproval{{ID: "case", TargetID: "app", FixtureRef: strings.Repeat("a", 64), OwnerIdentity: "owner", Cases: []NextjsActionCase{{ID: "baseline", Identity: "owner", Expect: "allow"}, {ID: "anonymous", Identity: "anonymous", Expect: "deny"}}}}}
}

func TestNextjsActionApprovalsRequireExplicitBoundedCases(t *testing.T) {
	if problems := ValidateNextjsActionApprovals(validActionConfig()); len(problems) > 0 {
		t.Fatalf("valid campaign refused: %+v", problems)
	}
	for _, mode := range []string{"no-test", "black-box", "no-workflow", "unknown-target", "wrong-target-identity", "bad-ref", "no-baseline", "too-many", "duplicate-case", "owner-denied", "unknown-identity", "mixed-origin-identity", "duplicate-variant"} {
		t.Run(mode, func(t *testing.T) {
			cfg := validActionConfig()
			switch mode {
			case "no-test":
				cfg.TestEnvironment = false
			case "black-box":
				cfg.Mode = ModeBlackBox
			case "no-workflow":
				cfg.WorkflowVersion = ""
			case "unknown-target":
				cfg.NextjsActionApprovals[0].TargetID = "other"
			case "wrong-target-identity":
				cfg.Access[0].TargetIDs = []string{"other"}
			case "bad-ref":
				cfg.NextjsActionApprovals[0].FixtureRef = "not-a-hash"
			case "no-baseline":
				cfg.NextjsActionApprovals[0].Cases[0].Expect = "deny"
			case "too-many":
				cfg.NextjsActionApprovals[0].Cases = make([]NextjsActionCase, 9)
			case "duplicate-case":
				cfg.NextjsActionApprovals[0].Cases[1].ID = "baseline"
			case "owner-denied":
				cfg.NextjsActionApprovals[0].Cases[1].Identity = "owner"
			case "unknown-identity":
				cfg.NextjsActionApprovals[0].Cases[1].Identity = "unknown"
			case "mixed-origin-identity":
				cfg.NextjsActionApprovals[0].Cases[1].CrossOrigin = true
			case "duplicate-variant":
				cfg.NextjsActionApprovals[0].Cases = append(cfg.NextjsActionApprovals[0].Cases, NextjsActionCase{ID: "another-anonymous", Identity: "anonymous", Expect: "deny"})
			}
			if problems := ValidateNextjsActionApprovals(cfg); len(problems) == 0 {
				t.Fatal("unsafe campaign accepted")
			}
		})
	}
}

func TestNextjsActionNormalizationCopiesCasesAndPreservesBaselineOrder(t *testing.T) {
	cfg := validActionConfig()
	cfg.NextjsActionApprovals[0].Cases[0].Expect = " ALLOW "
	normalized := Normalize(cfg)
	if normalized.NextjsActionApprovals[0].Cases[0].Expect != "allow" || cfg.NextjsActionApprovals[0].Cases[0].Expect != " ALLOW " {
		t.Fatal("normalization mutated its input or reordered the baseline")
	}
	normalized.NextjsActionApprovals[0].Cases[0].ID = "changed"
	if cfg.NextjsActionApprovals[0].Cases[0].ID != "baseline" {
		t.Fatal("normalization aliased nested cases")
	}
}
