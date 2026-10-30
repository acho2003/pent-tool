package assessment

import (
	"strings"
	"testing"
)

func validBoundaryConfig() AssessmentConfig {
	cfg := validActionConfig()
	cfg.NextjsActionApprovals = nil
	cfg.NextjsBoundaryApprovals = []NextjsBoundaryApproval{{ID: "cache", TargetID: "app", Kind: "cache", FixtureRef: strings.Repeat("b", 64), OwnerIdentity: "owner", Identity: "anonymous"}}
	return cfg
}
func TestNextjsBoundaryApprovalRequiresControlledEnvironmentAndBoundIdentities(t *testing.T) {
	if problems := ValidateNextjsBoundaryApprovals(validBoundaryConfig()); len(problems) > 0 {
		t.Fatalf("valid boundary approval refused: %+v", problems)
	}
	for _, mode := range []string{"black-box", "not-test", "disabled-workflow", "unknown-target", "unknown-identity", "same-identity", "invalid-kind", "bad-ref", "too-many"} {
		t.Run(mode, func(t *testing.T) {
			cfg := validBoundaryConfig()
			switch mode {
			case "black-box":
				cfg.Mode = ModeBlackBox
			case "not-test":
				cfg.TestEnvironment = false
			case "disabled-workflow":
				cfg.WorkflowVersion = ""
			case "unknown-target":
				cfg.NextjsBoundaryApprovals[0].TargetID = "other"
			case "unknown-identity":
				cfg.NextjsBoundaryApprovals[0].Identity = "unknown"
			case "same-identity":
				cfg.NextjsBoundaryApprovals[0].Identity = "owner"
			case "invalid-kind":
				cfg.NextjsBoundaryApprovals[0].Kind = "arbitrary-http"
			case "bad-ref":
				cfg.NextjsBoundaryApprovals[0].FixtureRef = "bad"
			case "too-many":
				cfg.NextjsBoundaryApprovals = make([]NextjsBoundaryApproval, 21)
			}
			if len(ValidateNextjsBoundaryApprovals(cfg)) == 0 {
				t.Fatal("unsafe boundary approval accepted")
			}
		})
	}
}
func TestNextjsBoundaryNormalizationDoesNotAliasInput(t *testing.T) {
	cfg := validBoundaryConfig()
	cfg.NextjsBoundaryApprovals[0].Kind = " CACHE "
	normalized := Normalize(cfg)
	if normalized.NextjsBoundaryApprovals[0].Kind != "cache" || cfg.NextjsBoundaryApprovals[0].Kind != " CACHE " {
		t.Fatal("normalization mutated approval")
	}
}
