package assessment

import (
	"strings"
	"testing"
)

func TestFuzzApprovalRequiresSeparateBoundedConsentAndControlledCleanup(t *testing.T) {
	valid := AssessmentConfig{WorkflowVersion: "unified-v1", Mode: ModeGrayBox, Types: []Type{TypeAPI}, Targets: []Target{{ID: "app", Kind: KindURL, Value: "https://app.test/"}}, TestEnvironment: true, APIDefinitions: []APIDefinitionBinding{{TargetID: "app", DefinitionID: strings.Repeat("a", 64)}}, FuzzApprovals: []FuzzApproval{{WriteApproval: WriteApproval{TargetID: "app", Method: "POST", Path: "/items", OperationID: "create", FixtureRef: strings.Repeat("b", 64), ContentType: "application/x-www-form-urlencoded", CleanupMethod: "DELETE", CleanupPath: "/items/fixture"}, Scanner: "wapiti", RequestLimit: 10, RepeatTestingApproved: true}}}
	if problems := Validate(Normalize(valid)); len(problems) > 0 {
		t.Fatalf("valid separate consent rejected: %+v", problems)
	}
	cases := []struct {
		name   string
		modify func(*AssessmentConfig)
	}{
		{"no repeated consent", func(c *AssessmentConfig) { c.FuzzApprovals[0].RepeatTestingApproved = false }},
		{"unbounded", func(c *AssessmentConfig) { c.FuzzApprovals[0].RequestLimit = 0 }},
		{"too many", func(c *AssessmentConfig) { c.FuzzApprovals[0].RequestLimit = 1001 }},
		{"production", func(c *AssessmentConfig) { c.TestEnvironment = false }},
		{"json", func(c *AssessmentConfig) { c.FuzzApprovals[0].ContentType = "application/json" }},
		{"legacy", func(c *AssessmentConfig) { c.WorkflowVersion = "" }},
		{"cleanup missing", func(c *AssessmentConfig) { c.FuzzApprovals[0].CleanupPath = "" }},
		{"wrong scanner", func(c *AssessmentConfig) { c.FuzzApprovals[0].Scanner = "nuclei" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			cfg.FuzzApprovals = append([]FuzzApproval(nil), valid.FuzzApprovals...)
			tc.modify(&cfg)
			if len(Validate(Normalize(cfg))) == 0 {
				t.Fatal("unsafe approval accepted")
			}
		})
	}
	if len(valid.WriteApprovals) != 0 {
		t.Fatal("fuzz consent changed exactly-once write approvals")
	}
}
