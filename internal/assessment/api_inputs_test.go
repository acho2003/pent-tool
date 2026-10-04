package assessment

import (
	"encoding/json"
	"strings"
	"testing"
)

func apiInputConfig() AssessmentConfig {
	return AssessmentConfig{
		Mode: ModeGrayBox, Types: []Type{TypeAPI},
		Targets:        []Target{{ID: "app", Kind: KindURL, Value: "https://api.example.test/v1"}},
		APIDefinitions: []APIDefinitionBinding{{TargetID: "app", DefinitionID: strings.Repeat("a", 64)}},
	}
}

func TestNormalizeAPIInputsAndApprovalsDeterministically(t *testing.T) {
	cfg := apiInputConfig()
	cfg.APIOperationInputs = []APIOperationInput{{DefinitionID: " " + strings.Repeat("a", 64), OperationID: " list ", Query: map[string]string{" q ": "value"}, PathParams: map[string]string{" id ": "42"}, RequestBodyRef: strings.Repeat("B", 64)}}
	cfg.WriteApprovals = []WriteApproval{{TargetID: " app ", Method: "post", Path: " /items ", OperationID: " create ", FixtureRef: strings.Repeat("C", 64), CleanupRef: strings.Repeat("D", 64)}}
	got := Normalize(cfg)
	input := got.APIOperationInputs[0]
	if input.DefinitionID != strings.Repeat("a", 64) || input.OperationID != "list" || input.Query["q"] != "value" || input.PathParams["id"] != "42" || input.RequestBodyRef != strings.Repeat("b", 64) {
		t.Fatalf("input not normalized: %+v", input)
	}
	approval := got.WriteApprovals[0]
	if approval.Method != "POST" || approval.FixtureRef != strings.Repeat("c", 64) || approval.CleanupRef != strings.Repeat("d", 64) {
		t.Fatalf("approval not normalized: %+v", approval)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "body bytes") {
		t.Fatal("inline body leaked into assessment config")
	}
}

func TestValidateAPIInputsAndWriteApprovals(t *testing.T) {
	valid := apiInputConfig()
	valid.APIOperationInputs = []APIOperationInput{{DefinitionID: strings.Repeat("a", 64), OperationID: "list", PathParams: map[string]string{"id": "42"}}}
	valid.TestEnvironment = true
	valid.WriteApprovals = []WriteApproval{{TargetID: "app", Method: "POST", Path: "/items", OperationID: "create", FixtureRef: strings.Repeat("b", 64), CleanupRef: strings.Repeat("c", 64)}}
	if probs := Validate(Normalize(valid)); len(probs) != 0 {
		t.Fatalf("valid API inputs/approval rejected: %+v", probs)
	}

	cases := []struct {
		name string
		edit func(*AssessmentConfig)
		code string
	}{
		{"unbound definition", func(c *AssessmentConfig) {
			c.APIOperationInputs = []APIOperationInput{{DefinitionID: strings.Repeat("e", 64), OperationID: "read"}}
		}, "api_input.operation.invalid"},
		{"control character", func(c *AssessmentConfig) {
			c.APIOperationInputs = []APIOperationInput{{DefinitionID: strings.Repeat("a", 64), OperationID: "read", Query: map[string]string{"q": "x\r\nInjected: y"}}}
		}, "api_input.value.invalid"},
		{"write without test environment", func(c *AssessmentConfig) {
			c.WriteApprovals = []WriteApproval{{TargetID: "app", Method: "POST", Path: "/items", OperationID: "create", FixtureRef: strings.Repeat("b", 64), CleanupRef: strings.Repeat("c", 64)}}
		}, "api_write.test_environment_required"},
		{"write without cleanup", func(c *AssessmentConfig) {
			c.TestEnvironment = true
			c.WriteApprovals = []WriteApproval{{TargetID: "app", Method: "POST", Path: "/items", OperationID: "create", FixtureRef: strings.Repeat("b", 64)}}
		}, "api_write.cleanup.required"},
		{"write excluded", func(c *AssessmentConfig) {
			c.TestEnvironment = true
			c.Exclusions = []Exclusion{{TargetID: "app", Method: "POST", PathPattern: "/v1/items"}}
			c.WriteApprovals = []WriteApproval{{TargetID: "app", Method: "POST", Path: "/items", OperationID: "create", FixtureRef: strings.Repeat("b", 64), CleanupRef: strings.Repeat("c", 64)}}
		}, "api_write.excluded"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := apiInputConfig()
			tc.edit(&cfg)
			if probs := Validate(Normalize(cfg)); !hasCode(probs, tc.code) {
				t.Fatalf("missing %s in problems: %+v", tc.code, probs)
			}
		})
	}
}

func TestValidateAuthorizationExpectationsRequireTwoBoundIdentities(t *testing.T) {
	cfg := apiInputConfig()
	fixtureA := strings.Repeat("a", 64)
	cfg.Access = []AccessBinding{
		{TargetIDs: []string{"app"}, Kind: AccessBearerToken, CredentialID: "cred-a", Identity: "owner", Role: "owner", VerifyURL: "https://api.example.test/v1/whoami", VerifyMarker: "owner"},
		{TargetIDs: []string{"app"}, Kind: AccessBearerToken, CredentialID: "cred-b", Identity: "reader", Role: "reader", VerifyURL: "https://api.example.test/v1/whoami", VerifyMarker: "reader"},
	}
	cfg.AuthorizationExpectations = []AuthorizationExpectation{
		{OperationID: "getRecord", Identity: "owner", Expect: "allow", ResourceFixtureRef: fixtureA},
		{OperationID: "getRecord", Identity: "reader", Expect: "deny", ResourceFixtureRef: fixtureA},
	}
	if probs := Validate(Normalize(cfg)); len(probs) != 0 {
		t.Fatalf("valid two-identity expectations rejected: %+v", probs)
	}
	cfg.AuthorizationExpectations = cfg.AuthorizationExpectations[:1]
	if probs := Validate(Normalize(cfg)); !hasCode(probs, "api_authorization_expectation.two_identities") {
		t.Fatalf("one identity not rejected: %+v", probs)
	}
}
