package assessment

import "testing"

func TestNormalize_UppercasesTrimsAndAssignsIDs(t *testing.T) {
	cfg := AssessmentConfig{
		Mode:  "  gray_box ",
		Types: []Type{"web_application", "API", "WEB_APPLICATION"}, // dup + case
		Targets: []Target{
			{Kind: "url", Value: "  https://App.Example.test/Portal/  "}, // no ID, mixed case value
		},
		Access: []AccessBinding{{TargetIDs: []string{"t1"}, Kind: "application_headers", CredentialID: "cred1"}},
	}
	out := Normalize(cfg)

	if out.Mode != ModeGrayBox {
		t.Errorf("mode = %q, want GRAY_BOX", out.Mode)
	}
	if len(out.Types) != 2 || out.Types[0] != TypeWebApplication || out.Types[1] != TypeAPI {
		t.Errorf("types not normalized/deduped: %v", out.Types)
	}
	if out.Targets[0].ID != "t1" {
		t.Errorf("target id = %q, want auto-assigned t1", out.Targets[0].ID)
	}
	// URL value keeps case and path, only outer whitespace trimmed.
	if out.Targets[0].Value != "https://App.Example.test/Portal/" {
		t.Errorf("url value not preserved: %q", out.Targets[0].Value)
	}
	if out.ScannerSelection.Mode != "auto" {
		t.Errorf("selection mode default = %q, want auto", out.ScannerSelection.Mode)
	}
}

func TestValidate_BlackBoxRejectsCredentialsAndInternalResources(t *testing.T) {
	cfg := Normalize(AssessmentConfig{
		Mode:  ModeBlackBox,
		Types: []Type{TypeWebApplication, TypeSourceCode},
		Targets: []Target{
			{ID: "app", Kind: KindURL, Value: "https://app.example.test"},
			{ID: "repo", Kind: KindRepository, Value: "https://github.com/x/y"},
		},
		Access: []AccessBinding{{TargetIDs: []string{"app"}, Kind: AccessApplicationHeaders, CredentialID: "c1"}},
	})
	probs := Validate(cfg)
	if !hasCode(probs, "blackbox.access.forbidden") {
		t.Errorf("expected blackbox.access.forbidden; got %+v", probs)
	}
	if !hasCode(probs, "blackbox.resource.forbidden") {
		t.Errorf("expected blackbox.resource.forbidden; got %+v", probs)
	}
	if FirstBlocking(probs) == nil {
		t.Error("expected a blocking problem")
	}
}

func TestValidate_RepositoryTargetMustBeOneHTTPSCloneURL(t *testing.T) {
	for _, value := range []string{
		"https://github.com/a/one.git, https://github.com/a/two.git",
		"https://github.com/a/one.git https://github.com/a/two.git",
		"https://user:token@github.com/a/one.git",
		"git@github.com:a/one.git",
	} {
		cfg := Normalize(AssessmentConfig{Mode: ModeWhiteBox, Types: []Type{TypeSourceCode}, Targets: []Target{{ID: "repo", Kind: KindRepository, Value: value}}})
		if !hasCode(Validate(cfg), "target.value.invalid") {
			t.Errorf("repository value %q should be rejected", value)
		}
	}
	cfg := Normalize(AssessmentConfig{Mode: ModeWhiteBox, Types: []Type{TypeSourceCode}, Targets: []Target{{ID: "repo", Kind: KindRepository, Value: "https://github.com/a/one.git"}}})
	if hasCode(Validate(cfg), "target.value.invalid") {
		t.Error("a single HTTPS clone URL should be accepted")
	}
}

func TestValidate_GrayBoxRequiresWhiteBoxForSource(t *testing.T) {
	cfg := Normalize(AssessmentConfig{
		Mode:    ModeGrayBox,
		Types:   []Type{TypeSourceCode},
		Targets: []Target{{ID: "repo", Kind: KindRepository, Value: "https://github.com/x/y"}},
	})
	probs := Validate(cfg)
	if !hasCode(probs, "graybox.resource.requires_whitebox") {
		t.Errorf("expected graybox.resource.requires_whitebox; got %+v", probs)
	}
}

func TestValidate_WhiteBoxAllowsAllResources(t *testing.T) {
	cfg := Normalize(AssessmentConfig{
		Mode:  ModeWhiteBox,
		Types: []Type{TypeSourceCode, TypeContainer},
		Targets: []Target{
			{ID: "repo", Kind: KindRepository, Value: "https://github.com/x/y"},
			{ID: "img", Kind: KindDockerImage, Value: "alpine:3.20"},
		},
	})
	if p := FirstBlocking(Validate(cfg)); p != nil {
		t.Errorf("White Box should not block resources, got %+v", p)
	}
}

func TestValidate_RejectsUnknownEnumsAndUnboundAccess(t *testing.T) {
	cfg := Normalize(AssessmentConfig{
		Mode:    "PURPLE_BOX",
		Types:   []Type{"TELEPATHY"},
		Targets: []Target{{ID: "x", Kind: "MAGIC", Value: "v"}},
		Access:  []AccessBinding{{Kind: AccessSSH}}, // no target ids
	})
	probs := Validate(cfg)
	for _, code := range []string{"mode.invalid", "types.invalid", "target.kind.invalid", "access.unbound"} {
		if !hasCode(probs, code) {
			t.Errorf("expected problem %q; got %+v", code, probs)
		}
	}
}

func TestValidate_APIdefinitionsRequireExplicitTargetAssociation(t *testing.T) {
	base := AssessmentConfig{Mode: ModeGrayBox, Types: []Type{TypeAPI}, Targets: []Target{{ID: "one", Kind: KindURL, Value: "https://one.example"}, {ID: "two", Kind: KindURL, Value: "https://two.example"}}}
	base.APIDefinitionIDs = []string{"sha256-id"}
	if !hasCode(Validate(Normalize(base)), "api_definition.target_required") {
		t.Fatal("unbound API definition accepted for multiple targets")
	}
	base.APIDefinitionIDs = nil
	base.APIDefinitions = []APIDefinitionBinding{{TargetID: "missing", DefinitionID: "sha256-id"}}
	if !hasCode(Validate(Normalize(base)), "api_definition.target_unknown") {
		t.Fatal("API definition bound to unknown target was accepted")
	}
}

func TestValidate_FormLoginRequiresVerificationAndOneURLTarget(t *testing.T) {
	base := AssessmentConfig{Mode: ModeGrayBox, Types: []Type{TypeWebApplication}, Targets: []Target{{ID: "app", Kind: KindURL, Value: "https://app.example.test/Portal"}, {ID: "other", Kind: KindURL, Value: "https://other.example.test"}}, Access: []AccessBinding{{Kind: AccessFormLogin, TargetIDs: []string{"app"}, CredentialID: "credential"}}}
	if !hasCode(Validate(Normalize(base)), "access.verification_required") {
		t.Fatal("form login without a verification marker was accepted")
	}
	base.Access[0].VerifyURL = "https://app.example.test/Portal/account"
	base.Access[0].VerifyMarker = "Account dashboard"
	if problem := FirstBlocking(Validate(Normalize(base))); problem != nil {
		t.Fatalf("valid form login was rejected: %+v", problem)
	}
	base.Access[0].TargetIDs = []string{"app", "other"}
	if !hasCode(Validate(Normalize(base)), "access.form_login.single_target") {
		t.Fatal("form login was bound to multiple applications")
	}
}

func TestValidate_PreservesValidURLPathAndRejectsOutOfScopeURLForms(t *testing.T) {
	valid := Normalize(AssessmentConfig{Mode: ModeBlackBox, Types: []Type{TypeWebApplication}, Targets: []Target{{ID: "app", Kind: KindURL, Value: "https://example.test:8443/Portal/Case?view=full"}}})
	if problem := FirstBlocking(Validate(valid)); problem != nil {
		t.Fatalf("valid application URL rejected: %+v", problem)
	}
	for _, value := range []string{"example.test", "https://user:pass@example.test", "https://example.test/#fragment", "https://example.test:99999/"} {
		cfg := Normalize(AssessmentConfig{Mode: ModeBlackBox, Types: []Type{TypeWebApplication}, Targets: []Target{{ID: "app", Kind: KindURL, Value: value}}})
		if !hasCode(Validate(cfg), "target.value.invalid") {
			t.Errorf("invalid URL target %q was accepted", value)
		}
	}
}

func TestDeriveCapabilities_PerTargetNoCrossUnion(t *testing.T) {
	cfg := Normalize(AssessmentConfig{
		Mode:  ModeGrayBox,
		Types: []Type{TypeWebApplication, TypeAPI},
		Targets: []Target{
			{ID: "app", Kind: KindURL, Value: "https://app.example.test/Portal/"},
			{ID: "other", Kind: KindURL, Value: "https://other.example.test"},
		},
		APIDefinitions: []APIDefinitionBinding{{TargetID: "app", DefinitionID: "def1"}},
		Access:         []AccessBinding{{TargetIDs: []string{"app"}, Kind: AccessApplicationHeaders, CredentialID: "c1"}},
	})
	ev := DeriveCapabilities(cfg)

	// app has web + api + schema + authenticated_web(available).
	if !hasEvidence(ev, CapAuthWeb, "app", StateAvailable) {
		t.Errorf("app should have available authenticated_web; got %+v", ev)
	}
	// "other" must NOT inherit app's credential.
	if hasEvidence(ev, CapAuthWeb, "other", StateAvailable) {
		t.Errorf("credential leaked onto unrelated target 'other'")
	}
	if !hasEvidence(ev, CapAPI, "app", StateAvailable) {
		t.Errorf("app should have api capability")
	}
	if !hasEvidence(ev, CapSchema, "app", StateDeclared) {
		t.Errorf("app should have declared schema capability")
	}
}

func TestDeriveCapabilities_BareIPHasNoWeb_RepoSourceConditional(t *testing.T) {
	cfg := Normalize(AssessmentConfig{
		Mode:  ModeWhiteBox,
		Types: []Type{TypeNetwork, TypeSourceCode},
		Targets: []Target{
			{ID: "ip", Kind: KindIP, Value: "10.0.0.5"},
			{ID: "repo", Kind: KindRepository, Value: "https://github.com/x/y"},
		},
	})
	ev := DeriveCapabilities(cfg)
	if hasCapForTarget(ev, CapWeb, "ip") {
		t.Errorf("bare IP must not establish web capability")
	}
	if !hasEvidence(ev, CapNetwork, "ip", StateDeclared) {
		t.Errorf("IP should establish declared network capability")
	}
	// Remote repo source is conditional (declared, not available) until checkout.
	if !hasEvidence(ev, CapSource, "repo", StateDeclared) {
		t.Errorf("remote repo source should be declared (conditional), got %+v", ev)
	}
	if hasEvidence(ev, CapSource, "repo", StateAvailable) {
		t.Errorf("remote repo source must not be 'available' before checkout")
	}
}

func TestDeriveCapabilities_UnsupportedResourcesUnavailable(t *testing.T) {
	cfg := Normalize(AssessmentConfig{
		Mode:    ModeWhiteBox,
		Types:   []Type{TypeCloud, TypeKubernetes},
		Targets: []Target{{ID: "acct", Kind: KindCloudAccount, Value: "aws:123"}, {ID: "k8s", Kind: KindKubernetesCluster, Value: "prod"}},
	})
	ev := DeriveCapabilities(cfg)
	if !hasEvidence(ev, CapCloud, "acct", StateUnavailable) {
		t.Errorf("cloud account should be unavailable")
	}
	if !hasEvidence(ev, CapKubernetes, "k8s", StateUnavailable) {
		t.Errorf("k8s cluster should be unavailable")
	}
}

// helpers

func hasCode(probs []Problem, code string) bool {
	for _, p := range probs {
		if p.Code == code {
			return true
		}
	}
	return false
}

func hasEvidence(ev []CapabilityEvidence, c Capability, targetID string, st EvidenceState) bool {
	for _, e := range ev {
		if e.Capability == c && e.TargetID == targetID && e.State == st {
			return true
		}
	}
	return false
}

func hasCapForTarget(ev []CapabilityEvidence, c Capability, targetID string) bool {
	for _, e := range ev {
		if e.Capability == c && e.TargetID == targetID {
			return true
		}
	}
	return false
}
