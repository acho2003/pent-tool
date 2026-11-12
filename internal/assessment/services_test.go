package assessment

import (
	"strings"
	"testing"
)

func microserviceConfig() AssessmentConfig {
	return AssessmentConfig{
		Mode:  ModeWhiteBox,
		Types: []Type{TypeWebApplication, TypeAPI, TypeContainer},
		Targets: []Target{
			{ID: "svc-1-url-1", Kind: KindURL, Value: "http://172.30.3.142:30862"},
			{ID: "svc-1-image", Kind: KindDockerImage, Value: "registry.example.test/bcrs/auth:6"},
			{ID: "svc-2-url-1", Kind: KindURL, Value: "http://172.30.3.10:31132"},
			{ID: "loose", Kind: KindURL, Value: "https://portal.example.test"},
		},
		Services: []Service{
			{ID: "svc-1", Name: "Auth Service", TargetIDs: []string{"svc-1-url-1", "svc-1-image"}},
			{ID: "svc-2", Name: "Common Service", TargetIDs: []string{"svc-2-url-1"}},
		},
	}
}

func problemCodes(cfg AssessmentConfig) map[string]bool {
	codes := map[string]bool{}
	for _, p := range Validate(Normalize(cfg)) {
		if p.Blocking {
			codes[p.Code] = true
		}
	}
	return codes
}

func TestServicesValidConfigHasNoServiceProblems(t *testing.T) {
	for code := range problemCodes(microserviceConfig()) {
		if strings.HasPrefix(code, "service.") {
			t.Fatalf("unexpected service problem %s", code)
		}
	}
}

func TestServicesRejectInvalidGroupings(t *testing.T) {
	cases := map[string]func(*AssessmentConfig){
		"service.id.duplicate":   func(c *AssessmentConfig) { c.Services[1].ID = "svc-1" },
		"service.name.duplicate": func(c *AssessmentConfig) { c.Services[1].Name = "auth service" },
		"service.target.unknown": func(c *AssessmentConfig) { c.Services[1].TargetIDs = []string{"missing"} },
		"service.target.shared":  func(c *AssessmentConfig) { c.Services[1].TargetIDs = []string{"svc-1-image"} },
		"service.targets.empty":  func(c *AssessmentConfig) { c.Services[1].TargetIDs = nil },
		"service.name.invalid":   func(c *AssessmentConfig) { c.Services[1].Name = "bad\nname" },
		"service.id.invalid":     func(c *AssessmentConfig) { c.Services[1].ID = "" },
	}
	for code, mutate := range cases {
		cfg := microserviceConfig()
		cfg.Services = append([]Service(nil), cfg.Services...)
		mutate(&cfg)
		if !problemCodes(cfg)[code] {
			t.Errorf("%s not reported", code)
		}
	}
	cfg := microserviceConfig()
	cfg.Services[0].Name = strings.Repeat("x", 129)
	if !problemCodes(cfg)["service.name.invalid"] {
		t.Error("overlong service name accepted")
	}
}

func TestServicesNormalizeAndLookup(t *testing.T) {
	cfg := microserviceConfig()
	cfg.Services[0].Name = "  Auth Service  "
	cfg.Services[0].ID = " svc-1 "
	cfg.Services[0].TargetIDs = []string{" svc-1-url-1 ", "svc-1-image"}
	n := Normalize(cfg)
	if n.Services[0].Name != "Auth Service" || n.Services[0].ID != "svc-1" || n.Services[0].TargetIDs[0] != "svc-1-url-1" {
		t.Fatalf("service not normalized: %+v", n.Services[0])
	}
	if svc, ok := n.ServiceForTarget("svc-1-image"); !ok || svc.Name != "Auth Service" {
		t.Fatal("image target not mapped to its service")
	}
	if _, ok := n.ServiceForTarget("loose"); ok {
		t.Fatal("ungrouped target mapped to a service")
	}
}

func TestTokenLoginBindsSeveralURLTargets(t *testing.T) {
	cfg := microserviceConfig()
	cfg.Mode = ModeGrayBox
	cfg.Types = []Type{TypeWebApplication, TypeAPI}
	cfg.Targets = []Target{cfg.Targets[0], cfg.Targets[2]}
	cfg.Services = []Service{{ID: "svc-1", Name: "Auth", TargetIDs: []string{"svc-1-url-1"}}, {ID: "svc-2", Name: "Common", TargetIDs: []string{"svc-2-url-1"}}}
	cfg.Access = []AccessBinding{
		{Kind: AccessTokenLogin, CredentialID: "cred-1", TargetIDs: []string{"svc-1-url-1"}, VerifyURL: "http://172.30.3.142:30862/api/me"},
		{Kind: AccessTokenLogin, CredentialID: "cred-1", TargetIDs: []string{"svc-2-url-1"}},
	}
	codes := problemCodes(cfg)
	for code := range codes {
		if strings.HasPrefix(code, "access.") {
			t.Fatalf("token login binding rejected: %s", code)
		}
	}
	caps := DeriveCapabilities(Normalize(cfg))
	seen := 0
	for _, c := range caps {
		if c.Capability == CapAuthWeb && c.AccessKind == AccessTokenLogin && c.State == StateAvailable {
			seen++
		}
	}
	if seen != 2 {
		t.Fatalf("expected authenticated_web available for both targets, got %d", seen)
	}
}

func TestTokenLoginRejectsNonURLTarget(t *testing.T) {
	cfg := microserviceConfig()
	cfg.Access = []AccessBinding{{Kind: AccessTokenLogin, CredentialID: "cred-1", TargetIDs: []string{"svc-1-image"}}}
	if !problemCodes(cfg)["access.target_must_be_url"] {
		t.Fatal("token login on an image target accepted")
	}
}

func TestRegistryCredentialsMustBindImages(t *testing.T) {
	cfg := microserviceConfig()
	cfg.Access = []AccessBinding{{Kind: AccessRegistryCreds, CredentialID: "reg-1", TargetIDs: []string{"svc-1-image"}}}
	if problemCodes(cfg)["access.registry.target_must_be_image"] {
		t.Fatal("registry credential on image rejected")
	}
	cfg.Access[0].TargetIDs = []string{"svc-1-url-1"}
	if !problemCodes(cfg)["access.registry.target_must_be_image"] {
		t.Fatal("registry credential on URL accepted")
	}
	cfg.Access[0].TargetIDs = []string{"svc-1-image"}
	cfg.Access[0].CredentialID = ""
	if !problemCodes(cfg)["access.registry.credential_required"] {
		t.Fatal("registry binding without credential accepted")
	}
}
