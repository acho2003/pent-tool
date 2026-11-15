package assessment

import "testing"

func TestSystemTemplateValidateAcceptsEMIS(t *testing.T) {
	tpl := SystemTemplate{
		Name:           "EMIS NestJS",
		BaseURL:        "https://dev-emis.systems.gov.bt",
		PathTemplate:   "/svc/{name}",
		VerifyTemplate: "/svc/{name}/health",
		SpecMode:       "path",
		SpecTemplate:   "/svc/{name}/documentation-json",
	}
	if p := FirstBlocking(tpl.Validate()); p != nil {
		t.Fatalf("valid template rejected: %s", p.Message)
	}
}

func TestSystemTemplateValidateDefaults(t *testing.T) {
	tpl := SystemTemplate{Name: "X", BaseURL: "https://h", PathTemplate: "/svc/{name}", VerifyTemplate: "/svc/{name}/me"}
	if p := FirstBlocking(tpl.Validate()); p != nil {
		t.Fatalf("template with defaulted spec/auth rejected: %s", p.Message)
	}
	got := tpl.WithDefaults()
	if got.SpecMode != "auto" || got.AuthHeaderName != "Authorization" || got.AuthHeaderPrefix != "Bearer " {
		t.Fatalf("defaults not applied: %+v", got)
	}
}

func TestSystemTemplateValidateRejections(t *testing.T) {
	base := func() SystemTemplate {
		return SystemTemplate{Name: "X", BaseURL: "https://h", PathTemplate: "/svc/{name}", VerifyTemplate: "/svc/{name}/me"}
	}
	cases := map[string]func(*SystemTemplate){
		"missing placeholder":  func(t *SystemTemplate) { t.PathTemplate = "/svc/static" },
		"two placeholders":     func(t *SystemTemplate) { t.PathTemplate = "/svc/{name}/{name}" },
		"non-absolute path":    func(t *SystemTemplate) { t.PathTemplate = "svc/{name}" },
		"path with query":      func(t *SystemTemplate) { t.PathTemplate = "/svc/{name}?x=1" },
		"bad base":             func(t *SystemTemplate) { t.BaseURL = "not a url" },
		"empty name":           func(t *SystemTemplate) { t.Name = "" },
		"bad spec mode":        func(t *SystemTemplate) { t.SpecMode = "guess" },
		"path mode no spec":    func(t *SystemTemplate) { t.SpecMode = "path" },
		"header name as value": func(t *SystemTemplate) { t.AuthHeaderName = "Authorization: Bearer x" },
		"prefix as token":      func(t *SystemTemplate) { t.AuthHeaderPrefix = "Bearer eyJhbGciOiJIUzI1NiJ9" },
		"jwt in marker":        func(t *SystemTemplate) { t.VerifyMarker = "eyJhbGciOiJIUzI1NiJ9.payload" },
		"secret in login":      func(t *SystemTemplate) { t.LoginURLTemplate = "/auth?token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
	}
	for name, mutate := range cases {
		tpl := base()
		mutate(&tpl)
		if p := FirstBlocking(tpl.Validate()); p == nil {
			t.Errorf("%s: expected a blocking problem, got none", name)
		}
	}
}

func TestLooksLikeSecret(t *testing.T) {
	secrets := []string{"eyJhbGciOiJIUzI1NiJ9.e30.sig", "AAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	for _, s := range secrets {
		if !looksLikeSecret(s) {
			t.Errorf("%q should look like a secret", s)
		}
	}
	safe := []string{"", "/svc/{name}", "https://dev-emis.systems.gov.bt", "/svc/{name}/documentation-json", "Bearer "}
	for _, s := range safe {
		if looksLikeSecret(s) {
			t.Errorf("%q should not look like a secret", s)
		}
	}
}
