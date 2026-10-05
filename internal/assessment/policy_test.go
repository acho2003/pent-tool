package assessment

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestNormalizeSortsOriginsExclusionsProvidersSeedsDeterministically(t *testing.T) {
	base := AssessmentConfig{
		Mode:    ModeGrayBox,
		Types:   []Type{TypeWebApplication},
		Targets: []Target{{ID: "app", Kind: KindURL, Value: "https://a.test"}},
	}
	a := base
	a.ApprovedOrigins = []ApprovedOrigin{
		{TargetID: " app ", Scheme: "HTTPS", Host: "B.test", PathPrefix: "/v1/"},
		{TargetID: "app", Scheme: "https", Host: "a.test", Port: 443},
		{TargetID: "app", Scheme: "https", Host: "a.test"}, // duplicate once default port is filled
		{TargetID: "app", Scheme: "http", Host: "[::1]", Port: 8080},
	}
	a.Exclusions = []Exclusion{
		{Method: "post", PathPattern: " /logout ", Reason: " ends session "},
		{TargetID: "app", Origin: "https://A.test:443", PathPattern: "/admin"},
		{Method: "POST", PathPattern: "/logout", Reason: "ends session"}, // duplicate
		{Method: "*", PathPattern: "/delete"},
	}
	a.DiscoveryProviders = &DiscoveryProviders{Subdomain: []string{" Amass", "subfinder", "amass", ""}, Historical: " GAU ", TLS: "SSLyze"}
	a.ManualSeeds = []string{" https://a.test/z ", "https://a.test/a", "", "https://a.test/z"}

	b := base
	b.ApprovedOrigins = []ApprovedOrigin{a.ApprovedOrigins[3], a.ApprovedOrigins[2], a.ApprovedOrigins[0]}
	b.Exclusions = []Exclusion{a.Exclusions[3], a.Exclusions[1], a.Exclusions[0]}
	b.DiscoveryProviders = &DiscoveryProviders{Subdomain: []string{"subfinder", "amass"}, Historical: "gau", TLS: "sslyze"}
	b.ManualSeeds = []string{"https://a.test/a", "https://a.test/z"}

	na, nb := Normalize(a), Normalize(b)
	if !reflect.DeepEqual(na, nb) {
		t.Fatalf("normalization depends on input order/spelling:\n%+v\n%+v", na, nb)
	}
	wantOrigins := []ApprovedOrigin{
		{TargetID: "app", Scheme: "http", Host: "::1", Port: 8080, PathPrefix: "/"},
		{TargetID: "app", Scheme: "https", Host: "a.test", Port: 443, PathPrefix: "/"},
		{TargetID: "app", Scheme: "https", Host: "b.test", Port: 443, PathPrefix: "/v1"},
	}
	if !reflect.DeepEqual(na.ApprovedOrigins, wantOrigins) {
		t.Errorf("origins = %+v\nwant %+v", na.ApprovedOrigins, wantOrigins)
	}
	wantExclusions := []Exclusion{
		{PathPattern: "/delete"},
		{Method: "POST", PathPattern: "/logout", Reason: "ends session"},
		{TargetID: "app", Origin: "https://a.test", PathPattern: "/admin"},
	}
	if !reflect.DeepEqual(na.Exclusions, wantExclusions) {
		t.Errorf("exclusions = %+v\nwant %+v", na.Exclusions, wantExclusions)
	}
	wantProviders := &DiscoveryProviders{Subdomain: []string{"amass", "subfinder"}, Historical: "gau", TLS: "sslyze"}
	if !reflect.DeepEqual(na.DiscoveryProviders, wantProviders) {
		t.Errorf("providers = %+v, want %+v", na.DiscoveryProviders, wantProviders)
	}
	if want := []string{"https://a.test/a", "https://a.test/z"}; !reflect.DeepEqual(na.ManualSeeds, want) {
		t.Errorf("seeds = %v, want %v", na.ManualSeeds, want)
	}

	// An all-empty provider selection collapses to nil; "none" is the canonical "".
	c := base
	c.DiscoveryProviders = &DiscoveryProviders{Historical: "none"}
	if got := Normalize(c).DiscoveryProviders; got != nil {
		t.Errorf("empty provider selection = %+v, want nil", got)
	}
}

func webConfig() AssessmentConfig {
	return AssessmentConfig{
		Mode:  ModeGrayBox,
		Types: []Type{TypeWebApplication},
		Targets: []Target{
			{ID: "app", Kind: KindURL, Value: "https://app.example.test/portal"},
			{ID: "dom", Kind: KindDomain, Value: "example.test"},
		},
	}
}

func TestValidateRejectsUnknownOriginTargetAndExclusionOrigin(t *testing.T) {
	cfg := webConfig()
	cfg.ApprovedOrigins = []ApprovedOrigin{
		{TargetID: "app", Scheme: "https", Host: "app.example.test", PathPrefix: "/portal"},
		{TargetID: "ghost", Scheme: "https", Host: "app.example.test"},
	}
	cfg.Exclusions = []Exclusion{
		{TargetID: "ghost", PathPattern: "/logout"},
		{Origin: "https://unapproved.example.test", PathPattern: "/logout"},
		{TargetID: "app", Origin: "https://example.test", PathPattern: "/logout"}, // approved for dom, not app
	}
	probs := Validate(Normalize(cfg))
	for _, code := range []string{"origin.target.unknown", "exclusion.target.unknown", "exclusion.origin.unknown"} {
		if !hasCode(probs, code) {
			t.Errorf("expected %s; got %+v", code, probs)
		}
	}
	if n := countCode(probs, "exclusion.origin.unknown"); n != 2 {
		t.Errorf("exclusion.origin.unknown count = %d, want 2; %+v", n, probs)
	}

	bad := webConfig()
	bad.ApprovedOrigins = []ApprovedOrigin{
		{TargetID: "app", Scheme: "ftp", Host: "app.example.test"},
		{TargetID: "app", Scheme: "https", Host: "app.example.test/x"},
		{TargetID: "app", Scheme: "https", Host: "app.example.test", Port: 70000},
		{TargetID: "app", Scheme: "https", Host: "app.example.test", PathPrefix: "/portal?x=1"},
	}
	bad.Exclusions = []Exclusion{{PathPattern: "logout"}, {PathPattern: ""}, {Method: "BREW", PathPattern: "/x"}}
	probs = Validate(Normalize(bad))
	if n := countCode(probs, "origin.invalid"); n != 4 {
		t.Errorf("origin.invalid count = %d, want 4; %+v", n, probs)
	}
	if n := countCode(probs, "exclusion.invalid"); n != 3 {
		t.Errorf("exclusion.invalid count = %d, want 3; %+v", n, probs)
	}

	// Origins must still cover the URL target they belong to.
	uncovered := webConfig()
	uncovered.ApprovedOrigins = []ApprovedOrigin{{TargetID: "app", Scheme: "https", Host: "app.example.test", Port: 8443}}
	if !hasCode(Validate(Normalize(uncovered)), "origin.target_not_covered") {
		t.Error("expected origin.target_not_covered when approved origins exclude the target URL")
	}

	good := webConfig()
	good.ApprovedOrigins = []ApprovedOrigin{
		{TargetID: "app", Scheme: "https", Host: "app.example.test", Port: 443, PathPrefix: "/portal"},
		{TargetID: "app", Scheme: "https", Host: "api.example.test", Port: 8443},
	}
	good.Exclusions = []Exclusion{
		{Method: "POST", PathPattern: "/logout"},
		{TargetID: "app", Origin: "https://api.example.test:8443", PathPattern: "/v1/orders/*/cancel"},
		{Origin: "http://example.test", PathPattern: "/admin"}, // derived origin of the legacy domain target
	}
	if probs := Validate(Normalize(good)); FirstBlocking(probs) != nil {
		t.Errorf("valid origins/exclusions rejected: %+v", probs)
	}
}

func TestValidateDiscoveryProvidersMutuallyExclusiveAndOptIn(t *testing.T) {
	with := func(mut func(*AssessmentConfig)) []Problem {
		cfg := webConfig()
		cfg.SubdomainDiscovery = true
		mut(&cfg)
		return Validate(Normalize(cfg))
	}
	for name, tc := range map[string]struct {
		mut  func(*AssessmentConfig)
		code string
	}{
		"both historical": {func(c *AssessmentConfig) { c.DiscoveryProviders = &DiscoveryProviders{Historical: "gau,waybackurls"} }, "discovery.historical.invalid"},
		"both tls":        {func(c *AssessmentConfig) { c.DiscoveryProviders = &DiscoveryProviders{TLS: "testssl+sslyze"} }, "discovery.tls.invalid"},
		"unknown tls":     {func(c *AssessmentConfig) { c.DiscoveryProviders = &DiscoveryProviders{TLS: "sslscan"} }, "discovery.tls.invalid"},
		"unknown sub": {func(c *AssessmentConfig) {
			c.DiscoveryProviders = &DiscoveryProviders{Subdomain: []string{"assetfinder"}}
		}, "discovery.subdomain.invalid"},
		"sub not opted in": {func(c *AssessmentConfig) {
			c.SubdomainDiscovery = false
			c.DiscoveryProviders = &DiscoveryProviders{Subdomain: []string{"subfinder"}}
		}, "discovery.subdomain.not_authorized"},
		"sub without domain": {func(c *AssessmentConfig) {
			c.Targets = c.Targets[:1]
			c.DiscoveryProviders = &DiscoveryProviders{Subdomain: []string{"amass"}}
		}, "discovery.subdomain.domain_required"},
	} {
		if probs := with(tc.mut); !hasCode(probs, tc.code) || FirstBlocking(probs) == nil {
			t.Errorf("%s: expected blocking %s; got %+v", name, tc.code, probs)
		}
	}
	ok := with(func(c *AssessmentConfig) {
		c.DiscoveryProviders = &DiscoveryProviders{Subdomain: []string{"subfinder", "amass"}, Historical: "waybackurls", TLS: "sslyze"}
	})
	if FirstBlocking(ok) != nil {
		t.Errorf("valid provider selection rejected: %+v", ok)
	}

	// Historical archives are an explicit opt-in: only a named provider authorizes them.
	if (*DiscoveryProviders)(nil).HistoricalAuthorized() || (&DiscoveryProviders{Historical: "none"}).HistoricalAuthorized() {
		t.Error("nil/none must not authorize external archive queries")
	}
	if !(&DiscoveryProviders{Historical: "gau"}).HistoricalAuthorized() {
		t.Error("gau must authorize external archive queries")
	}
}

func TestValidateManualSeedsMustBeInScope(t *testing.T) {
	cfg := webConfig()
	cfg.Exclusions = []Exclusion{{PathPattern: "/portal/logout"}}
	cfg.ManualSeeds = []string{
		"https://app.example.test/portal/reports?id=1", // in app's derived scope
		"https://example.test/about",                   // in dom's derived scope
		"https://app.example.test:8443/portal/x",       // other port
		"https://elsewhere.test/",                      // other host
		"https://app.example.test/portal/logout",       // excluded
		"not a url",
	}
	probs := Validate(Normalize(cfg))
	if n := countCode(probs, "manual_seed.out_of_scope"); n != 2 {
		t.Errorf("manual_seed.out_of_scope count = %d, want 2; %+v", n, probs)
	}
	if !hasCode(probs, "manual_seed.excluded") {
		t.Errorf("expected manual_seed.excluded; got %+v", probs)
	}
	if !hasCode(probs, "manual_seed.invalid") {
		t.Errorf("expected manual_seed.invalid; got %+v", probs)
	}
	if n := countCode(probs, "manual_seed.out_of_scope") + countCode(probs, "manual_seed.excluded") + countCode(probs, "manual_seed.invalid"); n != 4 {
		t.Errorf("in-scope seeds must not be reported; %+v", probs)
	}
}

func TestValidateBlackBoxForbidsTestEnvironment(t *testing.T) {
	cfg := webConfig()
	cfg.Mode = ModeBlackBox
	cfg.TestEnvironment = true
	if probs := Validate(Normalize(cfg)); !hasCode(probs, "blackbox.test_environment.forbidden") || FirstBlocking(probs) == nil {
		t.Errorf("expected blocking blackbox.test_environment.forbidden; got %+v", probs)
	}
	cfg.Mode = ModeGrayBox
	if probs := Validate(Normalize(cfg)); hasCode(probs, "blackbox.test_environment.forbidden") {
		t.Errorf("Gray Box should permit test_environment; got %+v", probs)
	}
}

func TestValidateVerifyURLMustBeInsideApprovedOrigin(t *testing.T) {
	cfg := webConfig()
	cfg.ApprovedOrigins = []ApprovedOrigin{{TargetID: "app", Scheme: "https", Host: "app.example.test", PathPrefix: "/portal"}}
	cfg.Access = []AccessBinding{{TargetIDs: []string{"app"}, Kind: AccessBearerToken, CredentialID: "c1", VerifyURL: "https://app.example.test:443/portal/me", VerifyMarker: "Welcome", NegativeMarker: "Sign in"}}
	if probs := Validate(Normalize(cfg)); FirstBlocking(probs) != nil {
		t.Errorf("in-origin verify URL rejected: %+v", probs)
	}
	cfg.Access[0].VerifyURL = "https://app.example.test/elsewhere/me"
	if probs := Validate(Normalize(cfg)); !hasCode(probs, "access.verify_url.out_of_scope") {
		t.Errorf("expected access.verify_url.out_of_scope; got %+v", probs)
	}
	cfg.Access[0].VerifyURL = "https://app.example.test/portal/me"
	cfg.Access[0].NegativeMarker = "bad\nmarker"
	if probs := Validate(Normalize(cfg)); !hasCode(probs, "access.negative_marker.invalid") {
		t.Errorf("expected access.negative_marker.invalid; got %+v", probs)
	}
}

func TestValidateHeaderCredentialAllowsAutomaticVerification(t *testing.T) {
	cfg := webConfig()
	cfg.Access = []AccessBinding{{TargetIDs: []string{"app"}, Kind: AccessApplicationHeaders, CredentialID: "cookie-credential"}}
	if probs := Validate(Normalize(cfg)); FirstBlocking(probs) != nil {
		t.Fatalf("header credential without custom verification fields should be accepted: %+v", probs)
	}
}

func TestEmptyNewFieldsSerializeUnchanged(t *testing.T) {
	cfg := Normalize(AssessmentConfig{
		Mode: ModeGrayBox, Types: []Type{TypeWebApplication, TypeAPI},
		Targets: []Target{{ID: "app", Kind: KindURL, Value: "https://app.example.test/portal"}, {ID: "dom", Kind: KindDomain, Value: "example.test"}},
		Access: []AccessBinding{{TargetIDs: []string{"app"}, Kind: AccessBearerToken, CredentialID: "cred-1",
			VerifyURL: "https://app.example.test/portal/me", VerifyMarker: "Welcome"}},
		Profile:            "standard",
		APIDefinitions:     []APIDefinitionBinding{{TargetID: "app", DefinitionID: "def-1"}},
		SubdomainDiscovery: true,
	})
	// Golden captured from the pre-change model (registry v4). Configs that do
	// not use the new policy fields must serialise byte-for-byte as before so
	// stored scans and plan fingerprints stay stable.
	const golden = `{"assessment_mode":"GRAY_BOX","assessment_types":["WEB_APPLICATION","API"],"assessment_targets":[{"id":"app","type":"URL","value":"https://app.example.test/portal"},{"id":"dom","type":"DOMAIN","value":"example.test"}],"access":[{"target_ids":["app"],"kind":"BEARER_TOKEN","credential_id":"cred-1","verify_url":"https://app.example.test/portal/me","verify_marker":"Welcome"}],"profile":"standard","scanner_selection":{"mode":"auto"},"api_definitions":[{"target_id":"app","definition_id":"def-1"}],"subdomain_discovery":true}`
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != golden {
		t.Fatalf("serialisation changed:\n got %s\nwant %s", raw, golden)
	}
	var back AssessmentConfig
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	again, _ := json.Marshal(Normalize(back))
	if string(again) != golden {
		t.Fatalf("normalize round trip changed serialisation:\n got %s", again)
	}
}

func countCode(probs []Problem, code string) int {
	n := 0
	for _, p := range probs {
		if p.Code == code {
			n++
		}
	}
	return n
}
