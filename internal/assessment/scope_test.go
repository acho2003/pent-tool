package assessment

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestAppScopeAllowsNormalizesDefaultPortsAndPathBoundary(t *testing.T) {
	scope := NewAppScope([]ApprovedOrigin{{TargetID: "app", Scheme: "https", Host: "A", Port: 443, PathPrefix: "/app"}})
	for _, raw := range []string{
		"https://a/app/x",
		"https://a:443/app",
		"https://A/app/x?q=1",
		"https://a/app/",
		"https://a./app/x#frag",
	} {
		if ok, reason := scope.Allows(raw); !ok {
			t.Errorf("Allows(%q) = false (%s), want true", raw, reason)
		}
	}
	for _, raw := range []string{
		"https://a:8443/app",
		"https://a/other",
		"https://a/application", // shares the prefix text but not the segment boundary
		"http://a/app/x",        // scheme is part of the destination
		"https://b/app/x",
		"https://a/app/../admin", // dot segments resolve outside the boundary
		"https://a/app/%2e%2e/admin",
		"https://user:pw@a/app/x",
		"/app/x",
		"ftp://a/app",
		"",
	} {
		if ok, _ := scope.Allows(raw); ok {
			t.Errorf("Allows(%q) = true, want false", raw)
		}
	}
	if ok, reason := scope.Allows("https://a:8443/app"); ok || reason == "" {
		t.Errorf("rejection should carry a reason, got %v %q", ok, reason)
	}

	// A zero AppScope authorizes nothing (fail closed).
	if ok, _ := (AppScope{}).Allows("https://a/app"); ok {
		t.Error("zero AppScope must not allow any URL")
	}
}

func TestAppScopeIPv6AndExplicitPorts(t *testing.T) {
	scope := NewAppScope([]ApprovedOrigin{{TargetID: "v6", Scheme: "https", Host: "[::1]", Port: 8443}})
	if ok, reason := scope.Allows("https://[::1]:8443/x"); !ok {
		t.Fatalf("explicit IPv6 port rejected: %s", reason)
	}
	if ok, _ := scope.Allows("https://[::1]:443/x"); ok {
		t.Error("[::1]:443 must be distinct from [::1]:8443")
	}
	if ok, _ := scope.Allows("https://[::1]/x"); ok {
		t.Error("[::1] (default port) must be distinct from [::1]:8443")
	}
	origins := scope.Origins()
	if len(origins) != 1 || origins[0].Host != "::1" || origins[0].Origin() != "https://[::1]:8443" {
		t.Fatalf("IPv6 origin not normalized/bracketed: %+v %q", origins, origins[0].Origin())
	}
	def := NewAppScope([]ApprovedOrigin{{TargetID: "v6", Scheme: "http", Host: "::1"}})
	if ok, reason := def.Allows("http://[::1]:80/"); !ok {
		t.Errorf("default http port on IPv6 rejected: %s", reason)
	}
	if got := def.Origins()[0].Origin(); got != "http://[::1]" {
		t.Errorf("default-port origin = %q, want http://[::1]", got)
	}
}

func TestAppScopeForTargetWithoutApprovedOrigins(t *testing.T) {
	cfg := Normalize(AssessmentConfig{
		Mode:  ModeGrayBox,
		Types: []Type{TypeWebApplication},
		Targets: []Target{
			{ID: "app", Kind: KindURL, Value: "https://App.example.test/Portal/"},
			{ID: "dom", Kind: KindDomain, Value: "example.org"},
			{ID: "repo", Kind: KindRepository, Value: "https://github.com/x/y"},
		},
	})
	app := AppScopeForTarget(cfg, "app")
	if ok, reason := app.Allows("https://app.example.test:443/Portal/login"); !ok {
		t.Errorf("derived URL boundary rejected in-scope URL: %s", reason)
	}
	for _, raw := range []string{"https://app.example.test/portal/login", "https://app.example.test/", "http://app.example.test/Portal/"} {
		if ok, _ := app.Allows(raw); ok {
			t.Errorf("derived URL boundary allowed %q", raw)
		}
	}
	if got := app.Origins(); len(got) != 1 || got[0].TargetID != "app" || got[0].PathPrefix != "/Portal" {
		t.Errorf("derived origin = %+v", got)
	}

	dom := AppScopeForTarget(cfg, "dom")
	for _, raw := range []string{"https://example.org/x", "http://example.org/"} {
		if ok, reason := dom.Allows(raw); !ok {
			t.Errorf("domain boundary rejected %q: %s", raw, reason)
		}
	}
	for _, raw := range []string{"https://example.org:8443/", "https://www.example.org/"} {
		if ok, _ := dom.Allows(raw); ok {
			t.Errorf("domain boundary must not authorize other ports or subdomains: %q", raw)
		}
	}

	if got := AppScopeForTarget(cfg, "repo").Origins(); len(got) != 0 {
		t.Errorf("repository target must not yield web origins: %+v", got)
	}
	if got := AppScopeForTarget(cfg, "missing").Origins(); len(got) != 0 {
		t.Errorf("unknown target must yield an empty scope: %+v", got)
	}

	// Approved origins replace the derived boundary for their own target only.
	cfg.ApprovedOrigins = []ApprovedOrigin{{TargetID: "app", Scheme: "https", Host: "api.example.test", Port: 8443, PathPrefix: "/v1"}}
	cfg = Normalize(cfg)
	if ok, _ := AppScopeForTarget(cfg, "app").Allows("https://api.example.test:8443/v1/users"); !ok {
		t.Error("approved origin not honoured")
	}
	if ok, _ := AppScopeForTarget(cfg, "app").Allows("https://app.example.test/Portal/"); ok {
		t.Error("approved origins must be authoritative once supplied")
	}
	if ok, _ := AppScopeForTarget(cfg, "dom").Allows("https://api.example.test:8443/v1/users"); ok {
		t.Error("another target's approved origin leaked into this target's scope")
	}
}

func TestAppScopeExcludedMatchesMethodAndPattern(t *testing.T) {
	origins := []ApprovedOrigin{
		{TargetID: "app", Scheme: "https", Host: "a"},
		{TargetID: "app", Scheme: "https", Host: "b"},
	}
	scope := NewAppScope(origins,
		Exclusion{Method: "post", PathPattern: "/logout", Reason: "ends session"},
		Exclusion{PathPattern: "/admin", Reason: "operator routes"},
		Exclusion{Origin: "https://b:443", PathPattern: "/cart/*/buy", Reason: "purchases"},
	)
	cases := []struct {
		method, url string
		want        bool
	}{
		{"POST", "https://a/logout", true},
		{"post", "https://a/logout/", true},
		{"GET", "https://a/logout", false}, // method-scoped exclusion
		{"GET", "https://a/admin", true},
		{"DELETE", "https://a/admin/users/1", true}, // segment-boundary prefix
		{"GET", "https://a/ADMIN", true},            // case-insensitive (fail safe)
		{"GET", "https://a/administrator", false},
		{"GET", "https://a/x/../admin", true}, // dot segments resolved first
		{"POST", "https://b/cart/42/buy", true},
		{"POST", "https://a/cart/42/buy", false}, // origin-scoped exclusion
		{"GET", "https://a/public", false},
	}
	for _, tc := range cases {
		got, reason := scope.Excluded(tc.method, tc.url)
		if got != tc.want {
			t.Errorf("Excluded(%s %s) = %v (%s), want %v", tc.method, tc.url, got, reason, tc.want)
		}
		if got && reason == "" {
			t.Errorf("Excluded(%s %s) must carry a reason", tc.method, tc.url)
		}
	}

	// Exclusions bound to a target only apply to that target's origins.
	cfg := Normalize(AssessmentConfig{
		Mode:    ModeGrayBox,
		Types:   []Type{TypeWebApplication},
		Targets: []Target{{ID: "one", Kind: KindURL, Value: "https://one.test"}, {ID: "two", Kind: KindURL, Value: "https://two.test"}},
		Exclusions: []Exclusion{
			{TargetID: "one", PathPattern: "/delete"},
			{PathPattern: "/logout"},
		},
	})
	if ok, _ := AppScopeForTarget(cfg, "one").Excluded("GET", "https://one.test/delete"); !ok {
		t.Error("target exclusion not applied to its own target")
	}
	if ok, _ := AppScopeForTarget(cfg, "two").Excluded("GET", "https://two.test/delete"); ok {
		t.Error("target exclusion leaked to another target")
	}
	if ok, _ := AppScopeForTarget(cfg, "two").Excluded("GET", "https://two.test/logout"); !ok {
		t.Error("global exclusion not applied to every target")
	}
}

func TestVerificationURLWithinTargetDefaultPort(t *testing.T) {
	for _, tc := range []struct {
		target, verify string
		want           bool
	}{
		{"https://a", "https://a:443/me", true},
		{"https://a:443", "https://a/me", true},
		{"http://a:80/app", "http://a/app/me", true},
		{"https://a/app", "https://a:8443/app/me", false},
		{"https://a/app", "https://a/other", false},
		{"https://a/app", "https://a/app/me?x=1", false}, // verify URLs carry no query
		{"https://a/app", "https://a/app/me#f", false},
	} {
		if got := verificationURLWithinTarget(tc.target, tc.verify); got != tc.want {
			t.Errorf("verificationURLWithinTarget(%q, %q) = %v, want %v", tc.target, tc.verify, got, tc.want)
		}
	}
}

func TestAppScopeJSONRoundTrip(t *testing.T) {
	scope := NewAppScope([]ApprovedOrigin{{TargetID: "app", Scheme: "https", Host: "a", PathPrefix: "/app"}},
		Exclusion{Method: "POST", PathPattern: "/logout"})
	raw, err := json.Marshal(scope)
	if err != nil {
		t.Fatal(err)
	}
	var back AppScope
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back.Origins(), scope.Origins()) || !reflect.DeepEqual(back.Exclusions(), scope.Exclusions()) {
		t.Fatalf("round trip lost scope: %s", raw)
	}
}
