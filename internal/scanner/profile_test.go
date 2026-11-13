package scanner

import (
	"testing"
	"time"
)

func TestResolveWebProfileDefaultsAndRejectsUnknown(t *testing.T) {
	p, ok := ResolveWebProfile("")
	if !ok || p.Name != ProfileGentle || p.RateRPS != 2 || p.MaxEndpoints != 500 {
		t.Fatalf("unexpected gentle profile: %#v", p)
	}
	p, ok = ResolveWebProfile(ProfileThorough)
	if !ok || p.RateRPS != 150 || p.MaxEndpoints != 2000 || p.Budget != 0 {
		t.Fatalf("unexpected thorough profile: %#v", p)
	}
	if _, ok := ResolveWebProfile("unsafe"); ok {
		t.Fatal("unknown profile accepted")
	}
}

func TestResolveWebProfilePreservesGentleBudgets(t *testing.T) {
	for _, name := range []string{"", ProfileGentle} {
		p, ok := ResolveWebProfile(name)
		if !ok || p.Name != ProfileGentle || p.RateRPS != 2 || p.MaxEndpoints != 500 || p.Budget != 30*time.Minute {
			t.Fatalf("gentle profile budgets changed for %q: %#v", name, p)
		}
		if p.AllowStateChanging {
			t.Fatal("gentle profile allows state-changing requests")
		}
	}
}

func TestProfileThoroughNeverAllowsStateChanging(t *testing.T) {
	p, ok := ResolveWebProfile(ProfileThorough)
	if !ok || p.Name != ProfileThorough {
		t.Fatalf("thorough profile not resolvable: %#v", p)
	}
	if p.AllowStateChanging || DefaultWebProfile(ProfileThorough).AllowStateChanging {
		t.Fatal("thorough profile must not enable writes automatically")
	}
}

func TestNextjsDeepProfileHasFiniteBudgetsAndNeverApprovesWrites(t *testing.T) {
	p, ok := ResolveWebProfile(ProfileNextjsDeep)
	if !ok || p.Name != ProfileNextjsDeep || p.RateRPS != 50 || p.MaxEndpoints != 3000 || p.Budget != 240*time.Minute || !p.Browser || p.AllowStateChanging {
		t.Fatalf("profile=%+v ok=%v", p, ok)
	}
}

func TestWebProfileEnvOverrides(t *testing.T) {
	t.Setenv("XALGORIX_WEB_RATE_RPS", "80")
	t.Setenv("XALGORIX_WEB_MAX_ENDPOINTS", "5000")
	t.Setenv("XALGORIX_WEB_BUDGET_MINUTES", "0") // unlimited
	p, ok := ResolveWebProfile(ProfileNextjsDeep)
	if !ok || p.RateRPS != 80 || p.MaxEndpoints != 5000 || p.Budget != 0 {
		t.Fatalf("overrides not applied: %+v", p)
	}
	// An override never flips the write/browser policy.
	if p.AllowStateChanging || !p.Browser {
		t.Fatalf("overrides changed safety policy: %+v", p)
	}
	// Invalid or negative rate/endpoints are ignored (default kept).
	t.Setenv("XALGORIX_WEB_RATE_RPS", "-5")
	t.Setenv("XALGORIX_WEB_MAX_ENDPOINTS", "notanumber")
	t.Setenv("XALGORIX_WEB_BUDGET_MINUTES", "")
	p, _ = ResolveWebProfile(ProfileNextjsDeep)
	if p.RateRPS != 50 || p.MaxEndpoints != 3000 || p.Budget != 240*time.Minute {
		t.Fatalf("invalid overrides should keep defaults: %+v", p)
	}
}

// Rate 0 means no limit / full speed, parsed like the 0-is-unlimited budget.
func TestWebProfileRateZeroMeansNoLimit(t *testing.T) {
	t.Setenv("XALGORIX_WEB_RATE_RPS", "0")
	p, ok := ResolveWebProfile(ProfileThorough)
	if !ok || p.RateRPS != 0 {
		t.Fatalf("rate 0 override should disable the limit: %+v", p)
	}
	// Full speed never relaxes the write/browser policy.
	if p.AllowStateChanging {
		t.Fatalf("rate 0 changed safety policy: %+v", p)
	}
}
