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
