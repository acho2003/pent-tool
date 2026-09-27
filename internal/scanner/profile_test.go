package scanner

import "testing"

func TestResolveWebProfileDefaultsAndRejectsUnknown(t *testing.T) {
	p, ok := ResolveWebProfile("")
	if !ok || p.Name != ProfileGentle || p.RateRPS != 2 || p.MaxEndpoints != 500 {
		t.Fatalf("unexpected gentle profile: %#v", p)
	}
	p, ok = ResolveWebProfile(ProfileThorough)
	if !ok || p.RateRPS != 5 || p.MaxEndpoints != 2000 {
		t.Fatalf("unexpected thorough profile: %#v", p)
	}
	if _, ok := ResolveWebProfile("unsafe"); ok {
		t.Fatal("unknown profile accepted")
	}
}
