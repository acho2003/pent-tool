// internal/scanner/scope_test.go
package scanner

import "testing"

func TestHostScopeKey(t *testing.T) {
	s := HostScope("api.example.com")
	if s.Kind != ScopeHost {
		t.Fatalf("kind = %q, want %q", s.Kind, ScopeHost)
	}
	if s.Target != "api.example.com" {
		t.Fatalf("target = %q", s.Target)
	}
	if got, want := s.Key(), "host:api.example.com"; got != want {
		t.Fatalf("key = %q, want %q", got, want)
	}
}

func TestScopeTrackConsts(t *testing.T) {
	if TrackWeb != "web" || TrackServer != "server" {
		t.Fatalf("track consts drifted: %q %q", TrackWeb, TrackServer)
	}
}
