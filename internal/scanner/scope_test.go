// internal/scanner/scope_test.go
package scanner

import (
	"encoding/json"
	"testing"
)

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

func TestRunScopeJSONRoundtrip(t *testing.T) {
	r := Run{Scanner: "nuclei", Target: "x", Status: "completed", Scope: "host:x"}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var got Run
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Scope != "host:x" {
		t.Fatalf("scope = %q, want host:x", got.Scope)
	}
	// Legacy record without scope stays empty.
	var legacy Run
	if err := json.Unmarshal([]byte(`{"scanner":"nuclei","status":"completed"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.Scope != "" {
		t.Fatalf("legacy scope = %q, want empty", legacy.Scope)
	}
}
