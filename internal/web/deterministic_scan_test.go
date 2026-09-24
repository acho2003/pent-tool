package web

import (
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

// TestUpsertScannerRunKeysOnScopeAndScanner guards the crash-persisted resume
// record: Increment 2 emits duplicate scanner names across scopes (per-host
// nuclei/zap/... and per-host recon nmap), so upsert must key on BOTH Scope and
// Scanner. Keying on Scanner alone would let one host's run overwrite another's.
func TestUpsertScannerRunKeysOnScopeAndScanner(t *testing.T) {
	var runs []scanner.Run

	upsertScannerRun(&runs, scanner.Run{Scanner: "nuclei", Scope: "host:a.example.com", Target: "a.example.com", Status: "completed"})
	upsertScannerRun(&runs, scanner.Run{Scanner: "nuclei", Scope: "host:b.example.com", Target: "b.example.com", Status: "completed"})

	// Both same-named runs on different scopes must be retained, not collapsed.
	if len(runs) != 2 {
		t.Fatalf("runs = %d, want 2 (per-host nuclei runs must not collapse): %#v", len(runs), runs)
	}
	byScope := map[string]scanner.Run{}
	for _, r := range runs {
		byScope[r.Scope] = r
	}
	if byScope["host:a.example.com"].Target != "a.example.com" || byScope["host:b.example.com"].Target != "b.example.com" {
		t.Fatalf("per-host runs lost their identity: %#v", runs)
	}

	// An update to host A's nuclei run replaces only that one; host B is untouched.
	upsertScannerRun(&runs, scanner.Run{Scanner: "nuclei", Scope: "host:a.example.com", Target: "a.example.com", Status: "failed", Reason: "rerun"})
	if len(runs) != 2 {
		t.Fatalf("update grew the slice to %d, want 2 (in-place replace): %#v", len(runs), runs)
	}
	byScope = map[string]scanner.Run{}
	for _, r := range runs {
		byScope[r.Scope] = r
	}
	if got := byScope["host:a.example.com"]; got.Status != "failed" || got.Reason != "rerun" {
		t.Fatalf("host A run not replaced: %#v", got)
	}
	if got := byScope["host:b.example.com"]; got.Status != "completed" {
		t.Fatalf("host B run must be untouched by host A's update: %#v", got)
	}
}

// TestUpsertDistinguishesLiveEmittedScopes guards the crash-persisted record for
// the live-emit path fixed in Increment 4: two scanner_started-style runs for the
// same scanner ("nmap") arrive with different per-host recon scopes. Before scope
// was threaded through Request, live-emitted runs carried Scope=="" and collapsed
// into one; now each carries its per-host scope and upsert must retain both.
func TestUpsertDistinguishesLiveEmittedScopes(t *testing.T) {
	var runs []scanner.Run

	upsertScannerRun(&runs, scanner.Run{Scanner: "nmap", Scope: "recon:t:a", Target: "a", Status: "running"})
	upsertScannerRun(&runs, scanner.Run{Scanner: "nmap", Scope: "recon:t:b", Target: "b", Status: "running"})

	if len(runs) != 2 {
		t.Fatalf("runs = %d, want 2 (live-emitted per-host nmap runs must not collapse): %#v", len(runs), runs)
	}
	byScope := map[string]scanner.Run{}
	for _, r := range runs {
		byScope[r.Scope] = r
	}
	if byScope["recon:t:a"].Target != "a" || byScope["recon:t:b"].Target != "b" {
		t.Fatalf("per-host live-emitted runs lost their identity: %#v", runs)
	}
}
