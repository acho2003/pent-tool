package web

import (
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

// TestScannerConfigThreadsReconAndTestsslPaths guards the config-plumbing gap
// where the recon tools' (subfinder/httpx/nmap) and testssl's paths/timeouts
// were never copied from config.Config into scanner.Config, silently falling
// back to bare PATH names inside the pipeline instead of respecting operator
// configuration. Built directly from a hand-populated config.Config literal
// (rather than the full config.Load/Get singleton) to avoid cross-package
// singleton/env brittleness while still exercising the real scannerConfig
// mapping.
func TestScannerConfigThreadsReconAndTestsslPaths(t *testing.T) {
	cfg := &config.Config{
		SubfinderPath:       "/usr/local/bin/subfinder",
		HttpxPath:           "/usr/local/bin/httpx",
		NmapPath:            "/usr/local/bin/nmap",
		TestsslPath:         "/opt/testssl.sh/testssl.sh",
		SemgrepPath:         "/usr/local/bin/semgrep",
		GitleaksPath:        "/usr/local/bin/gitleaks",
		OsvPath:             "/usr/local/bin/osv-scanner",
		SubfinderTimeoutSec: 111,
		HttpxTimeoutSec:     222,
		NmapTimeoutSec:      333,
		TestsslTimeoutSec:   444,
		SemgrepTimeoutSec:   555,
		GitleaksTimeoutSec:  666,
		OsvTimeoutSec:       777,
	}

	sc := scannerConfig(cfg)

	if sc.SubfinderPath != "/usr/local/bin/subfinder" {
		t.Errorf("SubfinderPath = %q, want /usr/local/bin/subfinder", sc.SubfinderPath)
	}
	if sc.HttpxPath != "/usr/local/bin/httpx" {
		t.Errorf("HttpxPath = %q, want /usr/local/bin/httpx", sc.HttpxPath)
	}
	if sc.NmapPath != "/usr/local/bin/nmap" {
		t.Errorf("NmapPath = %q, want /usr/local/bin/nmap", sc.NmapPath)
	}
	if sc.TestsslPath != "/opt/testssl.sh/testssl.sh" {
		t.Errorf("TestsslPath = %q, want /opt/testssl.sh/testssl.sh", sc.TestsslPath)
	}
	if sc.SubfinderTimeout != 111*time.Second {
		t.Errorf("SubfinderTimeout = %v, want 111s", sc.SubfinderTimeout)
	}
	if sc.HttpxTimeout != 222*time.Second {
		t.Errorf("HttpxTimeout = %v, want 222s", sc.HttpxTimeout)
	}
	if sc.NmapTimeout != 333*time.Second {
		t.Errorf("NmapTimeout = %v, want 333s", sc.NmapTimeout)
	}
	if sc.TestsslTimeout != 444*time.Second {
		t.Errorf("TestsslTimeout = %v, want 444s", sc.TestsslTimeout)
	}
	if sc.SemgrepPath != "/usr/local/bin/semgrep" {
		t.Errorf("SemgrepPath = %q, want /usr/local/bin/semgrep", sc.SemgrepPath)
	}
	if sc.GitleaksPath != "/usr/local/bin/gitleaks" {
		t.Errorf("GitleaksPath = %q, want /usr/local/bin/gitleaks", sc.GitleaksPath)
	}
	if sc.OsvPath != "/usr/local/bin/osv-scanner" {
		t.Errorf("OsvPath = %q, want /usr/local/bin/osv-scanner", sc.OsvPath)
	}
	if sc.SemgrepTimeout != 555*time.Second {
		t.Errorf("SemgrepTimeout = %v, want 555s", sc.SemgrepTimeout)
	}
	if sc.GitleaksTimeout != 666*time.Second {
		t.Errorf("GitleaksTimeout = %v, want 666s", sc.GitleaksTimeout)
	}
	if sc.OsvTimeout != 777*time.Second {
		t.Errorf("OsvTimeout = %v, want 777s", sc.OsvTimeout)
	}
}

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
