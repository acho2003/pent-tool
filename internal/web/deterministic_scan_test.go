package web

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
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

	sc := (&Server{}).ScannerConfig(cfg)

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

// TestWildcardUsesConfiguredSubfinderPathWithDUC guards that legacy wildcard
// discovery runs the operator-configured subfinder binary (so runtime pins
// apply) rather than resolving a bare "subfinder" off PATH, and that it passes
// -duc so subfinder's own auto-update stays disabled during a scan (spec 5).
func TestWildcardUsesConfiguredSubfinderPathWithDUC(t *testing.T) {
	cmd := subfinderCommand(context.Background(), "/opt/pinned/subfinder", "example.com", "/data/scan/subfinder.txt", "/data/scan")

	if cmd.Path != "/opt/pinned/subfinder" {
		t.Errorf("subfinder path = %q, want the configured /opt/pinned/subfinder", cmd.Path)
	}
	if !slices.Contains(cmd.Args, "-duc") {
		t.Errorf("subfinder args %v missing -duc (runtime auto-update must stay disabled)", cmd.Args)
	}
	if !slices.Contains(cmd.Args, "-d") || !slices.Contains(cmd.Args, "example.com") {
		t.Errorf("subfinder args %v missing -d example.com", cmd.Args)
	}
	if cmd.Dir != "/data/scan" {
		t.Errorf("subfinder dir = %q, want /data/scan", cmd.Dir)
	}
}

// TestLegacyTargetAuthNotForwardedToSiblingHosts guards the credential-free
// wildcard rule: discovered hosts are candidates, and the spec forbids
// forwarding credentials to discovered sibling hosts, so a per-host wildcard
// session must carry no targetAuth even when the request configured it.
func TestLegacyTargetAuthNotForwardedToSiblingHosts(t *testing.T) {
	s := &Server{}
	req := ScanRequest{TargetAuth: "cookie: session=super-secret", InstanceID: "inst-1", Name: "n"}

	sess := s.newWildcardSubdomainSession(context.Background(), &config.Config{}, req, "example.com", "sub.example.com", "/data/scan/sub", false)

	if sess.targetAuth != "" {
		t.Errorf("sibling session targetAuth = %q, want empty (credentials must never reach discovered hosts)", sess.targetAuth)
	}
	if sess.scanMode != "wildcard" {
		t.Errorf("scanMode = %q, want wildcard", sess.scanMode)
	}
	if sess.target != "sub.example.com" || sess.parentTarget != "example.com" {
		t.Errorf("session target/parent = %q/%q, want sub.example.com/example.com", sess.target, sess.parentTarget)
	}
}

// TestWildcardDiscoveredHostsRecordedAsCandidatesAndResumeStatePreserved guards
// two behaviors: (1) resume reuses persisted ResumeSubdomains verbatim and never
// shells out to subfinder, and (2) discovered hosts are recorded as candidates
// with provenance subfinder and the "legacy wildcard candidate" label, while the
// originally-requested root is marked as such.
func TestWildcardDiscoveredHostsRecordedAsCandidatesAndResumeStatePreserved(t *testing.T) {
	s := &Server{}

	// Resume state preserved: discovery reuses ResumeSubdomains and does not run
	// subfinder (the configured path is intentionally nonexistent).
	req := ScanRequest{
		IsResume:            true,
		ResumeDiscoveryDone: true,
		ResumeSubdomains:    []string{"b.example.com", "a.example.com", "example.com", "a.example.com"},
	}
	got := s.discoverWildcardHosts(context.Background(), &config.Config{SubfinderPath: "/nonexistent/subfinder"}, req, "example.com", t.TempDir())
	want := []string{"a.example.com", "b.example.com", "example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("resumed hosts = %v, want %v (dedup+sort of ResumeSubdomains, no subfinder exec)", got, want)
	}

	// Candidate recording.
	dir := t.TempDir()
	if err := writeWildcardCandidates(dir, "example.com", []string{"api.example.com", "example.com"}); err != nil {
		t.Fatalf("writeWildcardCandidates: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "candidates.json"))
	if err != nil {
		t.Fatalf("read candidates.json: %v", err)
	}
	var cands []wildcardCandidate
	if err := json.Unmarshal(data, &cands); err != nil {
		t.Fatalf("unmarshal candidates: %v", err)
	}
	byHost := map[string]wildcardCandidate{}
	for _, c := range cands {
		byHost[c.Host] = c
	}
	disc, ok := byHost["api.example.com"]
	if !ok {
		t.Fatalf("api.example.com not recorded as candidate: %#v", cands)
	}
	if disc.Provenance != "subfinder" {
		t.Errorf("discovered host provenance = %q, want subfinder", disc.Provenance)
	}
	if disc.Label != "legacy wildcard candidate" {
		t.Errorf("discovered host label = %q, want legacy wildcard candidate", disc.Label)
	}
	if disc.Root {
		t.Errorf("discovered host must not be marked root")
	}
	root, ok := byHost["example.com"]
	if !ok || !root.Root {
		t.Fatalf("root host not recorded/marked as root: %#v", cands)
	}
}

// TestScannerConfigWiresScopeGuard guards the execution-time DNS-rebinding
// defence: ScannerConfig installs a ScopeGuard closure that re-runs the
// self-listener/local-target guard on both the raw URL and the addresses the
// host resolved to.
func TestScannerConfigWiresScopeGuard(t *testing.T) {
	s := &Server{cfg: &config.Config{BindAddr: "127.0.0.1"}, port: 8089}
	sc := s.ScannerConfig(&config.Config{})
	if sc.ScopeGuard == nil {
		t.Fatal("ScannerConfig did not wire ScopeGuard")
	}

	t.Run("listener address blocked", func(t *testing.T) {
		blocked, reason := sc.ScopeGuard("http://127.0.0.1:8089", nil)
		if !blocked {
			t.Fatalf("ScopeGuard allowed the dashboard listener address")
		}
		if reason == "" {
			t.Errorf("blocked verdict must carry a reason")
		}
	})

	t.Run("resolved loopback blocked (DNS rebinding)", func(t *testing.T) {
		blocked, _ := sc.ScopeGuard("http://evil.example.com", []string{"127.0.0.1"})
		if !blocked {
			t.Fatalf("ScopeGuard allowed a host that resolved to loopback")
		}
	})

	t.Run("external target allowed", func(t *testing.T) {
		if blocked, _ := sc.ScopeGuard("http://93.184.216.34:80", nil); blocked {
			t.Fatalf("ScopeGuard blocked a non-local external target")
		}
	})
}
