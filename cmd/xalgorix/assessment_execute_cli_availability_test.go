package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

// TestCLIAssessmentAvailabilityDetectsOptionalWebTools locks CLI/web parity: the
// optional staged web/API adapters (dalfox, wapiti, schemathesis, sslyze) must be
// reported available from genuine binary presence, not left out of the map and
// defaulted to the registry's Available:false.
func TestCLIAssessmentAvailabilityDetectsOptionalWebTools(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
		return p
	}
	cfg := scanner.Config{
		DalfoxPath:       mk("dalfox"),
		WapitiPath:       mk("wapiti"),
		SchemathesisPath: mk("schemathesis"),
		SSLyzePath:       mk("sslyze"),
		NiktoPath:        mk("nikto"),
	}
	got := cliAssessmentAvailability(cfg)
	for _, id := range []string{"dalfox", "wapiti", "schemathesis", "sslyze", "nikto"} {
		if !got[id] {
			t.Errorf("scanner %q with a present binary reported unavailable by CLI planner", id)
		}
	}
	// An unset path stays unavailable rather than being guessed from PATH.
	if got["prowler"] {
		t.Errorf("prowler with no configured path reported available")
	}
}
