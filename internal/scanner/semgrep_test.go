package scanner

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestBuildSemgrepCommand(t *testing.T) {
	req := Request{Target: "/src/app", ScanDir: t.TempDir()}
	spec := buildSemgrep(req, Config{SemgrepPath: "semgrep", SemgrepTimeout: time.Minute})
	if spec.path != "semgrep" || spec.args[len(spec.args)-1] != "/src/app" {
		t.Fatalf("unexpected spec %+v", spec)
	}
	joined := strings.Join(spec.args, " ")
	for _, want := range []string{"p/default", "p/typescript", "p/nodejs", "p/owasp-top-ten", "p/jwt", "p/secrets", "p/docker"} {
		if !strings.Contains(joined, "--config "+want) {
			t.Fatalf("missing ruleset %q in %v", want, spec.args)
		}
	}
}

func TestSemgrepConfigsEnvOverride(t *testing.T) {
	t.Setenv("XALGORIX_SEMGREP_CONFIGS", " p/ci , ./local-rules.yaml ,, ")
	got := semgrepConfigs()
	if !slices.Equal(got, []string{"p/ci", "./local-rules.yaml"}) {
		t.Fatalf("override parse = %v", got)
	}
	t.Setenv("XALGORIX_SEMGREP_CONFIGS", "   ")
	if got := semgrepConfigs(); !slices.Equal(got, defaultSemgrepConfigs) {
		t.Fatalf("blank override should fall back to defaults, got %v", got)
	}
}

func TestBuildSemgrepNoSource(t *testing.T) {
	spec := buildSemgrep(Request{ScanDir: t.TempDir()}, Config{SemgrepPath: "semgrep", SemgrepTimeout: time.Minute})
	if spec.notApp == "" {
		t.Fatalf("expected notApp when no source, got %+v", spec)
	}
}
