package scanner

import (
	"os"
	"path/filepath"
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
	if got := semgrepConfigs(); !slices.Equal(got, registrySemgrepConfigs()) {
		t.Fatalf("blank override should fall back to the registry configs, got %v", got)
	}
}

func TestSemgrepPrefersBundledRulesOffline(t *testing.T) {
	dir := t.TempDir()
	for _, pack := range []string{"default", "typescript", "jwt"} { // partial bundle
		if err := os.WriteFile(filepath.Join(dir, pack+".yaml"), []byte("rules: []\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := bundledSemgrepRulesDir
	bundledSemgrepRulesDir = dir
	t.Cleanup(func() { bundledSemgrepRulesDir = old })

	got := semgrepConfigs()
	want := []string{filepath.Join(dir, "default.yaml"), filepath.Join(dir, "typescript.yaml"), filepath.Join(dir, "jwt.yaml")}
	if !slices.Equal(got, want) {
		t.Fatalf("bundled rules not preferred: got %v want %v", got, want)
	}
	// Env override still wins over the bundle.
	t.Setenv("XALGORIX_SEMGREP_CONFIGS", "p/ci")
	if got := semgrepConfigs(); !slices.Equal(got, []string{"p/ci"}) {
		t.Fatalf("env override should beat the bundle, got %v", got)
	}
}

func TestBuildSemgrepNoSource(t *testing.T) {
	spec := buildSemgrep(Request{ScanDir: t.TempDir()}, Config{SemgrepPath: "semgrep", SemgrepTimeout: time.Minute})
	if spec.notApp == "" {
		t.Fatalf("expected notApp when no source, got %+v", spec)
	}
}
