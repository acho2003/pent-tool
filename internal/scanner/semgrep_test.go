package scanner

import (
	"testing"
	"time"
)

func TestBuildSemgrepCommand(t *testing.T) {
	req := Request{Target: "/src/app", ScanDir: t.TempDir()}
	spec := buildSemgrep(req, Config{SemgrepPath: "semgrep", SemgrepTimeout: time.Minute})
	if spec.path != "semgrep" || spec.args[len(spec.args)-1] != "/src/app" {
		t.Fatalf("unexpected spec %+v", spec)
	}
}

func TestBuildSemgrepNoSource(t *testing.T) {
	spec := buildSemgrep(Request{ScanDir: t.TempDir()}, Config{SemgrepPath: "semgrep", SemgrepTimeout: time.Minute})
	if spec.notApp == "" {
		t.Fatalf("expected notApp when no source, got %+v", spec)
	}
}
