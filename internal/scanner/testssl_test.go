package scanner

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestBuildTestsslCommand(t *testing.T) {
	req := Request{Target: "example.com", ScanDir: t.TempDir()}
	cfg := Config{TestsslPath: "testssl.sh", TestsslTimeout: 5 * time.Minute}
	spec := buildTestssl(req, cfg)
	if spec.path != "testssl.sh" {
		t.Errorf("path = %q", spec.path)
	}
	if spec.timeout != 5*time.Minute {
		t.Errorf("timeout = %v", spec.timeout)
	}
	if !strings.HasSuffix(spec.artifact, "results.json") {
		t.Errorf("artifact = %q", spec.artifact)
	}
	// jsonfile must point at the artifact and the target must be last.
	if !slices.Contains(spec.args, "--jsonfile") {
		t.Errorf("args missing --jsonfile: %v", spec.args)
	}
	if spec.args[len(spec.args)-1] != "example.com" {
		t.Errorf("target not last arg: %v", spec.args)
	}
}

func TestBuildTestsslRejectsArtifactTarget(t *testing.T) {
	req := Request{Target: "artifact://blob", ScanDir: t.TempDir()}
	spec := buildTestssl(req, Config{TestsslPath: "testssl.sh", TestsslTimeout: time.Minute})
	if spec.notApp == "" {
		t.Errorf("expected notApp for artifact target, got spec %+v", spec)
	}
}
