package scanner

import (
	"context"
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

func TestTestsslConnectFailureClassify(t *testing.T) {
	fails := []string{
		"Unable to open a socket to 18.141.2.254:443.",
		`Fatal error: Can't connect to "1.2.3.4:443"`,
		"Oops: TCP connect problem",
	}
	for _, out := range fails {
		status, reason, ok := testsslConnectFailure(246, out)
		if !ok || status != "not_applicable" || reason == "" {
			t.Errorf("output %q -> status=%q reason=%q ok=%v (want not_applicable)", out, status, reason, ok)
		}
	}
	if _, _, ok := testsslConnectFailure(1, "Testing protocols via sockets ... offered"); ok {
		t.Error("a normal testssl run must not be reclassified as a connect failure")
	}
}

func TestBuildTestsslSetsConnectClassifier(t *testing.T) {
	spec := buildTestssl(Request{Target: "example.com", ScanDir: t.TempDir()}, Config{TestsslPath: "testssl.sh", TestsslTimeout: time.Minute})
	if spec.classify == nil {
		t.Fatal("buildTestssl must set a classify hook so an unreachable HTTPS host reads clearly")
	}
}

func TestExecuteSpecAppliesClassifyOnFailure(t *testing.T) {
	dir := t.TempDir()
	spec := commandSpec{
		path:     "sh",
		args:     []string{"-c", "echo 'Unable to open a socket to x:443'; exit 246"},
		timeout:  time.Minute,
		classify: testsslConnectFailure,
	}
	run := executeSpec(context.Background(), "testssl", Request{Target: "x", ScanDir: dir}, Config{MaxOutputBytes: 1 << 20}, spec, nil)
	if run.Status != "not_applicable" {
		t.Fatalf("classify hook not applied: status=%q reason=%q", run.Status, run.Reason)
	}
	if !strings.Contains(run.Reason, "TLS") {
		t.Errorf("reason = %q, want it to mention TLS reachability", run.Reason)
	}
}

func TestExecuteSpecClassifyLeavesRealFailureAlone(t *testing.T) {
	spec := commandSpec{
		path:     "sh",
		args:     []string{"-c", "echo 'parse error'; exit 3"},
		timeout:  time.Minute,
		classify: testsslConnectFailure,
	}
	run := executeSpec(context.Background(), "testssl", Request{Target: "x", ScanDir: t.TempDir()}, Config{MaxOutputBytes: 1 << 20}, spec, nil)
	if run.Status != "failed" {
		t.Fatalf("a non-connect failure must stay failed, got %q", run.Status)
	}
}
