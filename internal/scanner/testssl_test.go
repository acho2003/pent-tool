package scanner

import (
	"context"
	"os"
	"path/filepath"
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

func TestFailedTestsslRetainsOnlyVerifiedCompleteEntries(t *testing.T) {
	entry := `{"id":"TLS1_0","severity":"HIGH","ip":"example.test","port":"443","finding":"TLS 1.0 offered"}`
	for _, tc := range []struct {
		name, data string
		want       int
		parseError bool
	}{
		{"complete", "[" + entry + "]", 1, false},
		{"truncated", "[" + entry + `,{"id":"cut`, 1, true},
		{"unusable", `[{"id":`, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "results.json")
			if err := os.WriteFile(path, []byte(tc.data), 0o600); err != nil {
				t.Fatal(err)
			}
			run := finalizeRun(Run{Scanner: "testssl", Status: "failed", Reason: "exit status 3", ArtifactPath: path})
			findings, errs := ParseRuns([]Run{run})
			if len(findings) != tc.want || (len(errs) > 0) != tc.parseError {
				t.Fatalf("findings=%+v errors=%v", findings, errs)
			}
			if tc.want > 0 && findings[0].EvidenceCompleteness != "partial" {
				t.Fatalf("completeness=%q", findings[0].EvidenceCompleteness)
			}
			snapshot, snapshotErrs := BuildFindingsSnapshot([]Run{run}, nil)
			if len(snapshot.RawObservations) != tc.want || (len(snapshotErrs) > 0) != tc.parseError {
				t.Fatalf("observations=%+v errors=%v", snapshot.RawObservations, snapshotErrs)
			}
			if tc.want > 0 && (snapshot.RawObservations[0].SourceRunStatus != "failed" || snapshot.RawObservations[0].SourceRunReason != run.Reason || snapshot.RawObservations[0].EvidenceCompleteness != "partial") {
				t.Fatalf("partial provenance=%+v", snapshot.RawObservations[0])
			}
			if err := os.WriteFile(path, []byte(`[]`), 0o600); err != nil {
				t.Fatal(err)
			}
			findings, errs = ParseRuns([]Run{run})
			if len(findings) != 0 || len(errs) == 0 {
				t.Fatalf("changed artifact accepted: %+v, %v", findings, errs)
			}
		})
	}
}

func TestFailedTestsslWithoutJSONProducesNoFindings(t *testing.T) {
	run := finalizeRun(Run{Scanner: "testssl", Status: "failed", Reason: "exit status 3", ArtifactPath: filepath.Join(t.TempDir(), "missing.json")})
	findings, errs := ParseRuns([]Run{run})
	if len(findings) != 0 || len(errs) != 0 {
		t.Fatalf("diagnostics must not become findings: %+v, %v", findings, errs)
	}
}

func TestBuildTestsslThoroughHasNoOverallDeadline(t *testing.T) {
	spec := buildTestssl(Request{Target: "https://example.test/", ScanDir: t.TempDir(), Profile: ProfileThorough}, Config{TestsslPath: "testssl.sh", TestsslTimeout: time.Second})
	if spec.timeout != 0 {
		t.Fatalf("thorough testssl timeout = %s, want no overall deadline", spec.timeout)
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
