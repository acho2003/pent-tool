package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestTypedHTTPXUsesOnlyApprovedSchemeAndFiltersEvidence(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "httpx")
	argsPath := filepath.Join(dir, "args")
	seedsPath := filepath.Join(dir, "seeds")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsPath + "\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"-l\" ]; then shift; cp \"$1\" " + seedsPath + "; fi\n  if [ \"$1\" = \"-o\" ]; then shift; printf '%s\\n' '{\"url\":\"https://app.example.test/app\",\"scheme\":\"https\",\"status_code\":200}' '{\"url\":\"https://other.example.test/\",\"scheme\":\"https\",\"status_code\":200}' > \"$1\"; fi\n  shift\ndone\n"
	if err := os.WriteFile(tool, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	ac := assessment.AssessmentConfig{Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.example.test/app"}}}
	scope := assessment.AppScopeForTarget(ac, "app")
	run := (httpxRunner{}).Run(context.Background(), Request{Target: ac.Targets[0].Value, ScanDir: filepath.Join(dir, "scan"), AppScope: &scope}, Config{HttpxPath: tool, RateRPS: 2}, nil)
	if run.Status != "completed" || len(run.HTTPObservations) != 1 || run.HTTPObservations[0].StatusCode != 200 {
		t.Fatalf("HTTPX evidence: %+v", run)
	}
	seeds, err := os.ReadFile(seedsPath)
	if err != nil || string(seeds) != "https://app.example.test/app\n" {
		t.Fatalf("unapproved probe seed: %q err=%v", seeds, err)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil || !strings.Contains(string(args), "-nfs") {
		t.Fatalf("HTTPX could switch scheme: %q err=%v", args, err)
	}
}
