package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSubfinderCandidatesNeverExpandAcceptedScope(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "subfinder")
	script := "#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"-o\" ]; then\n    shift\n    printf '%s\\n' '{\"host\":\"api.example.test\"}' '{\"host\":\"api.example.test\"}' '{\"host\":\"other.test\"}' > \"$1\"\n  fi\n  shift\ndone\n"
	if err := os.WriteFile(tool, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	run := (subfinderRunner{}).Run(context.Background(), Request{Target: "example.test", ScanDir: dir}, Config{SubfinderPath: tool}, nil)
	if run.Status != "completed" || len(run.CandidateHosts) != 1 || run.CandidateHosts[0] != "api.example.test" {
		t.Fatalf("unsafe candidates: %+v", run)
	}
}
