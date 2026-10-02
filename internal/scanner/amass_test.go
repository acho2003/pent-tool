package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAmassPassiveCandidatesStayWithinSubmittedDomain(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "amass")
	argsPath := filepath.Join(dir, "args")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsPath + "\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"-o\" ]; then shift; printf '%s\\n' 'api.example.test' 'other.test' 'api.example.test' > \"$1\"; fi\n  shift\ndone\n"
	if err := os.WriteFile(tool, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	run := (amassRunner{}).Run(context.Background(), Request{Target: "example.test", ScanDir: dir}, Config{AmassPath: tool}, nil)
	if run.Status != "completed" || len(run.CandidateHosts) != 1 || run.CandidateHosts[0] != "api.example.test" {
		t.Fatalf("Amass candidates: %+v", run)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil || !strings.Contains(string(args), "-passive") || strings.Contains(string(args), "-active") {
		t.Fatalf("Amass was not passive: %q err=%v", args, err)
	}
}
