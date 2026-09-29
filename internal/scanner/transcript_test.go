package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTranscriptRecordsMixedStreamsAndSealsChecksum(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "scanner")
	script := "#!/bin/sh\nprintf 'first\\n'; sleep 0.02; printf 'secret-token\\n' >&2; sleep 0.02; printf 'last\\n'\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	run := executeSpecWithTranscript(context.Background(), "fixture", Request{Target: "test", ScanDir: dir, Secrets: []string{"secret-token"}}, Config{MaxOutputBytes: 1 << 20}, commandSpec{path: bin, timeout: time.Second}, nil)
	if run.Status != "completed" || run.TranscriptPath == "" || VerifyChecksum(run) != nil {
		t.Fatalf("run = %+v", run)
	}
	combined, err := os.ReadFile(run.TranscriptPath)
	if err != nil || string(combined) != "first\n[REDACTED]\nlast\n" {
		t.Fatalf("combined = %q, error = %v", combined, err)
	}
	if err := os.WriteFile(run.TranscriptPath, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if VerifyChecksum(run) == nil {
		t.Fatal("changed transcript passed checksum verification")
	}
}

func TestTranscriptCapsCombinedOutputAndKeepsSeparateLogs(t *testing.T) {
	dir := t.TempDir()
	stdout := filepath.Join(dir, "stdout.log")
	stderr := filepath.Join(dir, "stderr.log")
	for _, path := range []string{stdout, stderr} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	recorder := newTranscriptRecorder(Request{ScanDir: dir}, Config{MaxOutputBytes: 6}, nil)
	recorder.emit(Event{Type: "scanner_started", Run: Run{Scanner: "fixture", StdoutPath: stdout, StderrPath: stderr}})
	recorder.emit(Event{Type: "scanner_output", Output: "abcd", Stream: "stdout"})
	recorder.emit(Event{Type: "scanner_output", Output: "efgh", Stream: "stderr"})
	run := recorder.finish(Run{Scanner: "fixture", Status: "completed", StdoutPath: stdout, StderrPath: stderr})
	data, err := os.ReadFile(run.TranscriptPath)
	if err != nil || string(data) != "abcdef" || !run.Truncated {
		t.Fatalf("capped transcript = %q, run = %+v, error = %v", data, run, err)
	}
	if !strings.HasSuffix(run.TranscriptPath, "combined.log") {
		t.Fatalf("unexpected transcript path %q", run.TranscriptPath)
	}
}

func TestTranscriptIncludesUnemittedFinalError(t *testing.T) {
	dir := t.TempDir()
	stdout := filepath.Join(dir, "stdout.log")
	stderr := filepath.Join(dir, "stderr.log")
	if err := os.WriteFile(stdout, []byte("progress\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stderr, []byte("secret-token failed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	recorder := newTranscriptRecorder(Request{ScanDir: dir, Secrets: []string{"secret-token"}}, Config{MaxOutputBytes: 100}, nil)
	recorder.emit(Event{Type: "scanner_started", Run: Run{Scanner: "fixture", StdoutPath: stdout, StderrPath: stderr}})
	recorder.emit(Event{Type: "scanner_output", Output: "progress\n", Stream: "stdout"})
	recorder.emit(Event{Type: "scanner_failed", Run: Run{Scanner: "fixture", Status: "failed", StdoutPath: stdout, StderrPath: stderr}})
	run := recorder.finish(Run{Scanner: "fixture", Status: "failed", StdoutPath: stdout, StderrPath: stderr})
	data, err := os.ReadFile(run.TranscriptPath)
	if err != nil || string(data) != "progress\n[REDACTED] failed\n" {
		t.Fatalf("final error tail = %q, error = %v", data, err)
	}
}
