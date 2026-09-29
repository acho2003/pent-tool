package scanner

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// transcriptRecorder persists the same redacted chunks sent to the live feed,
// in their arrival order. Separate stdout/stderr files remain authoritative
// for troubleshooting and older records.
type transcriptRecorder struct {
	mu        sync.Mutex
	file      *os.File
	path      string
	written   int64
	limit     int64
	truncated bool
	secrets   []string
	seen      map[string]int64
	forward   EmitFunc
}

func newTranscriptRecorder(req Request, cfg Config, forward EmitFunc) *transcriptRecorder {
	return &transcriptRecorder{limit: cfg.MaxOutputBytes, secrets: secretValues(req, cfg), seen: make(map[string]int64), forward: forward}
}

func (t *transcriptRecorder) emit(event Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if event.Run.StdoutPath != "" && t.file == nil {
		path := filepath.Join(filepath.Dir(event.Run.StdoutPath), "combined.log")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err == nil {
			if f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); err == nil {
				t.file, t.path = f, path
			}
		}
	}
	if event.Type == "scanner_output" {
		event.Output = redact(event.Output, t.secrets)
		t.seen[event.Stream] += int64(len(event.Output))
		if t.file != nil {
			t.append([]byte(event.Output))
		}
	}
	if event.Run.Terminal() && t.file != nil {
		// A few adapters append their final error directly to stderr without
		// emitting a chunk. Include that tail, and early-failure logs too.
		for _, item := range []struct{ stream, path string }{{"stdout", event.Run.StdoutPath}, {"stderr", event.Run.StderrPath}} {
			f, err := os.Open(item.path)
			if err != nil {
				continue
			}
			_, err = f.Seek(t.seen[item.stream], io.SeekStart)
			if err == nil {
				data, _ := io.ReadAll(io.LimitReader(f, 1<<20))
				t.append([]byte(redact(string(data), t.secrets)))
			}
			_ = f.Close()
		}
	}
	if event.Run.Scanner != "" && t.path != "" {
		event.Run.TranscriptPath = t.path
		if event.Run.Terminal() {
			event.Run.Truncated = event.Run.Truncated || t.truncated
			event.Run = finalizeRun(event.Run)
		}
	}
	if t.forward != nil {
		t.forward(event)
	}
}

func (t *transcriptRecorder) append(data []byte) {
	if t.limit > 0 && t.written+int64(len(data)) > t.limit {
		remain := t.limit - t.written
		if remain < 0 {
			remain = 0
		}
		data = data[:int(remain)]
		t.truncated = true
	}
	if len(data) > 0 {
		n, _ := t.file.Write(data)
		t.written += int64(n)
	}
}

func (t *transcriptRecorder) finish(run Run) Run {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.file != nil {
		_ = t.file.Close()
		t.file = nil
		run.TranscriptPath = t.path
		run.Truncated = run.Truncated || t.truncated
		run = finalizeRun(run)
	}
	return run
}

func executeSpecWithTranscript(ctx context.Context, name string, req Request, cfg Config, spec commandSpec, emit EmitFunc) Run {
	transcript := newTranscriptRecorder(req, cfg, emit)
	run := executeSpec(ctx, name, req, cfg, spec, transcript.emit)
	return transcript.finish(run)
}
