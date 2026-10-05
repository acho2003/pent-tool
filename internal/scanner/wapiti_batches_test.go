package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWapitiBatchesCoverMoreThanFiftyInputs(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	bin := filepath.Join(t.TempDir(), "wapiti")
	os.WriteFile(bin, []byte("#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf '{\"vulnerabilities\":{}}' > \"$1\"; fi; shift; done\n"), 0700)
	req := Request{Target: "https://app.test/?q=0", StructuredDispatch: true, TestEnvironment: true, ScanDir: t.TempDir()}
	for i := 0; i < 111; i++ {
		req.EndpointTargets = append(req.EndpointTargets, fmt.Sprintf("https://app.test/?q=%d", i))
	}
	run := wapitiRunner{}.Run(context.Background(), req, Config{WapitiPath: bin, WapitiTimeout: time.Minute}, nil)
	if run.Status != "completed" || len(run.BatchRuns) != 3 || len(run.Submissions) != 111 {
		t.Fatalf("status=%s reason=%s batches=%d submissions=%d", run.Status, run.Reason, len(run.BatchRuns), len(run.Submissions))
	}
}
