package scanner

import (
	"context"
	"fmt"
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWapitiBatchesCoverMoreThanFiftyInputs(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	bin := filepath.Join(t.TempDir(), "wapiti")
	os.WriteFile(bin, []byte("#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf '{\"vulnerabilities\":{}}' > \"$1\"; fi; shift; done\n"), 0700)
	req := Request{WorkflowVersion: "unified-v1", Target: "https://app.test/?q=0", StructuredDispatch: true, TestEnvironment: true, ScanDir: t.TempDir()}
	for i := 0; i < 111; i++ {
		req.EndpointTargets = append(req.EndpointTargets, fmt.Sprintf("https://app.test/?q=%d", i))
	}
	run := wapitiRunner{}.Run(context.Background(), req, Config{WapitiPath: bin, WapitiTimeout: time.Minute}, nil)
	if run.Status != "completed" || len(run.BatchRuns) != 3 || len(run.Submissions) != 111 {
		t.Fatalf("status=%s reason=%s batches=%d submissions=%d", run.Status, run.Reason, len(run.BatchRuns), len(run.Submissions))
	}
}

// Exercise the actual assessment dispatcher, not just the batching helper.
func TestAssessmentWapitiRoutes684RequestsWithoutFiftyInputCeiling(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	root := t.TempDir()
	bin := filepath.Join(t.TempDir(), "wapiti")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf '{\"vulnerabilities\":{}}' > \"$1\"; fi; shift; done\n"), 0700); err != nil {
		t.Fatal(err)
	}
	target := assessment.Target{ID: "app", Kind: assessment.KindURL, Value: server.URL + "/?q=0"}
	cfg := Config{KatanaPath: "/nonexistent/katana", WapitiPath: bin, WapitiTimeout: time.Minute, WebMaxEndpoints: 1000, RateRPS: 10000}
	crawlReq := Request{Target: target.Value, Scope: "discovery:app", ScanDir: filepath.Join(root, "discovery", stableJobPath("app")), TypedAssessment: true}
	artifact := buildKatana(crawlReq, cfg).artifact
	if err := os.MkdirAll(filepath.Dir(artifact), 0700); err != nil {
		t.Fatal(err)
	}
	var rows strings.Builder
	for i := 0; i < 684; i++ {
		fmt.Fprintf(&rows, "{\"request\":{\"method\":\"GET\",\"endpoint\":%q},\"response\":{\"status_code\":200}}\n", fmt.Sprintf("%s/?q=%d", server.URL, i))
	}
	if err := os.WriteFile(artifact, []byte(rows.String()), 0600); err != nil {
		t.Fatal(err)
	}
	plan := AssessmentPlan{Fingerprint: "fixture-684", Config: assessment.AssessmentConfig{WorkflowVersion: "unified-v1", TestEnvironment: true, Targets: []assessment.Target{target}, Types: []assessment.Type{assessment.TypeWebApplication}}, Jobs: []PlanJob{{ID: "katana-app", Scanner: "katana", Variant: "katana", TargetID: "app", Target: target.Value, State: PlanSelected, AssessmentType: assessment.TypeWebApplication}, {ID: "wapiti-app", Scanner: "wapiti", Variant: "wapiti", TargetID: "app", Target: target.Value, State: PlanSelected, AssessmentType: assessment.TypeWebApplication}}}
	pipeline := Pipeline{Config: cfg}
	runs := pipeline.RunAssessmentJobs(t.Context(), plan, root, nil, nil)
	var run Run
	for _, result := range runs {
		if result.Scanner == "wapiti" {
			run = result
		}
	}
	if run.Status != "completed" || len(run.BatchRuns) != 14 || len(run.Submissions) != 684 {
		t.Fatalf("status=%s reason=%s batches=%d submissions=%d", run.Status, run.Reason, len(run.BatchRuns), len(run.Submissions))
	}
	ids := map[string]bool{}
	for _, submission := range run.Submissions {
		if submission.Status != "submitted" || submission.EndpointID == "" || ids[submission.EndpointID] {
			t.Fatalf("invalid or duplicate submission: %+v", submission)
		}
		ids[submission.EndpointID] = true
	}
	if got := endpointDispatchLimitForWorkflow("wapiti", 1000, false); got != 50 {
		t.Fatalf("legacy limit changed: %d", got)
	}
}
