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
	if err := os.WriteFile(bin, []byte(`#!/bin/sh
receipt="${0%/*}/received-inputs.txt"
while [ $# -gt 0 ]; do
 case "$1" in
  -u|--start) shift; printf '%s\n' "$1" >> "$receipt" ;;
  -o) shift; printf '{"vulnerabilities":{}}' > "$1" ;;
 esac
 shift
done
`), 0700); err != nil {
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
	received, err := os.ReadFile(filepath.Join(filepath.Dir(bin), "received-inputs.txt"))
	if err != nil {
		t.Fatal(err)
	}
	processInputs := strings.Split(strings.TrimSpace(string(received)), "\n")
	if len(processInputs) != 684 {
		t.Fatalf("scanner process received %d inputs, expected 684", len(processInputs))
	}
	delivered := map[string]bool{}
	for _, raw := range processInputs {
		if delivered[raw] {
			t.Fatal("scanner process received a duplicate input", raw)
		}
		delivered[raw] = true
	}
	for i := 0; i < 684; i++ {
		if !delivered[fmt.Sprintf("%s/?q=%d", server.URL, i)] {
			t.Fatalf("scanner process did not receive input %d", i)
		}
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

// Opt-in disposable-runtime acceptance: unlike the command receipt fixture,
// this verifies requests actually received by a local lab through the gateway.
func TestWapitiRuntimeBatchesExerciseSelectedInputs(t *testing.T) {
	if os.Getenv("XALGORIX_TEST_WAPITI") != "1" {
		t.Skip("requires the retained native Wapiti runtime")
	}
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><title>Local request fixture</title><body>fixture</body></html>")
	}))
	defer server.Close()
	origin, _ := assessment.ParseApprovedOrigin("app", server.URL)
	origin.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	req := Request{WorkflowVersion: "unified-v1", Target: server.URL + "/?q=0", StructuredDispatch: true, TypedAssessment: true, TestEnvironment: true, AppScope: &scope, ScanDir: t.TempDir(), AttemptID: "native-wapiti"}
	for i := 0; i < 684; i++ {
		raw := fmt.Sprintf("%s/?q=%d", server.URL, i)
		req.EndpointTargets = append(req.EndpointTargets, raw)
		req.InputRequests = append(req.InputRequests, ScannerRequestInput{EndpointID: fmt.Sprintf("request-%d", i), URL: raw, Method: "GET", Selected: true})
	}
	cfg := Config{WapitiPath: "/usr/local/bin/wapiti", WapitiTimeout: 3 * time.Minute, RateRPS: 10000, WebMaxEndpoints: 1000, MaxOutputBytes: 8 << 20, Budget: NewAssessmentBudget(10000, 1000, 3*time.Minute)}
	gateway, err := NewRecordingGateway(t.Context(), req, cfg, "wapiti")
	if err != nil {
		t.Fatal(err)
	}
	req.GatewayURL, req.GatewayCAPath, req.Gateway = gateway.URL, gateway.CAPath, gateway
	run := wapitiRunner{}.Run(t.Context(), req, cfg, nil)
	if err := gateway.Close(); err != nil {
		t.Fatal(err)
	}
	if run.Status != "completed" || len(run.BatchRuns) != 14 || len(run.Submissions) != 684 {
		for _, batch := range run.BatchRuns {
			t.Logf("batch: %s %s stderr=%s", batch.Status, batch.Reason, readCapped(batch.StderrPath, 4000))
		}
		t.Fatalf("native batches: status=%s reason=%s batches=%d submissions=%d", run.Status, run.Reason, len(run.BatchRuns), len(run.Submissions))
	}
	events, err := ReadCoverageEvents(gateway.EventPath)
	if err != nil {
		t.Fatal(err)
	}
	exercised := map[string]bool{}
	for _, event := range events {
		if event.Kind == "observed" {
			for _, id := range event.EndpointIDs {
				exercised[id] = true
			}
		}
	}
	for _, input := range req.InputRequests {
		if !exercised[input.EndpointID] {
			t.Errorf("no native HTTP receipt for %s", input.EndpointID)
		}
	}
	t.Logf("native HTTP receipts: %d selected variants in %d batches", len(exercised), len(run.BatchRuns))
}
