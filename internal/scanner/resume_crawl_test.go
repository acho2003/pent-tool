package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

// A crawl killed mid-run leaves a truncated artifact next to a "running" run.
// Resuming must discard it and crawl again, not parse it as a finished crawl.
func TestResumeDiscardsPartialCrawlOutputFromInterruptedAttempt(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	bin := filepath.Join(t.TempDir(), "katana")
	script := `#!/bin/sh
touch "${0%/*}/ran"
while [ $# -gt 0 ]; do
 case "$1" in -o) shift; printf '{"request":{"method":"GET","endpoint":"http://127.0.0.1:1/app/fresh"},"response":{"status_code":200}}\n' > "$1" ;; esac
 shift
done
`
	if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	target := assessment.Target{ID: "app", Kind: assessment.KindURL, Value: "http://127.0.0.1:1/app/"}
	cfg := Config{KatanaPath: bin, WebMaxEndpoints: 10, RateRPS: 10}
	root := t.TempDir()
	crawlReq := Request{Target: target.Value, Scope: "discovery:app", ScanDir: filepath.Join(root, "discovery", stableJobPath("app")), TypedAssessment: true}
	artifact := buildKatana(crawlReq, cfg).artifact
	if err := os.MkdirAll(filepath.Dir(artifact), 0700); err != nil {
		t.Fatal(err)
	}
	stale := `{"request":{"method":"GET","endpoint":"http://127.0.0.1:1/app/stale-partial"},"response":{"status_code":200}}` + "\n"
	if err := os.WriteFile(artifact, []byte(stale), 0600); err != nil {
		t.Fatal(err)
	}
	plan := katanaLimitationPlan("unified-v1", target)
	interrupted := Run{Scanner: "katana", Scope: "discovery:app", Target: target.Value, Status: "running"}
	pipeline := Pipeline{Config: cfg}
	pipeline.RunAssessmentJobs(t.Context(), plan, root, []Run{interrupted}, nil)

	if _, err := os.Stat(filepath.Join(filepath.Dir(bin), "ran")); err != nil {
		t.Fatal("katana was not run again after an interrupted attempt")
	}
	var urls []string
	for _, surface := range LoadAttackSurfaces(root) {
		for _, endpoint := range surface.Endpoints {
			urls = append(urls, endpoint.URL)
		}
	}
	joined := strings.Join(urls, " ")
	if strings.Contains(joined, "stale-partial") || !strings.Contains(joined, "/app/fresh") {
		t.Fatalf("inventory was built from the interrupted attempt's output: %v", urls)
	}
}

// A per-tool stop must reach the katana crawl: the crawl is registered with its
// own attempt ID, and stopping it cancels that attempt without failing the job
// as a clean zero-result crawl.
func TestKatanaCrawlHasItsOwnCancellableAttempt(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	bin := filepath.Join(t.TempDir(), "katana")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\ntouch \"${0%/*}/started\"\nexec sleep 30\n"), 0700); err != nil {
		t.Fatal(err)
	}
	target := assessment.Target{ID: "app", Kind: assessment.KindURL, Value: "http://127.0.0.1:1/app/"}
	pipeline := Pipeline{Config: Config{KatanaPath: bin, WebMaxEndpoints: 10, RateRPS: 10}}
	registered := make(chan string, 4)
	cancels := make(chan func(), 4)
	pipeline.AttemptControl = func(id string, cancel context.CancelFunc) func() {
		registered <- id
		cancels <- cancel
		return func() {}
	}
	var running Run
	emit := func(event Event) {
		if event.Scanner == "katana" && event.Run.Status == "running" && event.Run.AttemptID != "" {
			running = event.Run
		}
	}
	done := make(chan []Run, 1)
	go func() {
		done <- pipeline.RunAssessmentJobs(t.Context(), katanaLimitationPlan("unified-v1", target), t.TempDir(), nil, emit)
	}()

	var attemptID string
	var cancel func()
	select {
	case attemptID = <-registered:
		cancel = <-cancels
	case runs := <-done:
		t.Fatalf("assessment ended before the crawl registered an attempt: %+v", runs)
	case <-time.After(20 * time.Second):
		t.Fatal("the katana crawl never registered a cancellable attempt")
	}
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(filepath.Join(filepath.Dir(bin), "started")); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	var runs []Run
	select {
	case runs = <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("stopping the crawl did not end it")
	}
	var crawl Run
	for _, run := range runs {
		if run.Scanner == "katana" {
			crawl = run
		}
	}
	if crawl.Status != "cancelled" || crawl.AttemptID != attemptID || crawl.Completeness != "partial" {
		t.Fatalf("stopped crawl = status %q attempt %q (registered %q) completeness %q", crawl.Status, crawl.AttemptID, attemptID, crawl.Completeness)
	}
	if running.AttemptID != attemptID {
		t.Fatalf("running event carried attempt %q, want %q", running.AttemptID, attemptID)
	}
}

// A GraphQL operation's path is the endpoint's own absolute path. Mapping it onto
// a target that already includes that path must not duplicate the endpoint.
func TestGraphQLOperationURLIsNotJoinedToTheTargetPath(t *testing.T) {
	sdl := []byte("type Query {\n  record(id: ID = \"x\"): String\n}\n\ntype Mutation {\n  deleteRecord(id: ID!): Boolean\n}\n")
	for _, target := range []string{"http://lab.test:8080/app/graphql", "http://lab.test:8080/"} {
		want := "http://lab.test:8080/app/graphql"
		if target == "http://lab.test:8080/" {
			want = "http://lab.test:8080/graphql"
		}
		endpoints, err := ParseAPIDefinition(sdl, target)
		if err != nil {
			t.Fatal(err)
		}
		for _, endpoint := range endpoints {
			endpoint.Resolved, endpoint.Eligible, endpoint.Method = true, true, "GET"
			endpoint.RequestURL = ""
			got, urlErr := apiEndpointURL(target, endpoint)
			if urlErr != nil {
				// A materialized query is required for GraphQL reads; the path must
				// still be right when it is available.
				endpoint.RequestURL = want + "?query=x"
				got, urlErr = apiEndpointURL(target, endpoint)
			}
			if urlErr == nil && got != want && !strings.HasPrefix(got, want+"?") {
				t.Fatalf("target %s: operation %s mapped to %s, want %s", target, endpoint.OperationID, got, want)
			}
		}
	}
}
