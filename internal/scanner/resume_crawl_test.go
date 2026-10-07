package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
