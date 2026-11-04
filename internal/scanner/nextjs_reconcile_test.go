package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestNextjsVersionReconciliationRequiresExplicitSealedComparableEvidence(t *testing.T) {
	for _, mode := range []string{"consistent", "conflict", "unrelated", "unknown-runtime", "partial-source", "tampered", "stale-plan", "ambiguous-runtime"} {
		t.Run(mode, func(t *testing.T) {
			body := nextjsLockJSON(t, 3, map[string]any{"node_modules/next": map[string]any{"version": "14.1.0"}})
			req := nextjsDependencyRequest(t, map[string][]byte{"package-lock.json": body})
			source := assessment.Target{ID: "src", Kind: assessment.KindLocalSourcePath, Value: req.Target}
			req.Scope = assessmentJobScope(PlanJob{TargetID: source.ID, Target: source.Value})
			sourceRun := (nextjsDepsRunner{}).Run(t.Context(), req, Config{}, nil)
			sourceRun.PlanFingerprint = "accepted"
			if mode == "partial-source" {
				sourceRun.Completeness = "partial"
				sourceRun.Outcome = "PARTIAL"
			}
			if mode == "stale-plan" {
				sourceRun.PlanFingerprint = "older"
			}
			sourceRun = finalizeRun(sourceRun)
			var hits atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if r.URL.Path == "/" {
					fmt.Fprint(w, `<script>self.__next_f=[]</script><script src='/_next/static/main.js'></script>`)
					return
				}
				if r.URL.Path == "/_next/static/main.js" {
					version := "14.1.0"
					if mode == "conflict" || mode == "partial-source" {
						version = "15.0.0"
					}
					if mode == "unknown-runtime" {
						fmt.Fprint(w, "console.log('public')")
					} else {
						fmt.Fprintf(w, `window.next={version:"%s"};`, version)
					}
					return
				}
				http.NotFound(w, r)
			}))
			defer server.Close()
			runtimeReq := nextjsTestRequest(t, server.URL+"/")
			web := assessment.Target{ID: "web", Kind: assessment.KindURL, Value: runtimeReq.Target, RelatedTo: "src"}
			if mode == "unrelated" {
				web.RelatedTo = ""
			}
			runtimeReq.Scope = assessmentJobScope(PlanJob{TargetID: web.ID, Target: web.Value})
			runtimeRun := (nextjsAssetsRunner{}).Run(t.Context(), runtimeReq, Config{}, nil)
			runtimeRun.PlanFingerprint = "accepted"
			runtimeRun = finalizeRun(runtimeRun)
			if mode == "tampered" {
				file, _ := os.OpenFile(sourceRun.SourceManifestPath, os.O_WRONLY|os.O_APPEND, 0600)
				file.WriteString("\n")
				file.Close()
			}
			cfg := assessment.AssessmentConfig{Mode: assessment.ModeWhiteBox, Types: []assessment.Type{assessment.TypeSourceCode, assessment.TypeWebApplication}, Targets: []assessment.Target{source, web}}
			runs := []Run{sourceRun, runtimeRun}
			if mode == "ambiguous-runtime" {
				runs = append(runs, runtimeRun)
			}
			before := hits.Load()
			comparisons := reconcileNextjsEvidence(cfg, runs, t.TempDir(), "accepted", "comparison")
			if hits.Load() != before {
				t.Fatal("evidence comparison made network requests")
			}
			if mode == "unrelated" {
				if len(comparisons) != 0 {
					t.Fatal("target relationship was guessed")
				}
				return
			}
			if len(comparisons) != 1 {
				t.Fatal("comparison missing")
			}
			run := comparisons[0]
			findings, err := ParseRun(run)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := os.ReadFile(run.SourceManifestPath)
			var evidence nextjsVersionComparison
			json.Unmarshal(raw, &evidence)
			switch mode {
			case "consistent":
				if evidence.State != "consistent" || len(findings) != 0 || run.Completeness != "complete" {
					t.Fatalf("consistent evidence lost: %+v", run)
				}
			case "conflict":
				if evidence.State != "conflict" || len(findings) != 1 || findings[0].Severity != "info" || findings[0].CVE != "" || findings[0].Confidence != "evidence_conflict" {
					t.Fatal("conflict overstated or source advisory transferred")
				}
			default:
				if run.Outcome != "PARTIAL" || len(findings) != 0 || evidence.State != "unknown" {
					t.Fatalf("untrusted evidence produced a comparison: %+v", run)
				}
			}
			if err := VerifyChecksum(run); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "private.example") {
				t.Fatal("source URLs retained")
			}
		})
	}
}

func TestNextjsVersionReconciliationRunsAfterNativeAssessmentJobs(t *testing.T) {
	body := nextjsLockJSON(t, 3, map[string]any{"node_modules/next": map[string]any{"version": "14.1.0"}})
	request := nextjsDependencyRequest(t, map[string][]byte{"package-lock.json": body})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			fmt.Fprint(w, `<script>self.__next_f=[]</script><script src='/_next/static/main.js'></script>`)
			return
		}
		if r.URL.Path == "/_next/static/main.js" {
			fmt.Fprint(w, `window.next={version:"14.1.0"};`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	config := assessment.AssessmentConfig{Mode: assessment.ModeWhiteBox, Types: []assessment.Type{assessment.TypeSourceCode, assessment.TypeWebApplication}, Targets: []assessment.Target{{ID: "src", Kind: assessment.KindLocalSourcePath, Value: request.Target}, {ID: "web", Kind: assessment.KindURL, Value: server.URL + "/", RelatedTo: "src"}}, ScannerSelection: assessment.ScannerSelection{Mode: "custom", Variants: []string{"nextjs-deps", "nextjs-assets"}}}
	plan := PlanAssessment(PlanInput{Config: config})
	// Exercise native jobs without requiring an installed external crawler.
	jobs := plan.Jobs[:0]
	for _, job := range plan.Jobs {
		if job.Scanner == "nextjs-assets" || job.Scanner == "nextjs-deps" {
			job.Dependencies = nil
			jobs = append(jobs, job)
		}
	}
	plan.Jobs = jobs
	runs := NewPipeline(Config{}).RunAssessmentJobs(t.Context(), plan, t.TempDir(), nil, nil)
	count := 0
	for _, run := range runs {
		if run.Scanner == "nextjs-reconcile" {
			count++
			if run.Status != "completed" || run.Outcome != "SUCCESS_NO_FINDINGS" || run.Stage != StageResults {
				t.Fatalf("post-assessment evidence correlation failed: %+v", run)
			}
		}
	}
	if count != 1 {
		t.Fatalf("comparison should run once after both inputs; got %d", count)
	}
}
