package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func sastSource(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "app", "api"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"package.json": `{"dependencies":{"next":"16.4.3"}}`, "app/api/route.ts": `export function GET(req) { return fetch(req.nextUrl.searchParams.get('url')); }`} {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(name)), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}
func fakeSastEngine(t *testing.T, report string, exit string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "semgrep-fixture")
	body := "#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\nif [ \"$1\" = --output ]; then out=\"$2\"; shift 2; else shift; fi\ndone\ncat >\"$out\" <<'REPORT'\n" + report + "\nREPORT\nexit " + exit + "\n"
	if err := os.WriteFile(file, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	return file
}
func TestNextjsSASTNormalizesOnlyLocationsAndPreservesPartialFindings(t *testing.T) {
	for _, mode := range []string{"success", "partial", "malformed", "unknown-rule", "outside-file"} {
		t.Run(mode, func(t *testing.T) {
			source := sastSource(t)
			rule, path := "nextjs-route-query-fetch", "app/api/route.ts"
			if mode == "unknown-rule" {
				rule = "unreviewed-rule"
			}
			if mode == "outside-file" {
				path = "../../outside.ts"
			}
			raw := `{"results":[{"check_id":"` + rule + `","path":"` + path + `","start":{"line":1},"extra":{"message":"SOURCE_VALUE_MUST_NOT_SURVIVE","lines":"SECRET_MATCHED_SOURCE"}}],"errors":[],"paths":{"scanned":["app/api/route.ts"]}}`
			if mode == "malformed" {
				raw = `{"results":[]}`
			}
			exit := "0"
			if mode == "partial" {
				exit = "2"
			}
			req := Request{Target: source, ScanDir: t.TempDir(), Scope: "source:fixture", TypedAssessment: true}
			run := (nextjsSASTRunner{}).Run(t.Context(), req, Config{SemgrepPath: fakeSastEngine(t, raw, exit)}, nil)
			if mode == "malformed" || mode == "unknown-rule" || mode == "outside-file" {
				if run.Status != "failed" || run.ParserOutcome != "FAILED" {
					t.Fatalf("invalid report accepted: %+v", run)
				}
				return
			}
			if mode == "partial" {
				if run.Status != "failed" || run.Outcome != "PARTIAL" {
					t.Fatalf("partial result lost: %+v", run)
				}
			} else if run.Status != "completed" || run.Outcome != "SUCCESS_WITH_FINDINGS" {
				t.Fatalf("run=%+v", run)
			}
			findings, errs := ParseRuns([]Run{run})
			if len(errs) > 0 || len(findings) != 1 {
				t.Fatalf("findings=%+v errs=%v run=%+v", findings, errs, run)
			}
			if findings[0].Confidence != "local_dataflow" || findings[0].SourceLocation != "app/api/route.ts:1" || findings[0].Severity != "medium" {
				t.Fatalf("source evidence overstated or lost: %+v", findings[0])
			}
			for _, path := range []string{run.ArtifactPath, run.SourceManifestPath} {
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				for _, secret := range []string{"SOURCE_VALUE_MUST_NOT_SURVIVE", "SECRET_MATCHED_SOURCE", "return fetch("} {
					if strings.Contains(string(body), secret) {
						t.Fatal("source contents persisted")
					}
				}
			}
			if err := VerifyChecksum(run); err != nil {
				t.Fatal(err)
			}
			file, err := os.OpenFile(run.SourceManifestPath, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			file.Write([]byte(" "))
			file.Close()
			if VerifyChecksum(run) == nil {
				t.Fatal("source manifest is not sealed")
			}
		})
	}
}
func TestNextjsSASTSnapshotRejectsSymlinksAndReportsBounds(t *testing.T) {
	source := sastSource(t)
	outside := filepath.Join(t.TempDir(), "outside.ts")
	os.WriteFile(outside, []byte("PRIVATE_OUTSIDE_SOURCE"), 0600)
	if err := os.Symlink(outside, filepath.Join(source, "app", "api", "link.ts")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "app", "api", "large.ts"), []byte(strings.Repeat("x", nextjsSASTMaxFile+1)), 0600); err != nil {
		t.Fatal(err)
	}
	// A real API route over the per-file limit must be reported, not prefix-scanned.
	if err := os.MkdirAll(filepath.Join(source, "app", "large"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "app", "large", "route.ts"), []byte(strings.Repeat("x", nextjsSASTMaxFile+1)), 0600); err != nil {
		t.Fatal(err)
	}
	snapshot := t.TempDir()
	manifest, err := snapshotNextjsSAST(t.Context(), source, snapshot)
	if err != nil || manifest.Symlinks != 1 || manifest.Oversized != 1 || len(manifest.Files) != 1 {
		t.Fatalf("snapshot=%+v err=%v", manifest, err)
	}
	if _, err := os.Stat(filepath.Join(snapshot, "app", "api", "link.ts")); !os.IsNotExist(err) {
		t.Fatal("external symlink entered snapshot")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := snapshotNextjsSAST(ctx, source, t.TempDir()); err == nil {
		t.Fatal("cancelled snapshot continued")
	}
}
func TestNextjsSASTProfileSelectionAndFingerprint(t *testing.T) {
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeWhiteBox, Types: []assessment.Type{assessment.TypeSourceCode}, Targets: []assessment.Target{{ID: "src", Kind: assessment.KindLocalSourcePath, Value: "/src/app"}}, Profile: ProfileNextjsDeep}
	plan := PlanAssessment(PlanInput{Config: cfg})
	found := false
	for _, job := range plan.Jobs {
		if job.Scanner == "nextjs-sast" {
			found = job.State == PlanConditional || job.State == PlanSelected
		}
	}
	if !found || !strings.Contains(plan.ToolVersions["nextjs-sast-rules"], nextjsSASTVersion) {
		t.Fatalf("source pack not planned or fingerprinted: %+v", plan)
	}
	cfg.Profile = ProfileGentle
	plan = PlanAssessment(PlanInput{Config: cfg})
	for _, job := range plan.Jobs {
		if job.Scanner == "nextjs-sast" {
			t.Fatal("optional pack auto-selected without deep profile")
		}
	}
}
func TestNextjsSASTRealEngine(t *testing.T) {
	binary := os.Getenv("XALGORIX_TEST_SEMGREP")
	if binary == "" {
		t.Skip("set XALGORIX_TEST_SEMGREP to run the real pinned Semgrep engine")
	}
	source, err := filepath.Abs("testdata/nextjs-sast")
	if err != nil {
		t.Fatal(err)
	}
	req := Request{Target: source, ScanDir: t.TempDir(), Scope: "source:fixture", TypedAssessment: true}
	run := (nextjsSASTRunner{}).Run(t.Context(), req, Config{SemgrepPath: binary}, nil)
	if run.Status != "completed" {
		t.Fatalf("real engine: %+v", run)
	}
	findings, err := ParseRun(run)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.RuleID]++
		if strings.Contains(f.SourceLocation, "/safe/") || strings.HasPrefix(f.SourceLocation, "safe/") {
			t.Fatalf("negative control flagged: %+v", f)
		}
	}
	for rule := range nextjsSASTCatalog {
		expected := 1
		if rule == "nextjs-route-query-fetch" || rule == "nextjs-route-query-redirect" {
			expected = 2
		}
		if counts[rule] != expected {
			t.Fatalf("rule %s has %d matches; findings=%+v", rule, counts[rule], findings)
		}
	}
	var manifest nextjsSASTManifest
	raw, _ := os.ReadFile(run.SourceManifestPath)
	if json.Unmarshal(raw, &manifest) != nil || manifest.EngineScanned != len(manifest.Files) {
		t.Fatalf("real source coverage mismatch: %s", raw)
	}
}
