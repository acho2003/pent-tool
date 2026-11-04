package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func nextjsLockJSON(t *testing.T, version int, packages map[string]any) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{"lockfileVersion": version, "packages": packages})
	if err != nil {
		t.Fatal(err)
	}
	return body
}
func nextjsDependencyRequest(t *testing.T, files map[string][]byte) Request {
	t.Helper()
	source := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(source, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return Request{Target: source, ScanDir: t.TempDir(), Scope: "source:app", TypedAssessment: true}
}

func TestNextjsDependenciesMatchResolvedVersionsWithoutRetainingRegistrySecrets(t *testing.T) {
	for _, version := range []int{2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			body := nextjsLockJSON(t, version, map[string]any{
				"":                                       map[string]any{"name": "next", "version": "14.1.0", "dependencies": map[string]string{"next": "^14.0.0"}},
				"node_modules/next":                      map[string]any{"version": "14.1.0", "resolved": "https://user:REGISTRY_SECRET@private.example.test/next.tgz?token=PRIVATE_TOKEN", "dev": true},
				"node_modules/alias":                     map[string]any{"name": "next", "version": "15.0.0", "optional": true},
				"node_modules/wrapper/node_modules/next": map[string]any{"version": "14.1.0"},
				"node_modules/imposter/node_modules/next": map[string]any{"name": "different-package", "version": "14.1.0"},
			})
			req := nextjsDependencyRequest(t, map[string][]byte{"package-lock.json": body})
			run := (nextjsDepsRunner{}).Run(t.Context(), req, Config{}, nil)
			if run.Status != "completed" || run.Outcome != "SUCCESS_WITH_FINDINGS" {
				t.Fatalf("offline dependency checks failed: %+v", run)
			}
			findings, errs := ParseRuns([]Run{run})
			if len(errs) > 0 || len(findings) == 0 {
				t.Fatalf("findings=%d errs=%v", len(findings), errs)
			}
			locations := map[string]bool{}
			for _, finding := range findings {
				if finding.Confidence != "lockfile_version_match" || finding.Package != "next" || finding.Method != "" || !strings.HasPrefix(finding.SourceLocation, "package-lock.json#/packages/node_modules~1") {
					t.Fatalf("dependency evidence overstated: %+v", finding)
				}
				locations[finding.SourceLocation] = true
			}
			if len(locations) != 3 {
				t.Fatalf("resolutions collapsed or declaration/imposter matched: %v", locations)
			}
			manifestBytes, _ := os.ReadFile(run.SourceManifestPath)
			artifact, _ := os.ReadFile(run.ArtifactPath)
			for _, secret := range []string{"REGISTRY_SECRET", "PRIVATE_TOKEN", "private.example.test", `"resolved":`} {
				if strings.Contains(string(manifestBytes)+string(artifact), secret) {
					t.Fatalf("registry source data retained: %s", secret)
				}
			}
			var manifest nextjsDepsManifest
			if json.Unmarshal(manifestBytes, &manifest) != nil || len(manifest.Resolutions) != 3 {
				t.Fatal("source manifest missing resolutions")
			}
			digest := sha256.Sum256(body)
			if manifest.File.SHA256 != hex.EncodeToString(digest[:]) || manifest.AdvisorySHA256 != fmt.Sprintf("%x", sha256.Sum256(nextjsAdvisoriesJSON)) || manifest.AdvisoryRetrieved == "" {
				t.Fatal("lock/advisory provenance missing")
			}
			if err := VerifyChecksum(run); err != nil {
				t.Fatal(err)
			}
			file, err := os.OpenFile(run.SourceManifestPath, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			file.WriteString("\n")
			file.Close()
			run.Status = "failed"
			findings, errs = ParseRuns([]Run{run})
			if len(findings) != 0 || len(errs) == 0 {
				t.Fatal("tampered partial dependency evidence accepted")
			}
		})
	}
}

func TestNextjsDependenciesShrinkwrapPrecedenceAndNoRangeGuessing(t *testing.T) {
	vulnerable := nextjsLockJSON(t, 3, map[string]any{"node_modules/next": map[string]any{"version": "14.1.0"}})
	fixed := nextjsLockJSON(t, 3, map[string]any{"node_modules/next": map[string]any{"version": "16.4.3"}})
	req := nextjsDependencyRequest(t, map[string][]byte{"package-lock.json": vulnerable, "npm-shrinkwrap.json": fixed})
	run := (nextjsDepsRunner{}).Run(t.Context(), req, Config{}, nil)
	findings, err := ParseRun(run)
	if err != nil || len(findings) != 0 || run.Outcome != "SUCCESS_NO_FINDINGS" {
		t.Fatalf("shrinkwrap precedence failed: run=%+v findings=%d err=%v", run, len(findings), err)
	}
	raw, _ := os.ReadFile(run.SourceManifestPath)
	var manifest nextjsDepsManifest
	json.Unmarshal(raw, &manifest)
	if manifest.File.Path != "npm-shrinkwrap.json" || manifest.Resolutions[0].Version != "16.4.3" {
		t.Fatal("wrong authoritative lockfile")
	}
	for _, version := range []string{"^14.1.0", "14.1", "v14.1.0", "14.1.0-01", "file:next", "workspace:*", "14.1.0-" + strings.Repeat("a", nextjsDepsMaxVersionLength)} {
		body := nextjsLockJSON(t, 3, map[string]any{"node_modules/next": map[string]any{"version": version}})
		req := nextjsDependencyRequest(t, map[string][]byte{"package-lock.json": body})
		run := (nextjsDepsRunner{}).Run(t.Context(), req, Config{}, nil)
		findings, _ := ParseRun(run)
		if run.Outcome != "PARTIAL" || len(findings) != 0 {
			t.Fatalf("non-exact version was guessed: %q %+v", version, run)
		}
	}
}

func TestNextjsDependenciesIncompleteInputsAndSymlinksNeverLookClean(t *testing.T) {
	for _, mode := range []string{"missing", "legacy", "malformed", "linked", "invalid-path", "oversized", "symlink", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			files := map[string][]byte{}
			switch mode {
			case "legacy":
				files["package-lock.json"] = []byte(`{"lockfileVersion":1,"dependencies":{"next":{"version":"14.1.0"}}}`)
			case "malformed":
				files["package-lock.json"] = []byte(`{"lockfileVersion":3,"packages":`)
			case "linked":
				files["package-lock.json"] = nextjsLockJSON(t, 3, map[string]any{"node_modules/next": map[string]any{"link": true, "resolved": "../outside"}})
			case "invalid-path":
				files["package-lock.json"] = nextjsLockJSON(t, 3, map[string]any{"../node_modules/next": map[string]any{"version": "14.1.0"}})
			case "oversized":
				files["package-lock.json"] = []byte(strings.Repeat(" ", nextjsDepsMaxBytes+1))
			}
			req := nextjsDependencyRequest(t, files)
			if mode == "symlink" {
				outside := filepath.Join(t.TempDir(), "private.json")
				os.WriteFile(outside, []byte("OUTSIDE_SOURCE_MUST_NOT_BE_READ"), 0600)
				os.WriteFile(filepath.Join(req.Target, "package-lock.json"), nextjsLockJSON(t, 3, map[string]any{}), 0600)
				if err := os.Symlink(outside, filepath.Join(req.Target, "npm-shrinkwrap.json")); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			run := (nextjsDepsRunner{}).Run(ctx, req, Config{}, nil)
			if run.Outcome == "SUCCESS_NO_FINDINGS" || run.Completeness == "complete" {
				t.Fatalf("coverage gap looks clean: %+v", run)
			}
			if mode == "symlink" && run.Status != "failed" {
				t.Fatal("symlink-selected shrinkwrap was followed or ignored")
			}
		})
	}
}

func TestNextjsDependenciesSharedBoundsRetainKnownPartialMatches(t *testing.T) {
	packages := map[string]any{}
	for index := 0; index < nextjsDepsMaxResolutions+1; index++ {
		packages[fmt.Sprintf("node_modules/w%03d/node_modules/next", index)] = map[string]any{"version": "14.1.0"}
	}
	req := nextjsDependencyRequest(t, map[string][]byte{"package-lock.json": nextjsLockJSON(t, 3, packages)})
	run := (nextjsDepsRunner{}).Run(t.Context(), req, Config{}, nil)
	findings, errs := ParseRuns([]Run{run})
	if run.Status != "completed" || run.Outcome != "PARTIAL" || len(findings) == 0 || len(findings) > nextjsDepsMaxFindings || len(errs) > 0 {
		t.Fatalf("bounded matches lost or overstated: run=%+v count=%d errs=%v", run, len(findings), errs)
	}
	for _, finding := range findings {
		if finding.EvidenceCompleteness != "partial" {
			t.Fatal("bounded findings labeled complete")
		}
	}
	packages = map[string]any{}
	for index := 0; index < nextjsDepsMaxPackages+1; index++ {
		packages[fmt.Sprintf("node_modules/a%05d", index)] = map[string]any{"version": "1.0.0"}
	}
	packages["node_modules/next"] = map[string]any{"version": "14.1.0"}
	manifest, err := parseNextjsLock(t.Context(), nextjsLockJSON(t, 3, packages))
	if err != nil || len(manifest.Gaps) == 0 || len(manifest.Resolutions) != 0 {
		t.Fatal("package record cap was not explicit")
	}
}

func TestNextjsDependenciesPlanAndNativeExecutionWithoutExternalTools(t *testing.T) {
	body := nextjsLockJSON(t, 3, map[string]any{"node_modules/next": map[string]any{"version": "14.1.0"}})
	req := nextjsDependencyRequest(t, map[string][]byte{"package-lock.json": body})
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeWhiteBox, Types: []assessment.Type{assessment.TypeSourceCode}, Targets: []assessment.Target{{ID: "src", Kind: assessment.KindLocalSourcePath, Value: req.Target}}, Profile: ProfileNextjsDeep}
	plan := PlanAssessment(PlanInput{Config: cfg})
	selected := false
	for _, job := range plan.Jobs {
		if job.Scanner == "nextjs-deps" {
			selected = job.State == PlanSelected || job.State == PlanConditional
		}
	}
	if !selected || plan.ToolVersions["nextjs-deps-catalog"] != nextjsDepsVersion || !strings.Contains(plan.ToolVersions["nextjs-advisories"], ":") {
		t.Fatal("native source dependency job not selected/fingerprinted")
	}
	cfg.ScannerSelection = assessment.ScannerSelection{Mode: "custom", Variants: []string{"nextjs-deps"}}
	plan = PlanAssessment(PlanInput{Config: cfg})
	runs := NewPipeline(Config{}).RunAssessmentJobs(t.Context(), plan, t.TempDir(), nil, nil)
	found := false
	for _, run := range runs {
		if run.Scanner == "nextjs-deps" {
			found = true
			if run.Status != "completed" || run.Outcome != "SUCCESS_WITH_FINDINGS" {
				t.Fatalf("native dependency job failed: %+v", run)
			}
		}
	}
	if !found {
		t.Fatal("native dependency runner was not routed")
	}
	cfg.ScannerSelection = assessment.ScannerSelection{Mode: "custom", Variants: []string{"semgrep"}}
	plan = PlanAssessment(PlanInput{Config: cfg})
	for _, job := range plan.Jobs {
		if job.Scanner == "nextjs-deps" {
			t.Fatal("custom selection did not override dependency profile default")
		}
	}
}

func TestNextjsDependenciesReadPinnedFrameworkLockWithoutExecutingIt(t *testing.T) {
	source, err := filepath.Abs("../../test/nextjs-lab")
	if err != nil {
		t.Fatal(err)
	}
	run := (nextjsDepsRunner{}).Run(t.Context(), Request{Target: source, ScanDir: t.TempDir(), Scope: "source:pinned-lab", TypedAssessment: true}, Config{}, nil)
	if run.Status != "completed" || run.Outcome != "SUCCESS_NO_FINDINGS" {
		t.Fatalf("pinned framework dependency check failed: %+v", run)
	}
	body, err := os.ReadFile(run.SourceManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest nextjsDepsManifest
	if json.Unmarshal(body, &manifest) != nil || len(manifest.Resolutions) != 1 || manifest.Resolutions[0].Version != "16.4.3" || manifest.File.Path != "package-lock.json" {
		t.Fatal("pinned framework lock resolution was not preserved")
	}
}

func TestNextjsDependenciesKeepKnownMatchesWithUnresolvedSibling(t *testing.T) {
	body := nextjsLockJSON(t, 3, map[string]any{
		"node_modules/next":                      map[string]any{"version": "14.1.0"},
		"node_modules/wrapper/node_modules/next": map[string]any{"link": true, "resolved": "../unread-linked-workspace"},
	})
	req := nextjsDependencyRequest(t, map[string][]byte{"package-lock.json": body})
	run := (nextjsDepsRunner{}).Run(t.Context(), req, Config{}, nil)
	findings, errs := ParseRuns([]Run{run})
	if run.Outcome != "PARTIAL" || len(findings) == 0 || len(errs) > 0 {
		t.Fatalf("known matches not retained with unresolved sibling: run=%+v findings=%d errs=%v", run, len(findings), errs)
	}
	for _, finding := range findings {
		if finding.EvidenceCompleteness != "partial" {
			t.Fatal("unresolved dependency coverage labeled complete")
		}
	}
}
