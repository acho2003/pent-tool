package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func nestSource(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestNestjsSASTNotApplicableWithoutNestDependency(t *testing.T) {
	source := nestSource(t, map[string]string{"package.json": `{"dependencies":{"express":"4"}}`, "src/main.ts": "console.log(1)"})
	req := Request{Target: source, ScanDir: t.TempDir(), Scope: "source:fixture", TypedAssessment: true}
	run := (nestjsSASTRunner{}).Run(t.Context(), req, Config{SemgrepPath: fakeSastEngine(t, `{"results":[],"errors":[],"paths":{"scanned":[]}}`, "0")}, nil)
	if run.Status != "not_applicable" {
		t.Fatalf("non-Nest project: %+v", run)
	}
}

func TestNestjsSASTNormalizesFindingsWithoutSourceText(t *testing.T) {
	source := nestSource(t, map[string]string{"package.json": `{"dependencies":{"@nestjs/core":"10"}}`, "src/users.service.ts": "x", "src/users.service.spec.ts": "excluded", "test/app.e2e-spec.ts": "excluded"})
	raw := `{"results":[{"check_id":"nestjs-sql-raw-query-interpolation","path":"src/users.service.ts","start":{"line":7},"extra":{"lines":"SECRET_SOURCE_TEXT"}}],"errors":[],"paths":{"scanned":["src/users.service.ts"]}}`
	req := Request{Target: source, ScanDir: t.TempDir(), Scope: "source:fixture", TypedAssessment: true}
	run := (nestjsSASTRunner{}).Run(t.Context(), req, Config{SemgrepPath: fakeSastEngine(t, raw, "0")}, nil)
	if run.Status != "completed" || run.Scanner != "nestjs-sast" {
		t.Fatalf("run: %+v", run)
	}
	findings, err := ParseRun(run)
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	f := findings[0]
	if f.Severity != "high" || f.CWE != "CWE-89" || f.SourceLocation != "src/users.service.ts:7" || f.Remediation == "" {
		t.Fatalf("finding metadata: %+v", f)
	}
	data, _ := os.ReadFile(run.ArtifactPath)
	if strings.Contains(string(data), "SECRET_SOURCE_TEXT") {
		t.Fatal("matched source text was retained")
	}
	manifest, _ := os.ReadFile(run.SourceManifestPath)
	if strings.Contains(string(manifest), "spec.ts") || strings.Contains(string(manifest), "e2e") {
		t.Fatalf("test files entered the snapshot: %s", manifest)
	}
}

func TestNestjsSASTTargetSelection(t *testing.T) {
	for path, want := range map[string]bool{"src/main.ts": true, "src/app.js": true, "src/x.d.ts": false, "src/x.spec.ts": false, "src/x.e2e-spec.ts": false, "src/x.test.js": false, "README.md": false, "src/config.json": false} {
		if got := nestjsSASTTarget(path); got != want {
			t.Errorf("nestjsSASTTarget(%q)=%v want %v", path, got, want)
		}
	}
}

func TestNestjsRouteWithoutGuardDroppedWhenGlobalGuardRegistered(t *testing.T) {
	findings := []Finding{{RuleID: nestjsRouteWithoutGuard}, {RuleID: "nestjs-jwt-ignore-expiration"}}
	plain := nestSource(t, map[string]string{"src/app.module.ts": "@Module({})"})
	if got := nestjsDropGuardedRoutes(plain, []sastFile{{Path: "src/app.module.ts"}}, slices.Clone(findings)); len(got) != 2 {
		t.Fatalf("no global guard but findings dropped: %+v", got)
	}
	for _, body := range []string{"providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }]", "app.useGlobalGuards(new JwtAuthGuard())"} {
		guarded := nestSource(t, map[string]string{"src/app.module.ts": body})
		got := nestjsDropGuardedRoutes(guarded, []sastFile{{Path: "src/app.module.ts"}}, slices.Clone(findings))
		if len(got) != 1 || got[0].RuleID != "nestjs-jwt-ignore-expiration" {
			t.Fatalf("global guard %q: %+v", body, got)
		}
	}
}

func TestNestjsSASTSelectedAutomaticallyForSourceTargets(t *testing.T) {
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeWhiteBox, Types: []assessment.Type{assessment.TypeSourceCode}, Targets: []assessment.Target{{ID: "src", Kind: assessment.KindLocalSourcePath, Value: "/src/api"}}}
	plan := PlanAssessment(PlanInput{Config: cfg})
	found := slices.ContainsFunc(plan.Jobs, func(job PlanJob) bool {
		return job.Scanner == "nestjs-sast" && (job.State == PlanSelected || job.State == PlanConditional)
	})
	if !found {
		t.Fatalf("nestjs-sast not planned: %+v", plan.Decisions)
	}
	if !strings.Contains(plan.ToolVersions["nestjs-sast-rules"], nestjsSASTVersion) {
		t.Fatalf("rule pack missing from plan fingerprint inputs: %v", plan.ToolVersions)
	}
	if !HasAssessmentRunner("nestjs-sast") {
		t.Fatal("nestjs-sast has no runner")
	}
}

var nestAnnotation = regexp.MustCompile(`^\s*// (ruleid|ok): (\S+)`)

// TestNestjsSASTRealEngine runs the pinned Semgrep over testdata/nestjs-sast and
// requires an exact match with the `// ruleid:` annotations (each marks the next
// code line) and no match on any `// ok:` line or anywhere else.
func TestNestjsSASTRealEngine(t *testing.T) {
	binary := os.Getenv("XALGORIX_TEST_SEMGREP")
	if binary == "" {
		t.Skip("set XALGORIX_TEST_SEMGREP to run the real pinned Semgrep engine")
	}
	source, err := filepath.Abs("testdata/nestjs-sast")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	covered := map[string]bool{}
	err = filepath.WalkDir(source, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".ts") {
			return err
		}
		rel, _ := filepath.Rel(source, path)
		if !nestjsSASTTarget(filepath.ToSlash(rel)) || strings.HasPrefix(filepath.ToSlash(rel), "test/") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lines := strings.Split(string(body), "\n")
		for i, line := range lines {
			m := nestAnnotation.FindStringSubmatch(line)
			if m == nil || m[1] != "ruleid" {
				continue
			}
			j := i + 1
			for j < len(lines) && nestAnnotation.MatchString(lines[j]) {
				j++
			}
			want[fmt.Sprintf("%s %s:%d", m[2], filepath.ToSlash(rel), j+1)] = true
			covered[m[2]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for rule := range nestjsSASTCatalog {
		if !covered[rule] {
			t.Errorf("catalog rule %s has no positive fixture", rule)
		}
	}
	req := Request{Target: source, ScanDir: t.TempDir(), Scope: "source:fixture", TypedAssessment: true}
	run := (nestjsSASTRunner{}).Run(t.Context(), req, Config{SemgrepPath: binary}, nil)
	if run.Status != "completed" {
		t.Fatalf("real engine: %+v", run)
	}
	findings, err := ParseRun(run)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range findings {
		key := f.RuleID + " " + f.SourceLocation
		if !want[key] {
			t.Errorf("unexpected finding %s", key)
		}
		got[key] = true
	}
	for key := range want {
		if !got[key] {
			t.Errorf("missed expected finding %s", key)
		}
	}
}
