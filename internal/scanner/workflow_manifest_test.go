package scanner

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestWorkflowManifestRoundTripAtomic(t *testing.T) {
	scanDir := t.TempDir()
	cfg := assessment.AssessmentConfig{
		Mode: assessment.ModeBlackBox, Profile: "standard",
		Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.test/"}},
		Access: []assessment.AccessBinding{{Kind: assessment.AccessFormLogin, TargetIDs: []string{"app"},
			CredentialID: "cred-secret-id"}},
		Exclusions: []assessment.Exclusion{{PathPattern: "/logout", Reason: "logout"}},
	}
	policy := AcceptedPolicyFromConfig(cfg, PlanRegistryVersion)
	if policy.Hash == "" || policy.Hash != policy.ComputeHash() {
		t.Fatalf("policy hash = %q, want computed %q", policy.Hash, policy.ComputeHash())
	}
	manifest := &WorkflowManifest{PlanFingerprint: "sha256:plan", AcceptedPolicy: policy}
	manifest.SetStage(StageRecord{Stage: StageDAST, JobIDs: []string{"zap"}, Status: StageStatusCompleted,
		InputChecksum: "sha256:in", OutputChecksums: []string{"sha256:out"}, ToolVersions: map[string]string{"zap": "2.16.1"},
		StartedAt: "2026-10-02T00:00:00Z", FinishedAt: "2026-10-02T00:01:00Z"})
	manifest.SetStage(StageRecord{Stage: StageCrawl, JobIDs: []string{"katana"}, Status: StageStatusCompleted})
	// SetStage replaces an existing record for the same stage.
	manifest.SetStage(StageRecord{Stage: StageCrawl, JobIDs: []string{"katana"}, Status: StageStatusFailed, GapKind: GapToolUnavailable})

	if err := SaveWorkflowManifest(scanDir, manifest); err != nil {
		t.Fatal(err)
	}
	path := WorkflowManifestPath(scanDir)
	if want := filepath.Join(scanDir, "workflow", "workflow-v1.json"); path != want {
		t.Fatalf("path = %q, want %q", path, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("workflow dir has stray files: %v", entries)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "cred-secret-id") || strings.Contains(string(data), "credential") {
		t.Fatalf("manifest leaks credential references: %s", data)
	}

	loaded, ok := LoadWorkflowManifest(scanDir)
	if !ok {
		t.Fatal("manifest did not load")
	}
	if loaded.SchemaVersion != WorkflowManifestSchemaVersion || loaded.UpdatedAt == "" {
		t.Fatalf("schema/updated = %d/%q", loaded.SchemaVersion, loaded.UpdatedAt)
	}
	if len(loaded.Stages) != 2 || loaded.Stages[0].Stage != StageCrawl || loaded.Stages[1].Stage != StageDAST {
		t.Fatalf("stages not in stage order: %+v", loaded.Stages)
	}
	if got, ok := loaded.Stage(StageCrawl); !ok || got.Status != StageStatusFailed || got.GapKind != GapToolUnavailable {
		t.Fatalf("crawl stage = %+v (%v)", got, ok)
	}
	dast, _ := loaded.Stage(StageDAST)
	want, _ := manifest.Stage(StageDAST)
	if !reflect.DeepEqual(dast, want) {
		t.Fatalf("dast round trip = %+v, want %+v", dast, want)
	}
	if !reflect.DeepEqual(loaded.AcceptedPolicy, policy) {
		t.Fatalf("policy round trip = %+v, want %+v", loaded.AcceptedPolicy, policy)
	}

	// A second save replaces the file atomically and leaves no temp siblings.
	manifest.SetStage(StageRecord{Stage: StageValidation, Status: StageStatusSkipped, GapKind: GapEmptyInput})
	if err := SaveWorkflowManifest(scanDir, manifest); err != nil {
		t.Fatal(err)
	}
	entries, _ = os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("workflow dir has stray files after rewrite: %v", entries)
	}
	if again, ok := LoadWorkflowManifest(scanDir); !ok || len(again.Stages) != 3 {
		t.Fatalf("rewrite = %+v (%v)", again, ok)
	}
	if err := SaveWorkflowManifest(scanDir, nil); err == nil {
		t.Fatal("nil manifest saved")
	}
}

func TestStageInputChecksumChangesWhenUpstreamOutputChanges(t *testing.T) {
	base := StageInputChecksum("sha256:policy", []string{"sha256:katana-a", "sha256:openapi"}, []string{"sha256:fixture"})
	if !strings.HasPrefix(base, "sha256:") {
		t.Fatalf("checksum = %q", base)
	}
	// Order of the upstream set does not matter; nil and empty are the same.
	if got := StageInputChecksum("sha256:policy", []string{"sha256:openapi", "sha256:katana-a"}, []string{"sha256:fixture"}); got != base {
		t.Fatalf("order changed checksum: %q != %q", got, base)
	}
	if StageInputChecksum("p", nil, nil) != StageInputChecksum("p", []string{}, []string{}) {
		t.Fatal("nil and empty inputs differ")
	}
	// Re-running discovery changes its output, which must invalidate DAST.
	if got := StageInputChecksum("sha256:policy", []string{"sha256:katana-b", "sha256:openapi"}, []string{"sha256:fixture"}); got == base {
		t.Fatal("upstream output change did not change the stage input checksum")
	}
	if got := StageInputChecksum("sha256:other-policy", []string{"sha256:katana-a", "sha256:openapi"}, []string{"sha256:fixture"}); got == base {
		t.Fatal("policy change did not change the stage input checksum")
	}
	if got := StageInputChecksum("sha256:policy", []string{"sha256:katana-a", "sha256:openapi"}, []string{"sha256:fixture-2"}); got == base {
		t.Fatal("artifact change did not change the stage input checksum")
	}
	// Moving a checksum between the upstream and artifact lists is a different input.
	if StageInputChecksum("p", []string{"x"}, nil) == StageInputChecksum("p", nil, []string{"x"}) {
		t.Fatal("upstream and artifact checksums are not domain separated")
	}

	runs := []Run{
		{Scanner: "katana", Status: "completed", Checksum: "sha256:b"},
		{Scanner: "openapi", Status: "completed", Checksum: "sha256:a"},
		{Scanner: "nuclei", Status: "failed"},
		{Scanner: "katana", Status: "completed", Checksum: "sha256:b"},
	}
	if got := RunOutputChecksums(runs); !reflect.DeepEqual(got, []string{"sha256:a", "sha256:b"}) {
		t.Fatalf("output checksums = %v", got)
	}
}

func TestWorkflowManifestAuthStageNeverReusable(t *testing.T) {
	versions := map[string]string{"zap": "2.16.1"}
	dast := StageRecord{Stage: StageDAST, Status: StageStatusCompleted, InputChecksum: "sha256:in",
		ToolVersions: versions, FinishedAt: "2026-10-02T00:01:00Z"}
	if !dast.Reusable("sha256:in", map[string]string{"zap": "2.16.1"}) {
		t.Fatal("matching completed DAST stage is not reusable")
	}
	if dast.Reusable("sha256:changed", versions) {
		t.Fatal("stage with different inputs is reusable")
	}
	if dast.Reusable("sha256:in", map[string]string{"zap": "2.17.0"}) {
		t.Fatal("stage whose tool changed is reusable")
	}
	failed := dast
	failed.Status, failed.GapKind = StageStatusFailed, GapCancelled
	if failed.Reusable("sha256:in", versions) {
		t.Fatal("failed stage is reusable")
	}
	gap := dast
	gap.GapKind = GapBudgetExhausted
	if gap.Reusable("sha256:in", versions) {
		t.Fatal("stage with a coverage gap is reusable")
	}
	empty := StageRecord{Stage: StageCrawl, Status: StageStatusCompleted}
	if empty.Reusable("", nil) {
		t.Fatal("stage without a recorded input checksum is reusable")
	}
	noTools := StageRecord{Stage: StageCrawl, Status: StageStatusCompleted, InputChecksum: "c"}
	if !noTools.Reusable("c", map[string]string{}) {
		t.Fatal("nil and empty tool versions differ")
	}

	auth := StageRecord{Stage: StageAuth, Status: StageStatusCompleted, InputChecksum: "sha256:in",
		ToolVersions: versions, FinishedAt: "2026-10-02T00:01:00Z"}
	if auth.Reusable("sha256:in", versions) || StageReusable(StageAuth) {
		t.Fatal("auth stage must always be reverified")
	}
	if !StageReusable(StageDAST) {
		t.Fatal("DAST stage is never reusable")
	}
}

func TestLoadWorkflowManifestMissingReturnsNoManifest(t *testing.T) {
	scanDir := t.TempDir()
	if m, ok := LoadWorkflowManifest(scanDir); ok || m != nil {
		t.Fatalf("missing manifest = %+v (%v)", m, ok)
	}
	if err := os.MkdirAll(filepath.Join(scanDir, "workflow"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"legacy without schema": `{"plan_fingerprint":"sha256:x","stages":[]}`,
		"future schema":         `{"schema_version":2,"plan_fingerprint":"sha256:x"}`,
		"corrupt":               `{"schema_version":1,`,
	} {
		if err := os.WriteFile(WorkflowManifestPath(scanDir), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if m, ok := LoadWorkflowManifest(scanDir); ok || m != nil {
			t.Fatalf("%s: manifest = %+v (%v)", name, m, ok)
		}
	}
}
