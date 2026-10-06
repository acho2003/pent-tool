package scanner

import (
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"testing"
)

func TestAssessmentWorkflowRecordsActualStageOutcomes(t *testing.T) {
	dir := t.TempDir()
	plan := AssessmentPlan{Config: assessment.AssessmentConfig{Profile: ProfileGentle}, Fingerprint: "sha256:accepted", RegistryVersion: PlanRegistryVersion,
		ToolVersions: map[string]string{"katana": "v1.7.0"}, Jobs: []PlanJob{
			{ID: "crawl-job", Scanner: "katana", Stage: StageCrawl},
			{ID: "template-job", Scanner: "nuclei", Stage: StageTemplates},
		}}
	runs := []Run{
		{Scanner: "katana", Stage: StageCrawl, Status: "completed", Checksum: "sha256:crawl", StartedAt: "2026-10-02T00:00:00Z", FinishedAt: "2026-10-02T00:01:00Z"},
		{Scanner: "nuclei", Stage: StageTemplates, Status: "skipped", GapKind: GapPrerequisiteFailed, StartedAt: "2026-10-02T00:01:01Z", FinishedAt: "2026-10-02T00:01:01Z"},
	}
	if err := saveAssessmentWorkflow(dir, plan, runs); err != nil {
		t.Fatal(err)
	}
	manifest, ok := LoadWorkflowManifest(dir)
	if !ok || manifest.PlanFingerprint != plan.Fingerprint || len(manifest.Stages) != 2 {
		t.Fatalf("manifest: %+v loaded=%v", manifest, ok)
	}
	crawl, _ := manifest.Stage(StageCrawl)
	template, _ := manifest.Stage(StageTemplates)
	if crawl.Status != StageStatusCompleted || crawl.ToolVersions["katana"] != "v1.7.0" || len(crawl.OutputChecksums) != 1 || template.Status != StageStatusSkipped || template.GapKind != GapPrerequisiteFailed {
		t.Fatalf("stage evidence: crawl=%+v templates=%+v", crawl, template)
	}
}

func TestWorkflowCheckpointDoesNotClaimPartialEvidenceCompleted(t *testing.T) {
	dir := t.TempDir()
	plan := AssessmentPlan{Fingerprint: "sha256:partial", Jobs: []PlanJob{{ID: "one", Scanner: "nuclei", Stage: StageTemplates}}}
	if err := saveAssessmentWorkflow(dir, plan, []Run{{Scanner: "nuclei", Stage: StageTemplates, Status: "completed", Completeness: "partial", Outcome: "PARTIAL"}}); err != nil {
		t.Fatal(err)
	}
	manifest, ok := LoadWorkflowManifest(dir)
	stage, _ := manifest.Stage(StageTemplates)
	if !ok || stage.Status != StageStatusPartial {
		t.Fatalf("partial evidence claimed clean completion: %+v", stage)
	}
}
