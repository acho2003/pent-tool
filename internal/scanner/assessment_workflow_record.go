package scanner

import (
	"sort"
)

// saveAssessmentWorkflow derives a stage record from the executor's actual
// outcomes. The manifest is evidence, not a second source of execution truth.
func saveAssessmentWorkflow(scanDir string, plan AssessmentPlan, runs []Run) error {
	policy := AcceptedPolicyFromConfig(plan.Config, plan.RegistryVersion)
	manifest := &WorkflowManifest{PlanFingerprint: plan.Fingerprint, AcceptedPolicy: policy}
	grouped := map[string][]Run{}
	for _, run := range runs {
		stage := run.Stage
		if stage == "" {
			stage = stageForScanner(run.Scanner)
		}
		grouped[stage] = append(grouped[stage], run)
	}
	upstream := []string{}
	stages := make([]string, 0, len(grouped))
	for stage := range grouped {
		stages = append(stages, stage)
	}
	sort.Slice(stages, func(i, j int) bool { return stageRank(stages[i]) < stageRank(stages[j]) })
	for _, stage := range stages {
		stageRuns := grouped[stage]
		record := StageRecord{Stage: stage, Status: StageStatusCompleted, InputChecksum: StageInputChecksum(policy.Hash, upstream, nil), OutputChecksums: RunOutputChecksums(stageRuns), ToolVersions: map[string]string{}}
		completed, skipped := 0, 0
		for _, run := range stageRuns {
			if run.Status == "completed" {
				completed++
			}
			if run.Status == "skipped" {
				skipped++
			}
			if record.GapKind == "" && run.GapKind != "" {
				record.GapKind = run.GapKind
			}
			if record.StartedAt == "" || (run.StartedAt != "" && run.StartedAt < record.StartedAt) {
				record.StartedAt = run.StartedAt
			}
			if run.FinishedAt > record.FinishedAt {
				record.FinishedAt = run.FinishedAt
			}
			if version := plan.ToolVersions[run.Scanner]; version != "" {
				record.ToolVersions[run.Scanner] = version
			}
		}
		switch {
		case completed == len(stageRuns):
			record.Status = StageStatusCompleted
		case skipped == len(stageRuns):
			record.Status = StageStatusSkipped
		case completed > 0:
			record.Status = StageStatusPartial
		default:
			record.Status = StageStatusFailed
		}
		for _, job := range plan.Jobs {
			if job.Stage == stage {
				record.JobIDs = append(record.JobIDs, job.ID)
			}
		}
		sort.Strings(record.JobIDs)
		manifest.Stages = append(manifest.Stages, record)
		upstream = append(upstream, record.OutputChecksums...)
	}
	return SaveWorkflowManifest(scanDir, manifest)
}
