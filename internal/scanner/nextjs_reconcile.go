package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

const nextjsReconcileVersion = "nextjs-reconcile-v1"

type nextjsVersionComparison struct {
	Schema          int      `json:"schema_version"`
	SourceTarget    string   `json:"source_target_id"`
	WebTarget       string   `json:"web_target_id"`
	State           string   `json:"state"`
	Locked          []string `json:"locked_versions,omitempty"`
	Observed        []string `json:"observed_versions,omitempty"`
	SourceChecksum  string   `json:"source_run_checksum,omitempty"`
	RuntimeChecksum string   `json:"runtime_run_checksum,omitempty"`
	Reason          string   `json:"reason,omitempty"`
}

func reconcileNextjsEvidence(cfg assessment.AssessmentConfig, runs []Run, scanDir, fingerprint, attempt string) []Run {
	targets := map[string]assessment.Target{}
	for _, target := range cfg.Targets {
		targets[target.ID] = target
	}
	var output []Run
	for _, web := range cfg.Targets {
		source, linked := targets[web.RelatedTo]
		if web.Kind != assessment.KindURL || !linked || (source.Kind != assessment.KindRepository && source.Kind != assessment.KindLocalSourcePath) {
			continue
		}
		comparison := nextjsVersionComparison{Schema: 1, SourceTarget: source.ID, WebTarget: web.ID, State: "unknown"}
		run := Run{Scanner: "nextjs-reconcile", Target: SafeTelemetryURL(web.Value), Scope: "app:" + web.ID, Variant: nextjsReconcileVersion, Stage: StageResults, PlanFingerprint: fingerprint, AttemptID: attempt, Status: "completed", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Outcome: "PARTIAL", Completeness: "partial"}
		run.WorkflowVersion = cfg.WorkflowVersion
		if run.AttemptID == "" {
			id, err := newAssessmentAttemptID()
			if err != nil {
				run.Status, run.Reason = "failed", "comparison attempt identity unavailable"
				output = append(output, finalizeRun(run))
				continue
			}
			run.AttemptID = id
		}
		selectEvidence := func(target assessment.Target, scanner string) (Run, bool) {
			var selected Run
			count := 0
			scope := assessmentJobScope(PlanJob{TargetID: target.ID, Target: target.Value})
			for _, candidate := range runs {
				if candidate.Scanner == scanner && candidate.Scope == scope && candidate.Target == target.Value && candidate.PlanFingerprint == fingerprint {
					selected = candidate
					count++
				}
			}
			return selected, count == 1 && selected.Status == "completed" && VerifyChecksum(selected) == nil
		}
		sourceRun, sourceOK := selectEvidence(source, "nextjs-deps")
		runtimeRun, runtimeOK := selectEvidence(web, "nextjs-assets")
		var findings []Finding
		switch {
		case !sourceOK:
			comparison.Reason = "one complete checksum-verified source dependency run is required"
		case !runtimeOK:
			comparison.Reason = "one complete checksum-verified runtime discovery run is required"
		default:
			comparison.SourceChecksum, comparison.RuntimeChecksum = sourceRun.Checksum, runtimeRun.Checksum
			sourceInfo, err := os.Stat(sourceRun.SourceManifestPath)
			var manifest nextjsDepsManifest
			sourceRaw, readErr := []byte(nil), error(nil)
			if err == nil && sourceInfo.Mode().IsRegular() && sourceInfo.Size() <= 1<<20 {
				sourceRaw, readErr = os.ReadFile(sourceRun.SourceManifestPath)
			} else {
				readErr = fmt.Errorf("source manifest unavailable")
			}
			runtimeInfo, runtimeErr := os.Stat(runtimeRun.ArtifactPath)
			var runtimeFindings []Finding
			if runtimeErr == nil && runtimeInfo.Mode().IsRegular() && runtimeInfo.Size() <= 16<<20 {
				runtimeFindings, runtimeErr = ParseRun(runtimeRun)
			}
			locked, observed := map[string]bool{}, map[string]bool{}
			if readErr == nil && json.Unmarshal(sourceRaw, &manifest) == nil && manifest.Schema == 1 && strings.HasPrefix(manifest.Catalog, "nextjs-deps-") {
				for _, resolution := range manifest.Resolutions {
					if exactNextjsLockVersion(resolution.Version) {
						locked[resolution.Version] = true
					}
				}
			} else {
				readErr = fmt.Errorf("source manifest schema unavailable")
			}
			if runtimeErr == nil {
				for _, finding := range runtimeFindings {
					if finding.RuleID == "nextjs-fingerprint" && finding.Confidence == "confirmed" && exactNextjsLockVersion(finding.PackageVersion) {
						observed[finding.PackageVersion] = true
					}
				}
			}
			for version := range locked {
				comparison.Locked = append(comparison.Locked, version)
			}
			sort.Strings(comparison.Locked)
			for version := range observed {
				comparison.Observed = append(comparison.Observed, version)
			}
			sort.Strings(comparison.Observed)
			switch {
			case readErr != nil || runtimeErr != nil:
				comparison.Reason = "sealed version evidence could not be decoded within its bounds"
			case len(manifest.Gaps) > 0 || sourceRun.Completeness != "complete":
				comparison.Reason = "source dependency coverage is incomplete"
			case len(comparison.Locked) == 0:
				comparison.Reason = "source evidence has no exact Next.js resolution"
			case len(comparison.Observed) != 1:
				comparison.Reason = "runtime version evidence is missing or ambiguous"
			default:
				agrees := false
				for _, version := range comparison.Locked {
					if order, ok := compareSemver(version, comparison.Observed[0]); ok && order == 0 {
						agrees = true
					}
				}
				run.Outcome, run.Completeness = "SUCCESS_NO_FINDINGS", "complete"
				if agrees {
					comparison.State = "consistent"
					comparison.Reason = "observed runtime string matches a related locked version; deployment provenance is not established"
				} else {
					comparison.State = "conflict"
					comparison.Reason = "observed runtime string differs from every exact version in the explicitly related source lockfiles"
					run.Outcome = "SUCCESS_WITH_FINDINGS"
					findings = append(findings, Finding{SourceID: nextjsSourceID("nextjs-version-evidence-conflict", web.ID+"\x00"+source.ID), Scanner: "nextjs-reconcile", RuleID: "nextjs-version-evidence-conflict", Title: "Observed Next.js version differs from related source lockfiles", Severity: "info", Target: SafeTelemetryURL(web.Value), Endpoint: SafeTelemetryURL(web.Value), Package: "next", PackageVersion: comparison.Observed[0], Confidence: "evidence_conflict", Description: "The explicitly related source and runtime observations disagree. Review deployment revision, multiple applications, vendoring, and the declared relationship before transferring any source advisory conclusion to this deployment.", Evidence: fmt.Sprintf("observed runtime %s; %d distinct related locked versions; both input runs checksum-verified; exact version sets retained in the comparison manifest", comparison.Observed[0], len(comparison.Locked)), Remediation: "Verify the source-to-deployment relationship and rebuild/deploy from the intended locked dependency graph."})
				}
			}
		}
		directory := filepath.Join(scanDir, "scanner-output", "nextjs-reconcile", stableJobPath(web.ID), stableJobPath(run.AttemptID))
		if err := os.MkdirAll(directory, 0700); err != nil {
			run.Status, run.Reason = "failed", "comparison directory could not be created"
			output = append(output, finalizeRun(run))
			continue
		}
		run.SourceManifestPath = filepath.Join(directory, "version-comparison.json")
		run.ArtifactPath = filepath.Join(directory, "findings.jsonl")
		raw, err := json.MarshalIndent(comparison, "", "  ")
		if err == nil {
			err = os.WriteFile(run.SourceManifestPath, raw, 0600)
		}
		artifact, openErr := os.OpenFile(run.ArtifactPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if openErr == nil {
			encoder := json.NewEncoder(artifact)
			for _, finding := range findings {
				finding.EvidenceRef = run.SourceManifestPath
				if encodeErr := encoder.Encode(finding); encodeErr != nil {
					err = encodeErr
					break
				}
			}
			if syncErr := artifact.Sync(); syncErr != nil {
				err = syncErr
			}
			artifact.Close()
		} else {
			err = openErr
		}
		if err != nil {
			run.Status, run.ParserOutcome, run.Reason = "failed", "FAILED", "comparison evidence could not be persisted"
		} else {
			run.ParserOutcome = "SUCCESS"
			run.Reason = comparison.Reason
			if run.Completeness == "partial" {
				run.Limitations = []RunLimitation{{Kind: "nextjs_version_correlation", Reason: comparison.Reason}}
			}
		}
		output = append(output, finalizeRun(run))
	}
	return output
}
