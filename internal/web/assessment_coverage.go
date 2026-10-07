package web

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

type assessmentJobCoverage struct {
	ID              string            `json:"id"`
	Scanner         string            `json:"scanner"`
	Variant         string            `json:"variant"`
	TargetID        string            `json:"target_id"`
	Target          string            `json:"target"`
	AssessmentTypes []assessment.Type `json:"assessment_types,omitempty"`
	PlannedState    scanner.PlanState `json:"planned_state"`
	Status          string            `json:"status"`
	Reason          string            `json:"reason,omitempty"`
	StartedAt       string            `json:"started_at,omitempty"`
	FinishedAt      string            `json:"finished_at,omitempty"`
	HasArtifact     bool              `json:"has_artifact"`
	ArtifactState   string            `json:"artifact_state"`
	// Limitations are categories the run did not cover, such as an adapter whose
	// traffic is not gateway-enforced. A completed status is not full coverage.
	Limitations []scanner.RunLimitation `json:"limitations,omitempty"`
}

type assessmentCapabilityCoverage struct {
	Capability string                   `json:"capability"`
	TargetID   string                   `json:"target_id,omitempty"`
	State      assessment.EvidenceState `json:"state"`
	Reason     string                   `json:"reason"`
}

type assessmentOperationCoverage struct {
	TargetID string `json:"target_id"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Origin   string `json:"origin,omitempty"`
	Status   string `json:"status"`
	Reason   string `json:"reason"`
	Eligible bool   `json:"eligible"`
}

type assessmentOperationCounts struct {
	Discovered     int `json:"discovered"`
	Eligible       int `json:"eligible"`
	Attempted      int `json:"attempted"`
	Completed      int `json:"completed"`
	BatchCompleted int `json:"batch_completed"`
	Failed         int `json:"failed"`
	Skipped        int `json:"skipped"`
	NotAttempted   int `json:"not_attempted"`
}

type assessmentCoverageResponse struct {
	Proof           *scanner.CoverageProof         `json:"proof,omitempty"`
	ScanID          string                         `json:"scan_id"`
	State           string                         `json:"state"`
	Profile         string                         `json:"profile,omitempty"`
	PlanFingerprint string                         `json:"plan_fingerprint,omitempty"`
	Mode            assessment.Mode                `json:"assessment_mode,omitempty"`
	Types           []assessment.Type              `json:"assessment_types,omitempty"`
	TypeCoverage    []scanner.TypeCoverage         `json:"type_coverage,omitempty"`
	Jobs            []assessmentJobCoverage        `json:"jobs,omitempty"`
	Capabilities    []assessmentCapabilityCoverage `json:"capabilities,omitempty"`
	Operations      []assessmentOperationCoverage  `json:"api_operations,omitempty"`
	OperationCounts assessmentOperationCounts      `json:"api_operation_counts"`
	Gaps            []scanner.PlanDecision         `json:"gaps,omitempty"`
	Counts          map[string]int                 `json:"counts"`
	Reason          string                         `json:"reason,omitempty"`
}

func isScanCoveragePath(path string) bool {
	return strings.HasPrefix(path, "/api/scans/") && strings.HasSuffix(path, "/coverage")
}

func (s *Server) handleAssessmentCoverage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	scanID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/scans/"), "/coverage")
	if scanID == "" || strings.Contains(scanID, "/") {
		http.Error(w, "invalid assessment coverage path", http.StatusBadRequest)
		return
	}
	scanDir, record := s.findScanByID(scanID)
	if record == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(buildAssessmentCoverage(scanID, record, scanDir))
}

func buildAssessmentCoverage(scanID string, record *ScanRecord, scanDir string) assessmentCoverageResponse {
	coverage := assessmentCoverageResponse{ScanID: scanID, State: "legacy", Counts: map[string]int{}}
	if record != nil {
		proof := scanner.BuildCoverageProof(scanner.LoadAttackSurfaces(scanDir), record.ScannerRuns)
		coverage.Proof = &proof
	}
	if record == nil || record.AssessmentPlan == nil {
		coverage.Reason = "This scan predates assessment planning and has no recorded coverage snapshot."
		return coverage
	}
	plan := record.AssessmentPlan
	coverage.Profile = record.Profile
	coverage.PlanFingerprint = record.PlanFingerprint
	coverage.Mode = plan.Config.Mode
	coverage.Types = append([]assessment.Type(nil), plan.Config.Types...)
	coverage.TypeCoverage = append([]scanner.TypeCoverage(nil), plan.Coverage...)
	for _, capability := range plan.Capabilities {
		state, reason := capability.State, capability.Reason
		if capability.Capability == assessment.CapAuthWeb {
			for _, run := range record.ScannerRuns {
				if run.Scanner == "zap" && run.Status == "failed" && strings.Contains(run.Reason, "authenticated session") {
					for _, job := range plan.Jobs {
						if job.Scanner == "zap" && job.TargetID == capability.TargetID && job.Target == run.Target {
							state, reason = assessment.StateUnavailable, "authenticated session expired during scanning; remaining checks were not completed"
						}
					}
				}
			}
		}
		coverage.Capabilities = append(coverage.Capabilities, assessmentCapabilityCoverage{
			Capability: string(capability.Capability), TargetID: capability.TargetID,
			State: state, Reason: reason,
		})
	}
	for _, endpoint := range plan.APIEndpoints {
		coverage.OperationCounts.Discovered++
		if endpoint.Resolved && endpoint.Eligible {
			coverage.OperationCounts.Eligible++
		}
		operation := assessmentOperationCoverage{
			TargetID: endpoint.TargetID, Method: endpoint.Method, Path: endpoint.Path, Origin: endpoint.Origin,
			Status: "inventoried_not_executed", Reason: "operation is inventoried but has not been submitted to ZAP", Eligible: endpoint.Eligible,
		}
		if !endpoint.Resolved || !endpoint.Eligible {
			operation.Status = "skipped"
			operation.Reason = endpoint.Reason
			if operation.Reason == "" {
				operation.Reason = "operation needs values or explicit approval"
			}
		} else {
			var targetValue string
			for _, target := range plan.Config.Targets {
				if target.ID == endpoint.TargetID {
					targetValue = target.Value
					break
				}
			}
			for _, run := range record.ScannerRuns {
				if (run.Scanner != "zap" && run.Scanner != "apichecks") || run.Target != targetValue || run.PlanFingerprint != plan.Fingerprint {
					continue
				}
				found := false
				for _, result := range run.APIEndpointResults {
					if result.Method == endpoint.Method && result.Path == endpoint.Path && (endpoint.Origin == "" || result.Origin == endpoint.Origin) {
						operation.Status, operation.Reason, found = result.Status, result.Reason, true
						if run.Scanner == "apichecks" && result.Status == "checked" {
							operation.Status = "tested"
							operation.Reason = "Native read-only API checks completed for this operation."
						} else if result.Status == "seeded" {
							if run.Status == "completed" {
								operation.Status = "batch_completed"
								operation.Reason = "Operation was seeded into the scoped ZAP batch; ZAP does not report per-operation completion."
							} else if run.Status == "running" {
								operation.Status = "attempted"
								operation.Reason = "Operation was seeded into a ZAP batch that is still running."
							} else {
								operation.Status = "incomplete"
								operation.Reason = "Operation was seeded, but the ZAP batch did not complete."
							}
						}
						break
					}
				}
				if !found && run.Status != "running" {
					operation.Status, operation.Reason = "not_attempted", run.Reason
					if operation.Reason == "" {
						operation.Reason = "ZAP finished without recording an operation attempt"
					}
				}
				break
			}
		}
		// An approved write is sent by its own job, not by apichecks or ZAP, so its
		// outcome is joined here: otherwise a write that ran once with cleanup would
		// still read "skipped: needs an explicit safe request example".
		writeTarget := ""
		for _, target := range plan.Config.Targets {
			if target.ID == endpoint.TargetID {
				writeTarget = target.Value
				break
			}
		}
		for _, run := range record.ScannerRuns {
			if run.Scanner != "apiwrites" || run.PlanFingerprint != plan.Fingerprint || run.Target != writeTarget {
				continue
			}
			for _, result := range run.APIEndpointResults {
				if result.Method != endpoint.Method || result.Path != endpoint.Path {
					continue
				}
				switch result.Status {
				case "completed":
					operation.Status, operation.Reason = "tested", "Approved write was sent once and its declared cleanup completed."
				case "written":
					operation.Status, operation.Reason = "incomplete", "Approved write was sent but its declared cleanup was not confirmed."
				case "cleanup_failed", "failed":
					operation.Status, operation.Reason = "failed", result.Reason
				default:
					if operation.Status == "skipped" && result.Reason != "" {
						operation.Reason = result.Reason
					}
				}
			}
		}
		switch operation.Status {
		case "attempted":
			coverage.OperationCounts.Attempted++
		case "batch_completed":
			coverage.OperationCounts.Attempted++
			coverage.OperationCounts.BatchCompleted++
		case "tested":
			coverage.OperationCounts.Attempted++
			coverage.OperationCounts.Completed++
		case "failed", "incomplete":
			coverage.OperationCounts.Attempted++
			coverage.OperationCounts.Failed++
		case "skipped":
			coverage.OperationCounts.Skipped++
		default:
			coverage.OperationCounts.NotAttempted++
		}
		coverage.Operations = append(coverage.Operations, operation)
	}
	for _, decision := range plan.Decisions {
		if decision.State != scanner.PlanNotApplicable && decision.State != scanner.PlanSelected {
			coverage.Gaps = append(coverage.Gaps, decision)
		}
	}
	for _, job := range plan.Jobs {
		item := assessmentJobCoverage{
			ID: job.ID, Scanner: job.Scanner, Variant: job.Variant, TargetID: job.TargetID, Target: job.Target,
			AssessmentTypes: append([]assessment.Type(nil), job.AssessmentTypes...), PlannedState: job.State,
			Status: "queued", Reason: "planned job has not started",
		}
		for _, run := range record.ScannerRuns {
			if run.Scanner != job.Scanner || run.Variant != job.Variant || run.Target != job.Target || run.PlanFingerprint != plan.Fingerprint {
				continue
			}
			item.Status, item.Reason = run.Status, run.Reason
			item.StartedAt, item.FinishedAt = run.StartedAt, run.FinishedAt
			item.ArtifactState = assessmentArtifactState(scanDir, run)
			item.HasArtifact = item.ArtifactState == "verified"
			item.Limitations = append([]scanner.RunLimitation(nil), run.Limitations...)
			break
		}
		if job.State == scanner.PlanConditional && item.Status == "queued" {
			item.Status = "skipped"
			item.Reason = "conditional job awaits target-scoped preparation"
		}
		coverage.Counts[item.Status]++
		coverage.Jobs = append(coverage.Jobs, item)
	}
	for index := range coverage.TypeCoverage {
		typeCoverage := &coverage.TypeCoverage[index]
		matching, allComplete, hasRunning := 0, true, false
		for _, job := range coverage.Jobs {
			if !containsAssessmentType(job.AssessmentTypes, typeCoverage.Type) {
				continue
			}
			matching++
			if job.Status != "completed" {
				allComplete = false
			}
			if job.Status == "running" || job.Status == "queued" {
				hasRunning = true
			}
		}
		hasGap := false
		for _, gap := range coverage.Gaps {
			if containsAssessmentType(gap.Types, typeCoverage.Type) {
				hasGap = true
				break
			}
		}
		if typeCoverage.Type == assessment.TypeAPI {
			for _, operation := range coverage.Operations {
				if operation.Status != "batch_completed" && operation.Status != "tested" {
					hasGap = true
					break
				}
			}
		}
		switch {
		case matching == 0:
			typeCoverage.State = "not_tested"
		case hasRunning:
			typeCoverage.State = "in_progress"
		case allComplete && !hasGap:
			typeCoverage.State = "complete"
			typeCoverage.Reason = "All selected jobs for this type completed."
		default:
			typeCoverage.State = "partial"
			typeCoverage.Reason = "At least one selected job was skipped, failed, or not fully covered."
		}
	}
	switch strings.ToLower(strings.TrimSpace(record.Status)) {
	case "running", "pending", "saved":
		coverage.State = strings.ToLower(strings.TrimSpace(record.Status))
	case "failed":
		coverage.State = "failed"
	case "stopped", "cancelled":
		coverage.State = "partial"
	default:
		coverage.State = "complete"
		for _, job := range coverage.Jobs {
			if job.Status != "completed" {
				coverage.State = "partial"
				break
			}
		}
		if len(coverage.Gaps) > 0 || len(coverage.TypeCoverage) == 0 {
			coverage.State = "partial"
		}
		for _, typeCoverage := range coverage.TypeCoverage {
			if typeCoverage.State != "complete" {
				coverage.State = "partial"
				break
			}
		}
	}
	return coverage
}

func containsAssessmentType(types []assessment.Type, want assessment.Type) bool {
	for _, typ := range types {
		if typ == want {
			return true
		}
	}
	return false
}

func assessmentArtifactState(scanDir string, run scanner.Run) string {
	if run.ArtifactPath == "" {
		return "unavailable"
	}
	path, ok := safeScannerPath(scanDir, run.ArtifactPath)
	if !ok {
		return "unavailable"
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "unavailable"
	}
	if scanner.VerifyChecksum(run) != nil {
		return "unverified"
	}
	return "verified"
}
