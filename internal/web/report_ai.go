package web

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

const reportPromptVersion = "scanner-report-v2"

type reportManifest struct {
	SchemaVersion int                         `json:"schema_version"`
	Mode          string                      `json:"mode"`
	PromptVersion string                      `json:"prompt_version"`
	GeneratedAt   string                      `json:"generated_at"`
	Model         string                      `json:"model,omitempty"`
	Provider      string                      `json:"provider,omitempty"`
	SourceRuns    []scanner.Run               `json:"source_runs"`
	ParseErrors   []string                    `json:"parse_errors,omitempty"`
	Scopes        []reportScope               `json:"scopes,omitempty"`
	Recon         *reportReconSummary         `json:"recon,omitempty"`
	Assessment    *assessmentCoverageResponse `json:"assessment_coverage,omitempty"`
	Findings      []reportFinding             `json:"findings"`
}

type reportFinding struct {
	SourceID              string                    `json:"source_id"`
	Fingerprint           string                    `json:"fingerprint,omitempty"`
	NormalizedType        string                    `json:"normalized_type,omitempty"`
	DedupeScope           string                    `json:"dedupe_scope,omitempty"`
	Scanner               string                    `json:"scanner"`
	Title                 string                    `json:"title"`
	Severity              string                    `json:"severity"`
	Status                string                    `json:"status,omitempty"`
	StatusReason          string                    `json:"status_reason,omitempty"`
	Scanners              []string                  `json:"scanners,omitempty"`
	ObservationIDs        []string                  `json:"observation_ids,omitempty"`
	AffectedEndpointCount int                       `json:"affected_endpoint_count,omitempty"`
	AffectedInstanceCount int                       `json:"affected_instance_count,omitempty"`
	ObservationCount      int                       `json:"observation_count,omitempty"`
	AffectedEndpoints     []scanner.FindingEndpoint `json:"affected_endpoints,omitempty"`
	SeverityUnrated       bool                      `json:"severity_unrated,omitempty"` // placeholder severity the scanner did not rate
	Target                string                    `json:"target,omitempty"`
	Endpoint              string                    `json:"endpoint,omitempty"`
	Method                string                    `json:"method,omitempty"`
	Parameter             string                    `json:"parameter,omitempty"`
	Explanation           string                    `json:"explanation"`
	Evidence              string                    `json:"evidence,omitempty"`
	EvidenceRef           string                    `json:"evidence_reference"`
	Impact                string                    `json:"impact,omitempty"`
	Remediation           string                    `json:"remediation,omitempty"`
	CVE                   string                    `json:"cve,omitempty"`
	CWE                   string                    `json:"cwe,omitempty"`
	CVSS                  float64                   `json:"cvss,omitempty"`
	Scope                 string                    `json:"scope,omitempty"`
	Sources               []scanner.FindingSource   `json:"sources,omitempty"`
	Confidence            string                    `json:"confidence,omitempty"`
	NativeConfidence      string                    `json:"native_confidence,omitempty"`
	EvidenceCompleteness  string                    `json:"evidence_completeness,omitempty"`
}

// GenerateCLIReport runs the same report-only AI and deterministic fallback
// path used by the web server. Scanner execution must already be complete.
func GenerateCLIReport(cfg *config.Config, target, scanDir string, runs []scanner.Run) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("configuration is required")
	}
	if len(runs) == 0 {
		return "", fmt.Errorf("no scanner runs to report")
	}
	for _, run := range runs {
		if !run.Terminal() {
			return "", fmt.Errorf("scanner %s is not terminal", run.Scanner)
		}
	}
	s := &Server{cfg: cfg, dataDir: cfg.DataDir, clients: make(map[*wsClient]bool), instances: make(map[string]*ScanInstance)}
	now := time.Now().Format(time.RFC3339Nano)
	rec := &ScanRecord{SchemaVersion: scanner.SchemaVersion, ID: filepath.Base(scanDir), Target: target, Status: "finished", StartedAt: now, FinishedAt: now, ScannerRuns: append([]scanner.Run(nil), runs...), Events: []WSEvent{}, Vulns: []VulnSummary{}}
	path := s.generateScannerReport(rec, scanDir, "")
	if path == "" {
		return "", fmt.Errorf("report generation failed")
	}
	return path, nil
}

func (s *Server) generateScannerReport(rec *ScanRecord, scanDir, instanceID string) string {
	if rec == nil {
		return ""
	}
	for _, run := range rec.ScannerRuns {
		if run.Status == "completed" && run.ArtifactPath != "" {
			if err := scanner.VerifyChecksum(run); err != nil {
				log.Printf("[report] refusing changed scanner artifact: %v", err)
				return ""
			}
		}
	}
	startedEvent := WSEvent{Type: "report_started", Content: "Generating report from immutable scanner output", Timestamp: time.Now().Format(time.RFC3339Nano)}
	rec.Events = append(rec.Events, startedEvent)
	s.saveScanRecordTo(rec, scanDir)
	s.broadcastToInstance(instanceID, startedEvent)
	snapshot, parseErrs := rebuildFindingsSnapshot(rec, scanDir, true)
	if snapshot == nil {
		return ""
	}
	manifest := reportManifest{SchemaVersion: 2, Mode: "deterministic_fallback", PromptVersion: reportPromptVersion, GeneratedAt: time.Now().Format(time.RFC3339Nano), SourceRuns: append([]scanner.Run(nil), rec.ScannerRuns...), Findings: fallbackSnapshotFindings(snapshot)}
	if rec.AssessmentPlan != nil {
		coverage := buildAssessmentCoverage(rec.ID, rec, scanDir)
		manifest.SchemaVersion = 3
		manifest.Assessment = &coverage
	}
	for _, err := range parseErrs {
		manifest.ParseErrors = append(manifest.ParseErrors, err.Error())
	}
	scopes := buildReportScopes(scanDir, rec.ScannerRuns)
	recon := summarizeReportRecon(scopes)
	manifest.Scopes, manifest.Recon = scopes, &recon
	orderReportFindings(manifest.Findings, scopes)
	data, _ := json.MarshalIndent(manifest, "", "  ")
	_ = os.WriteFile(filepath.Join(scanDir, "report.json"), data, 0o600)
	copyRec := *rec
	activeReport := make([]reportFinding, 0, len(manifest.Findings))
	for _, finding := range manifest.Findings {
		if finding.Status == "" || scanner.FindingActive(scanner.FindingStatus(finding.Status)) {
			activeReport = append(activeReport, finding)
		}
	}
	copyRec.Vulns = reportFindingsToVulns(activeReport)
	rec.Vulns = append([]VulnSummary(nil), copyRec.Vulns...)
	copyRec.ReportMode = manifest.Mode
	copyRec.ReportGeneratedAt = manifest.GeneratedAt
	copyRec.ReportScopes = scopes
	path, err := s.generateReportAt(&copyRec, scanDir)
	if err != nil {
		log.Printf("[report] PDF generation failed: %v", err)
		return ""
	}
	rec.ReportMode, rec.ReportGeneratedAt = manifest.Mode, manifest.GeneratedAt
	readyEvent := WSEvent{Type: "report_ready", Content: "Report ready", Output: "/api/report/" + rec.ID, Timestamp: time.Now().Format(time.RFC3339Nano)}
	rec.Events = append(rec.Events, readyEvent)
	s.saveScanRecordTo(rec, scanDir)
	s.broadcastToInstance(instanceID, readyEvent)
	return path
}

func fallbackSnapshotFindings(snapshot *scanner.FindingsSnapshot) []reportFinding {
	if snapshot == nil {
		return []reportFinding{}
	}
	observations := make(map[string]scanner.RawObservation, len(snapshot.RawObservations))
	for _, observation := range snapshot.RawObservations {
		observations[observation.ID] = observation
	}
	out := make([]reportFinding, 0, len(snapshot.UniqueFindings))
	for _, f := range snapshot.UniqueFindings {
		primary := scanner.RawObservation{}
		if len(f.ObservationIDs) > 0 {
			primary = observations[f.ObservationIDs[0]]
		}
		out = append(out, reportFinding{SourceID: f.ID, Fingerprint: f.Fingerprint, NormalizedType: f.NormalizedType, DedupeScope: string(f.DedupeScope), Scanner: firstFindingScanner(securityFindingToSummary(f)), Scanners: append([]string(nil), f.Scanners...), Title: f.Title, Severity: f.Severity, SeverityUnrated: primary.SeverityUnrated, Status: string(f.Status), StatusReason: f.StatusReason, Target: f.Target, Endpoint: firstFindingEndpoint(f), AffectedEndpointCount: f.AffectedEndpointCount, AffectedInstanceCount: f.AffectedInstanceCount, ObservationCount: f.ObservationCount, ObservationIDs: append([]string(nil), f.ObservationIDs...), AffectedEndpoints: append([]scanner.FindingEndpoint(nil), f.Endpoints...), Explanation: "The originating scanners reported this normalized issue; review the linked raw observations for evidence.", Evidence: primary.Evidence, EvidenceRef: primary.EvidenceReference, CVE: strings.Join(f.CVE, ", "), CWE: strings.Join(f.CWE, ", "), CVSS: f.CVSS, Impact: "Scanner-reported issue; validate impact in the affected environment.", Scope: f.Scope})
	}
	return out
}

// fallbackReportFindings remains as a compatibility helper for callers and
// tests that construct parser findings directly instead of a snapshot.
func fallbackReportFindings(in []scanner.Finding) []reportFinding {
	out := make([]reportFinding, 0, len(in))
	for _, f := range in {
		out = append(out, reportFinding{SourceID: f.SourceID, Fingerprint: f.Fingerprint, Scanner: f.Scanner, Title: f.Title, Severity: f.Severity, SeverityUnrated: f.SeverityUnrated, Target: f.Target, Endpoint: f.Endpoint, Method: f.Method, Parameter: f.Parameter, Explanation: firstNonBlank(f.Description, "The originating scanner reported this issue in its native output."), Evidence: f.Evidence, EvidenceRef: f.EvidenceRef, CVE: f.CVE, CWE: f.CWE, CVSS: f.CVSS, Impact: "Scanner-reported issue; validate impact in the affected environment.", Scope: f.Scope})
	}
	return out
}

func reportFindingsToVulns(in []reportFinding) []VulnSummary {
	out := make([]VulnSummary, 0, len(in))
	for _, f := range in {
		scanners := reportScanners(f)
		tags := append([]string{"scanner-reported"}, scanners...)
		out = append(out, VulnSummary{ID: f.SourceID, Fingerprint: f.Fingerprint, NormalizedType: f.NormalizedType, DedupeScope: f.DedupeScope, Title: f.Title, Severity: f.Severity, Status: f.Status, StatusReason: f.StatusReason, Target: f.Target, Scope: f.Scope, Endpoint: f.Endpoint, Method: f.Method, Parameter: f.Parameter, CVSS: f.CVSS, ObservationIDs: append([]string(nil), f.ObservationIDs...), Scanners: append([]string(nil), scanners...), AffectedEndpointCount: f.AffectedEndpointCount, AffectedInstanceCount: f.AffectedInstanceCount, ObservationCount: f.ObservationCount, AffectedEndpoints: append([]scanner.FindingEndpoint(nil), f.AffectedEndpoints...), Description: f.Explanation, Impact: f.Impact, CVE: f.CVE, CWE: f.CWE, Confidence: f.Confidence, NativeConfidence: f.NativeConfidence, EvidenceCompleteness: f.EvidenceCompleteness, TechnicalAnalysis: f.Evidence + "\n" + reportEvidenceRefs(f), Remediation: f.Remediation, VerificationMethod: strings.Join(scanners, ", "), Verified: f.Status == string(scanner.StatusConfirmed), Tags: tags})
	}
	return out
}

// reportScanners lists the distinct scanners that reported f, primary first.
func reportScanners(f reportFinding) []string {
	if len(f.Sources) == 0 {
		return []string{f.Scanner}
	}
	var out []string
	for _, s := range f.Sources {
		if !slices.Contains(out, s.Scanner) {
			out = append(out, s.Scanner)
		}
	}
	return out
}

// reportEvidenceRefs renders f's evidence trace: the single reference for an
// unmerged finding (unchanged shape), or one labelled line per source.
func reportEvidenceRefs(f reportFinding) string {
	if len(f.Sources) == 0 {
		return "Evidence reference: " + f.EvidenceRef
	}
	lines := make([]string, 0, len(f.Sources))
	for _, s := range f.Sources {
		lines = append(lines, fmt.Sprintf("Evidence reference (%s): %s", s.Scanner, s.EvidenceRef))
	}
	return strings.Join(lines, "\n")
}
