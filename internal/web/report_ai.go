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

const reportPromptVersion = "scanner-report-v5"

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

// reportManifestNeedsRefresh ensures cached PDFs/manifests created before the
// evidence section was added are rebuilt from their saved scanner artifacts.
func reportManifestNeedsRefresh(scanDir string) bool {
	data, err := os.ReadFile(filepath.Join(scanDir, "report.json"))
	if err != nil {
		return true
	}
	var header struct {
		PromptVersion string `json:"prompt_version"`
	}
	return json.Unmarshal(data, &header) != nil || header.PromptVersion != reportPromptVersion
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
	EvidenceItems         []reportEvidenceItem      `json:"evidence_items,omitempty"`
}

type reportEvidenceItem struct {
	EvidenceCompleteness string `json:"evidence_completeness,omitempty"`
	Scanner              string `json:"scanner,omitempty"`
	SourceID             string `json:"source_id,omitempty"`
	EvidenceReference    string `json:"evidence_reference,omitempty"`
	Target               string `json:"target,omitempty"`
	Endpoint             string `json:"endpoint,omitempty"`
	Method               string `json:"method,omitempty"`
	Parameter            string `json:"parameter,omitempty"`
	ParameterLocation    string `json:"parameter_location,omitempty"`
	SourceLocation       string `json:"source_location,omitempty"`
	Package              string `json:"package,omitempty"`
	PackageVersion       string `json:"package_version,omitempty"`
	Protocol             string `json:"protocol,omitempty"`
	Port                 string `json:"port,omitempty"`
	Container            string `json:"container,omitempty"`
	Resource             string `json:"resource,omitempty"`
	Description          string `json:"description,omitempty"`
	Evidence             string `json:"evidence,omitempty"`
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
		if (run.Status == "completed" || (run.Scanner == "testssl" && run.Status == "failed" && run.Checksum != "")) && run.ArtifactPath != "" {
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
		evidenceItems := make([]reportEvidenceItem, 0, len(f.ObservationIDs))
		if len(f.ObservationIDs) > 0 {
			primary = observations[f.ObservationIDs[0]]
		}
		for _, observationID := range f.ObservationIDs {
			observation, ok := observations[observationID]
			if !ok {
				continue
			}
			evidenceItems = append(evidenceItems, evidenceItemFromObservation(observation))
		}
		out = append(out, reportFinding{SourceID: f.ID, Fingerprint: f.Fingerprint, NormalizedType: f.NormalizedType, DedupeScope: string(f.DedupeScope), Scanner: firstFindingScanner(securityFindingToSummary(f)), Scanners: append([]string(nil), f.Scanners...), Title: f.Title, Severity: f.Severity, SeverityUnrated: primary.SeverityUnrated, Status: string(f.Status), StatusReason: f.StatusReason, Target: sanitizeEvidenceText(sanitizeEvidenceURL(f.Target)), Endpoint: sanitizeEvidenceURL(firstFindingEndpoint(f)), AffectedEndpointCount: f.AffectedEndpointCount, AffectedInstanceCount: f.AffectedInstanceCount, ObservationCount: f.ObservationCount, ObservationIDs: append([]string(nil), f.ObservationIDs...), AffectedEndpoints: sanitizeFindingEndpoints(f.Endpoints), EvidenceItems: evidenceItems, Explanation: "The originating scanners reported this normalized issue; review the linked raw observations for evidence.", Evidence: sanitizeEvidenceText(primary.Evidence), EvidenceRef: sanitizeEvidenceText(primary.EvidenceReference), CVE: strings.Join(f.CVE, ", "), CWE: strings.Join(f.CWE, ", "), CVSS: f.CVSS, Impact: "Scanner-reported issue; validate impact in the affected environment.", Scope: f.Scope})
	}
	return out
}

// fallbackReportFindings remains as a compatibility helper for callers and
// tests that construct parser findings directly instead of a snapshot.
func fallbackReportFindings(in []scanner.Finding) []reportFinding {
	out := make([]reportFinding, 0, len(in))
	for _, f := range in {
		out = append(out, reportFinding{SourceID: f.SourceID, Fingerprint: f.Fingerprint, Scanner: f.Scanner, Title: f.Title, Severity: f.Severity, SeverityUnrated: f.SeverityUnrated, Target: sanitizeEvidenceText(sanitizeEvidenceURL(f.Target)), Endpoint: sanitizeEvidenceURL(f.Endpoint), Method: f.Method, Parameter: f.Parameter, Explanation: sanitizeEvidenceText(firstNonBlank(f.Description, "The originating scanner reported this issue in its native output.")), Evidence: sanitizeEvidenceText(f.Evidence), EvidenceRef: sanitizeEvidenceText(f.EvidenceRef), EvidenceItems: []reportEvidenceItem{{Scanner: f.Scanner, SourceID: f.SourceID, EvidenceReference: sanitizeEvidenceText(f.EvidenceRef), Target: sanitizeEvidenceText(sanitizeEvidenceURL(f.Target)), Endpoint: sanitizeEvidenceURL(f.Endpoint), Method: f.Method, Parameter: f.Parameter, ParameterLocation: f.ParameterLocation, SourceLocation: sanitizeEvidenceText(f.SourceLocation), Package: sanitizeEvidenceText(f.Package), PackageVersion: sanitizeEvidenceText(f.PackageVersion), Protocol: f.Protocol, Port: f.Port, Container: sanitizeEvidenceText(f.Container), Resource: sanitizeEvidenceText(f.Resource), Description: sanitizeEvidenceText(f.Description), Evidence: sanitizeEvidenceText(f.Evidence)}}, CVE: f.CVE, CWE: f.CWE, CVSS: f.CVSS, Impact: "Scanner-reported issue; validate impact in the affected environment.", Scope: f.Scope})
	}
	return out
}

func reportFindingsToVulns(in []reportFinding) []VulnSummary {
	out := make([]VulnSummary, 0, len(in))
	for _, f := range in {
		scanners := reportScanners(f)
		tags := append([]string{"scanner-reported"}, scanners...)
		out = append(out, VulnSummary{ID: f.SourceID, Fingerprint: f.Fingerprint, NormalizedType: f.NormalizedType, DedupeScope: f.DedupeScope, Title: f.Title, Severity: f.Severity, Status: f.Status, StatusReason: f.StatusReason, Target: f.Target, Scope: f.Scope, Endpoint: f.Endpoint, Method: f.Method, Parameter: f.Parameter, CVSS: f.CVSS, ObservationIDs: append([]string(nil), f.ObservationIDs...), Scanners: append([]string(nil), scanners...), AffectedEndpointCount: f.AffectedEndpointCount, AffectedInstanceCount: f.AffectedInstanceCount, ObservationCount: f.ObservationCount, AffectedEndpoints: append([]scanner.FindingEndpoint(nil), f.AffectedEndpoints...), Description: f.Explanation, Impact: f.Impact, CVE: f.CVE, CWE: f.CWE, Confidence: f.Confidence, NativeConfidence: f.NativeConfidence, EvidenceCompleteness: f.EvidenceCompleteness, TechnicalAnalysis: renderFindingEvidence(f), Remediation: f.Remediation, VerificationMethod: strings.Join(scanners, ", "), Verified: f.Status == string(scanner.StatusConfirmed), Tags: tags})
	}
	return out
}

func evidenceItemFromObservation(o scanner.RawObservation) reportEvidenceItem {
	o = sanitizeFindingObservation(o)
	return reportEvidenceItem{EvidenceCompleteness: o.EvidenceCompleteness, Scanner: o.Scanner, SourceID: o.SourceID, EvidenceReference: o.EvidenceReference, Target: o.Target, Endpoint: o.Endpoint, Method: o.Method, Parameter: o.Parameter, ParameterLocation: o.ParameterLocation, SourceLocation: o.SourceLocation, Package: o.Package, PackageVersion: o.PackageVersion, Protocol: o.Protocol, Port: o.Port, Container: o.Container, Resource: o.Resource, Description: o.Description, Evidence: o.Evidence}
}

func sanitizeFindingEndpoints(in []scanner.FindingEndpoint) []scanner.FindingEndpoint {
	out := append([]scanner.FindingEndpoint(nil), in...)
	for i := range out {
		out[i].Endpoint = sanitizeEvidenceURL(out[i].Endpoint)
		out[i].CanonicalEndpoint = sanitizeEvidenceURL(out[i].CanonicalEndpoint)
		out[i].Parameter = sanitizeEvidenceText(out[i].Parameter)
	}
	return out
}

func renderFindingEvidence(f reportFinding) string {
	var b strings.Builder
	if len(f.EvidenceItems) == 0 {
		b.WriteString("Affected location: Not provided by scanner.\nEvidence excerpt: ")
		b.WriteString(firstNonBlank(sanitizeEvidenceText(f.Evidence), "Not provided by scanner"))
		if ref := reportEvidenceRefs(f); strings.TrimSpace(strings.TrimSuffix(ref, ":")) != "Evidence reference" {
			b.WriteString("\n")
			b.WriteString(sanitizeEvidenceText(ref))
		}
		return b.String()
	}
	b.WriteString("Scanner evidence and affected locations:\n")
	for i, item := range f.EvidenceItems {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(fmt.Sprintf("Observation %d — scanner: %s", i+1, firstNonBlank(item.Scanner, "Not provided by scanner")))
		if item.SourceID != "" {
			b.WriteString("; source: " + sanitizeEvidenceText(item.SourceID))
		}
		b.WriteString("\nEvidence available: " + evidenceAvailabilityLabel(item))
		b.WriteString("\nLocation: " + evidenceLocation(item))
		if item.EvidenceReference != "" {
			b.WriteString("\nEvidence reference: " + sanitizeEvidenceText(item.EvidenceReference))
		}
		if item.Description != "" {
			b.WriteString("\nFinding detail: " + item.Description)
		}
		evidence := firstNonBlank(item.Evidence, "Not provided by scanner")
		b.WriteString("\nEvidence excerpt: " + sanitizeEvidenceText(evidence))
	}
	return b.String()
}

func evidenceLocation(item reportEvidenceItem) string {
	parts := []string{}
	if item.Endpoint != "" {
		parts = append(parts, "URL/endpoint="+sanitizeEvidenceURL(item.Endpoint))
	}
	if item.Method != "" {
		parts = append(parts, "method="+item.Method)
	}
	if item.Parameter != "" {
		label := "parameter"
		if item.ParameterLocation != "" {
			label = item.ParameterLocation + " parameter"
		}
		parts = append(parts, label+"="+sanitizeEvidenceText(item.Parameter))
	}
	if item.SourceLocation != "" {
		parts = append(parts, "source="+item.SourceLocation)
	}
	if item.Package != "" {
		value := item.Package
		if item.PackageVersion != "" {
			value += "@" + item.PackageVersion
		}
		parts = append(parts, "package="+value)
	}
	if item.Protocol != "" || item.Port != "" {
		parts = append(parts, "service="+strings.Trim(strings.Join([]string{item.Protocol, item.Port}, "/"), "/"))
	}
	if item.Target != "" {
		parts = append(parts, "target="+sanitizeEvidenceText(sanitizeEvidenceURL(item.Target)))
	}
	if item.Container != "" {
		parts = append(parts, "container="+item.Container)
	}
	if item.Resource != "" {
		parts = append(parts, "resource="+item.Resource)
	}
	if len(parts) == 0 {
		return "Not provided by scanner"
	}
	return strings.Join(parts, "; ")
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

func evidenceAvailabilityLabel(item reportEvidenceItem) string {
	label := "Not provided by scanner"
	if item.Evidence != "" {
		label = "Scanner output excerpt"
	} else if item.EvidenceReference != "" {
		label = "Scanner reference only"
	}
	if item.EvidenceCompleteness == "request_response" {
		label = "Request/response recorded by scanner"
	}
	if item.EvidenceCompleteness == "partial" {
		label += " (partial)"
	}
	return label
}
