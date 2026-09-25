package web

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/llm"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

const reportPromptVersion = "scanner-report-v2"

type reportManifest struct {
	SchemaVersion int                 `json:"schema_version"`
	Mode          string              `json:"mode"`
	PromptVersion string              `json:"prompt_version"`
	GeneratedAt   string              `json:"generated_at"`
	Model         string              `json:"model,omitempty"`
	Provider      string              `json:"provider,omitempty"`
	SourceRuns    []scanner.Run       `json:"source_runs"`
	ParseErrors   []string            `json:"parse_errors,omitempty"`
	Scopes        []reportScope       `json:"scopes,omitempty"`
	Recon         *reportReconSummary `json:"recon,omitempty"`
	Findings      []reportFinding     `json:"findings"`
}

type reportFinding struct {
	SourceID    string                  `json:"source_id"`
	Scanner     string                  `json:"scanner"`
	Title       string                  `json:"title"`
	Severity    string                  `json:"severity"`
	Target      string                  `json:"target,omitempty"`
	Endpoint    string                  `json:"endpoint,omitempty"`
	Explanation string                  `json:"explanation"`
	Evidence    string                  `json:"evidence,omitempty"`
	EvidenceRef string                  `json:"evidence_reference"`
	Impact      string                  `json:"impact,omitempty"`
	Remediation string                  `json:"remediation,omitempty"`
	CVE         string                  `json:"cve,omitempty"`
	CWE         string                  `json:"cwe,omitempty"`
	CVSS        float64                 `json:"cvss,omitempty"`
	Scope       string                  `json:"scope,omitempty"`
	Sources     []scanner.FindingSource `json:"sources,omitempty"`
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
	parsed, parseErrs := scanner.ParseRuns(rec.ScannerRuns)
	manifest := reportManifest{SchemaVersion: 2, Mode: "deterministic_fallback", PromptVersion: reportPromptVersion, GeneratedAt: time.Now().Format(time.RFC3339Nano), SourceRuns: append([]scanner.Run(nil), rec.ScannerRuns...), Findings: fallbackReportFindings(parsed)}
	for _, err := range parseErrs {
		manifest.ParseErrors = append(manifest.ParseErrors, err.Error())
	}
	if enriched, err := s.aiReportFindings(parsed); err == nil && len(enriched) > 0 {
		manifest.Mode = "ai"
		manifest.Model = s.cfg.LLM
		manifest.Provider = s.cfg.LLMProvider
		manifest.Findings = enriched
	} else if err != nil {
		log.Printf("[report] AI unavailable or invalid; deterministic fallback: %v", err)
	}
	scopes := buildReportScopes(scanDir, rec.ScannerRuns)
	recon := summarizeReportRecon(scopes)
	manifest.Scopes, manifest.Recon = scopes, &recon
	orderReportFindings(manifest.Findings, scopes)
	data, _ := json.MarshalIndent(manifest, "", "  ")
	_ = os.WriteFile(filepath.Join(scanDir, "report.json"), data, 0o600)
	copyRec := *rec
	copyRec.Vulns = reportFindingsToVulns(manifest.Findings)
	copyRec.ReportMode = manifest.Mode
	copyRec.ReportGeneratedAt = manifest.GeneratedAt
	copyRec.ReportScopes = scopes
	path, err := s.generateReportAt(&copyRec, scanDir)
	if err != nil {
		log.Printf("[report] PDF generation failed: %v", err)
		return ""
	}
	rec.ReportMode, rec.ReportGeneratedAt = manifest.Mode, manifest.GeneratedAt
	eventType := "report_ready"
	if manifest.Mode != "ai" {
		eventType = "report_fallback"
	}
	readyEvent := WSEvent{Type: eventType, Content: fmt.Sprintf("%s report ready", strings.ReplaceAll(manifest.Mode, "_", " ")), Output: "/api/report/" + rec.ID, Timestamp: time.Now().Format(time.RFC3339Nano)}
	rec.Events = append(rec.Events, readyEvent)
	s.saveScanRecordTo(rec, scanDir)
	s.broadcastToInstance(instanceID, readyEvent)
	return path
}

func fallbackReportFindings(in []scanner.Finding) []reportFinding {
	out := make([]reportFinding, 0, len(in))
	for _, f := range in {
		out = append(out, reportFinding{SourceID: f.SourceID, Scanner: f.Scanner, Title: f.Title, Severity: f.Severity, Target: f.Target, Endpoint: f.Endpoint, Explanation: firstNonBlank(f.Description, "The originating scanner reported this issue in its native output."), Evidence: f.Evidence, EvidenceRef: f.EvidenceRef, CVE: f.CVE, CWE: f.CWE, CVSS: f.CVSS, Impact: "Scanner-reported issue; validate impact in the affected environment.", Remediation: "Review the scanner evidence and apply the vendor or project remediation guidance.", Scope: f.Scope, Sources: f.Sources})
	}
	return out
}

func (s *Server) aiReportFindings(in []scanner.Finding) ([]reportFinding, error) {
	if len(in) == 0 {
		return nil, nil
	}
	if strings.TrimSpace(s.cfg.LLM) == "" {
		return nil, fmt.Errorf("Report AI model is not configured")
	}
	client := llm.NewClient(s.cfg)
	var out []reportFinding
	for start := 0; start < len(in); start += 50 {
		end := start + 50
		if end > len(in) {
			end = len(in)
		}
		chunk := in[start:end]
		// The model sees only primary records: a merged finding's sources[] hold
		// secondary source_ids the allow-map rejects, so an echoed one would
		// force a fallback. Sources are restored from the chunk below. Copy, so
		// the caller's findings are not mutated.
		projection := make([]scanner.Finding, len(chunk))
		copy(projection, chunk)
		for i := range projection {
			projection[i].Sources = nil
		}
		payload, _ := json.Marshal(projection)
		prompt := `You generate a security report from scanner records. You may explain, deduplicate, classify, and recommend remediation, but must not invent findings, claim exploitation, or claim independent verification. Return JSON only: {"findings":[{"source_id":"exact input source_id","scope":"exact input scope","scanner":"exact input scanner","title":"...","severity":"critical|high|medium|low|info","target":"exact input target","endpoint":"...","explanation":"...","evidence":"concise input-backed evidence","evidence_reference":"exact input evidence_reference","impact":"...","remediation":"...","cve":"...","cwe":"...","cvss":0.0}]}. Every output item must use an exact source_id, scope, target, and evidence_reference from the input.` + "\nINPUT:\n" + string(payload)
		resp, err := client.Chat([]llm.Message{{Role: "system", Content: "Report-generation stage only. Produce strict JSON grounded exclusively in supplied scanner records."}, {Role: "user", Content: prompt}})
		if err != nil {
			return nil, err
		}
		clean := strings.TrimSpace(llm.CleanContent(resp))
		clean = strings.TrimPrefix(strings.TrimSuffix(clean, "```"), "```json")
		var envelope struct {
			Findings []reportFinding `json:"findings"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(clean)), &envelope); err != nil {
			return nil, fmt.Errorf("invalid Report AI JSON: %w", err)
		}
		allowed := map[string][]scanner.Finding{}
		bySource := map[string][]scanner.Finding{}
		for _, f := range chunk {
			key := aiFindingKey(f.Scope, f.SourceID)
			allowed[key] = append(allowed[key], f)
			bySource[f.SourceID] = append(bySource[f.SourceID], f)
		}
		for _, f := range envelope.Findings {
			src, ok := matchAIFinding(allowed, bySource, f.Scope, f.SourceID, f.Target)
			if !ok {
				return nil, fmt.Errorf("Report AI returned source_id %q (scope %q, target %q) that matches no single input finding", f.SourceID, f.Scope, f.Target)
			}
			f.Scanner = src.Scanner
			f.Target = firstNonBlank(f.Target, src.Target)
			f.Endpoint = firstNonBlank(f.Endpoint, src.Endpoint)
			f.Evidence = firstNonBlank(f.Evidence, src.Evidence)
			f.EvidenceRef = src.EvidenceRef
			f.Scope = src.Scope
			f.Sources = src.Sources
			f.CVE = firstNonBlank(f.CVE, src.CVE)
			f.CWE = firstNonBlank(f.CWE, src.CWE)
			if f.CVSS == 0 {
				f.CVSS = src.CVSS
			}
			f.Severity = normalizeSeverityBucket(f.Severity)
			// The scanner (or merged, highest-contributor) severity is a floor:
			// the AI may explain and classify a finding, not downgrade it. An
			// unrated placeholder severity is not a floor, so the AI may rate
			// it freely.
			if srcSev := normalizeSeverityBucket(src.Severity); !src.SeverityUnrated && severityRankValue(srcSev) > severityRankValue(f.Severity) {
				f.Severity = srcSev
			}
			if strings.TrimSpace(f.Title) == "" || strings.TrimSpace(f.Explanation) == "" || strings.TrimSpace(f.EvidenceRef) == "" || strings.TrimSpace(f.Impact) == "" || strings.TrimSpace(f.Remediation) == "" {
				return nil, fmt.Errorf("Report AI returned incomplete structured finding for source_id %q", f.SourceID)
			}
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].SourceID != out[j].SourceID {
			return out[i].SourceID < out[j].SourceID
		}
		return out[i].Scope < out[j].Scope
	})
	return out, nil
}

// aiFindingKey identifies the input findings an AI item may refer to. A
// SourceID alone is not unique: two host scopes on one IP can both report
// nmap:<ip>:<port>. Nor is (scope, source_id): an osv SourceID carries no path,
// so one package in two lockfiles of a source scope yields two inputs that
// differ only by Target.
func aiFindingKey(scope, sourceID string) string { return scope + "\x00" + sourceID }

// matchAIFinding resolves an AI output item to exactly one input finding. The
// candidates are the inputs with the item's (scope, source_id), or, when the AI
// omitted or garbled the scope, the inputs with its source_id. Several
// candidates are narrowed by the item's exact target. ok is false unless
// exactly one candidate remains, which rejects the AI response and forces the
// deterministic fallback.
func matchAIFinding(allowed, bySource map[string][]scanner.Finding, scope, sourceID, target string) (scanner.Finding, bool) {
	cands := allowed[aiFindingKey(scope, sourceID)]
	if len(cands) == 0 {
		cands = bySource[sourceID]
	}
	if len(cands) == 1 {
		return cands[0], true
	}
	if len(cands) == 0 || target == "" {
		return scanner.Finding{}, false
	}
	want := filepath.ToSlash(filepath.Clean(target))
	var match []scanner.Finding
	for _, c := range cands {
		if filepath.ToSlash(filepath.Clean(c.Target)) == want {
			match = append(match, c)
		}
	}
	if len(match) == 1 {
		return match[0], true
	}
	return scanner.Finding{}, false
}

func reportFindingsToVulns(in []reportFinding) []VulnSummary {
	out := make([]VulnSummary, 0, len(in))
	for i, f := range in {
		scanners := reportScanners(f)
		tags := append([]string{"scanner-reported"}, scanners...)
		out = append(out, VulnSummary{ID: fmt.Sprintf("SCAN-%04d", i+1), Title: f.Title, Severity: f.Severity, Target: f.Target, Scope: f.Scope, Endpoint: f.Endpoint, CVSS: f.CVSS, Description: f.Explanation, Impact: f.Impact, CVE: f.CVE, CWE: f.CWE, TechnicalAnalysis: f.Evidence + "\n" + reportEvidenceRefs(f), Remediation: f.Remediation, ExploitationProof: "Scanner-reported evidence; no independent exploitation was performed.", VerificationMethod: strings.Join(scanners, ", "), Verified: false, Tags: tags})
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
