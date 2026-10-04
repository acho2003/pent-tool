package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/apifixture"
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

func (s *Server) scannerAvailability() map[string]bool {
	available := map[string]bool{}
	paths := map[string]string{
		"subfinder": s.cfg.SubfinderPath, "amass": s.cfg.AmassPath, "dnsx": s.cfg.DNSXPath, "gau": s.cfg.GauPath, "waybackurls": s.cfg.WaybackurlsPath, "httpx": s.cfg.HttpxPath, "nmap": s.cfg.NmapPath, "masscan": s.cfg.MasscanPath, "nikto": s.cfg.NiktoPath,
		"nuclei": s.cfg.NucleiPath, "testssl": s.cfg.TestsslPath, "sslyze": s.cfg.SSLyzePath, "vuls": s.cfg.VulsPath,
		"trivy": s.cfg.TrivyPath, "semgrep": s.cfg.SemgrepPath, "gitleaks": s.cfg.GitleaksPath, "osv": s.cfg.OsvPath,
		"lynis": s.cfg.SSHPath,
		// Staged web-pipeline adapters: availability is genuine binary presence.
		"katana": s.cfg.KatanaPath, "dalfox": s.cfg.DalfoxPath, "wapiti": s.cfg.WapitiPath,
		// Cloud / Kubernetes posture-audit adapters.
		"kube-bench": s.cfg.KubeBenchPath, "prowler": s.cfg.ProwlerPath, "scoutsuite": s.cfg.ScoutSuitePath,
	}
	for id, path := range paths {
		_, err := exec.LookPath(path)
		available[id] = err == nil
	}
	if scanner.MasscanCapabilityReason() != "" {
		available["masscan"] = false
	}
	// Typed assessment planning requires an explicitly dedicated managed ZAP
	// backend; a configured shared daemon is not sufficient evidence.
	available["zap"] = strings.TrimSpace(s.cfg.ZAPURL) != "" && s.cfg.ZAPDedicated && !scanner.ZAPServiceQuarantined(s.cfg.ZAPURL)
	available["openvas"] = (strings.TrimSpace(s.cfg.GVMHost) != "" || strings.TrimSpace(s.cfg.GVMSocket) != "") && s.cfg.GVMUsername != "" && s.cfg.GVMPassword != ""
	return available
}

func (s *Server) handleAssessmentPlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var cfg assessment.AssessmentConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, "invalid assessment configuration", http.StatusBadRequest)
		return
	}
	plan := s.buildAssessmentPlan(cfg)
	w.Header().Set("Content-Type", "application/json")
	status := http.StatusOK
	if len(plan.Errors) > 0 {
		status = http.StatusUnprocessableEntity
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(plan)
}

// buildAssessmentPlan builds the plan for a preview (and for saved-plan
// revalidation), where no per-scan loopback allowlist exists.
func (s *Server) buildAssessmentPlan(cfg assessment.AssessmentConfig) scanner.AssessmentPlan {
	return s.buildAssessmentPlanForScan(cfg, nil)
}

// buildAssessmentPlanForScan builds the plan with the request's per-scan
// loopback allowlist, so preview and start run the same scope guard.
func (s *Server) buildAssessmentPlanForScan(cfg assessment.AssessmentConfig, allowLoopbackPorts []int) scanner.AssessmentPlan {
	credentialAvailability := map[string]bool{}
	credentialRevisions := map[string]string{}
	if vault, err := s.openCredentialVault(); err == nil {
		for _, binding := range cfg.Access {
			if strings.TrimSpace(binding.CredentialID) == "" {
				continue
			}
			// Non-secret revision metadata: rotating a bound credential makes
			// an accepted plan stale.
			if revision, revErr := vault.RevisionOf(binding.CredentialID); revErr == nil {
				credentialRevisions[binding.CredentialID] = strconv.Itoa(revision)
			}
			for _, targetID := range binding.TargetIDs {
				key := targetID + "\x00" + string(binding.Kind) + "\x00" + binding.CredentialID
				record, lookupErr := vault.Get(binding.CredentialID, targetID)
				credentialAvailability[key] = lookupErr == nil && record.Kind == binding.Kind
				if binding.Kind == assessment.AccessSSH {
					credentialAvailability[key] = credentialAvailability[key] && assessmentSSHAliasPattern.MatchString(strings.TrimSpace(record.Values["ssh_alias"]))
				}
			}
		}
	}
	unavailableReasons := map[string]string{}
	if _, err := exec.LookPath(s.cfg.MasscanPath); err == nil {
		if reason := scanner.MasscanCapabilityReason(); reason != "" {
			unavailableReasons["masscan"] = reason
		}
	}
	plan := scanner.PlanAssessment(scanner.PlanInput{Config: cfg, Availability: s.assessmentScannerAvailability(), UnavailabilityReasons: unavailableReasons, CredentialAvailability: credentialAvailability, ToolVersions: s.toolVersions, CredentialRevisions: credentialRevisions})
	plan.Errors = append(plan.Errors, s.assessmentScopeProblems(cfg, allowLoopbackPorts)...)
	if len(plan.Errors) == 0 {
		normalized := plan.Config
		fixtureStore := apifixture.Store{Dir: filepath.Join(s.dataDir, "_api_fixtures")}
		checkFixture := func(ref, field string) {
			if ref == "" {
				return
			}
			file, err := fixtureStore.Open(ref)
			if err != nil {
				plan.Errors = append(plan.Errors, assessment.Problem{Code: "api_fixture.unavailable", Message: field + " references a fixture that is missing or unavailable", Blocking: true})
				return
			}
			_ = file.Close()
		}
		for _, input := range normalized.APIOperationInputs {
			checkFixture(input.RequestBodyRef, "API request body")
		}
		for _, approval := range normalized.WriteApprovals {
			checkFixture(approval.FixtureRef, "API write")
			checkFixture(approval.CleanupRef, "API write cleanup")
		}
		for _, expectation := range normalized.AuthorizationExpectations {
			checkFixture(expectation.ResourceFixtureRef, "API authorization expectation")
		}
		bindings := append([]assessment.APIDefinitionBinding(nil), normalized.APIDefinitions...)
		if len(bindings) == 0 && len(normalized.APIDefinitionIDs) > 0 && len(normalized.Targets) == 1 {
			for _, id := range normalized.APIDefinitionIDs {
				bindings = append(bindings, assessment.APIDefinitionBinding{TargetID: normalized.Targets[0].ID, DefinitionID: id})
			}
		}
		targetByID := make(map[string]assessment.Target, len(normalized.Targets))
		for _, target := range normalized.Targets {
			targetByID[target.ID] = target
		}
		for _, binding := range bindings {
			target := targetByID[binding.TargetID]
			definition, err := loadAPIDefinition(s.dataDir, binding.DefinitionID)
			if err == nil {
				var endpoints []scanner.APIEndpoint
				endpoints, err = scanner.ParseOpenAPI(definition, target.Value)
				if err == nil {
					operationIDs := make(map[string]bool, len(endpoints))
					for _, endpoint := range endpoints {
						operationIDs[endpoint.OperationID] = true
					}
					for _, input := range normalized.APIOperationInputs {
						if input.DefinitionID == binding.DefinitionID && !operationIDs[input.OperationID] {
							plan.Errors = append(plan.Errors, assessment.Problem{Code: "api_input.operation_unknown", Message: fmt.Sprintf("API input refers to unknown operation %q in definition %s", input.OperationID, binding.DefinitionID), Blocking: true})
						}
					}
					endpoints = scanner.MaterializeOpenAPIOperations(endpoints, binding.DefinitionID, target.Value, normalized.APIOperationInputs)
					for i := range endpoints {
						endpoints[i].TargetID = binding.TargetID
					}
					plan.APIEndpoints = append(plan.APIEndpoints, endpoints...)
				}
			}
			if err != nil {
				plan.Errors = append(plan.Errors, assessment.Problem{Code: "api_definition.unavailable", Message: "API definition " + binding.DefinitionID + " is unavailable or invalid for its mapped target: " + err.Error(), Blocking: true})
			}
		}
	}
	return plan
}

// assessmentScopeProblems runs the self-listener / local-target guard over
// every network target and every approved origin. It honours the global
// AllowLocalTargets opt-in and the per-scan loopback allowlist, and never
// exposes the dashboard listener.
func (s *Server) assessmentScopeProblems(cfg assessment.AssessmentConfig, allowLoopbackPorts []int) []assessment.Problem {
	var problems []assessment.Problem
	for _, target := range cfg.Targets {
		switch target.Kind {
		case assessment.KindDomain, assessment.KindURL, assessment.KindIP, assessment.KindCIDR, assessment.KindHost:
			if s.isBlockedTargetForScan(target.Value, allowLoopbackPorts) {
				problems = append(problems, assessment.Problem{Code: "target.scope_blocked", Message: fmt.Sprintf("assessment target %q is local, internal, or the Xalgorix listener and is outside scan policy", target.ID), Blocking: true})
			}
		}
	}
	for _, origin := range cfg.ApprovedOrigins {
		if s.isBlockedTargetForScan(origin.Origin(), allowLoopbackPorts) {
			problems = append(problems, assessment.Problem{Code: "target.scope_blocked", Message: fmt.Sprintf("approved origin %s of target %q is local, internal, or the Xalgorix listener and is outside scan policy", origin.Origin(), origin.TargetID), Blocking: true})
		}
	}
	return problems
}

func (s *Server) assessmentScannerAvailability() map[string]bool {
	available := s.scannerAvailability()
	for _, def := range scanner.ScannerRegistry() {
		if !scanner.HasAssessmentRunner(def.ID) {
			available[def.ID] = false
		}
	}
	return available
}

func (s *Server) handleScannerRegistry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	available := s.assessmentScannerAvailability()
	definitions := scanner.ScannerRegistry()
	for i := range definitions {
		if ok, exists := available[definitions[i].ID]; exists {
			definitions[i].Available = ok
		}
		if definitions[i].ID == "masscan" && !definitions[i].Available {
			definitions[i].AvailabilityReason = scanner.MasscanCapabilityReason()
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"registry_version": "1", "scanners": definitions})
}

func (s *Server) handleScannerStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	available := func(path string) bool { _, err := exec.LookPath(path); return err == nil }
	zapConfigured := strings.TrimSpace(s.cfg.ZAPURL) != ""
	zapHealthy := false
	if zapConfigured {
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get(strings.TrimRight(s.cfg.ZAPURL, "/") + "/JSON/core/view/version/?apikey=" + url.QueryEscape(s.cfg.ZAPAPIKey))
		if err == nil {
			zapHealthy = resp.StatusCode/100 == 2 && !scanner.ZAPServiceQuarantined(s.cfg.ZAPURL)
			_ = resp.Body.Close()
		}
	}
	gvmConfigured := strings.TrimSpace(s.cfg.GVMHost) != "" || strings.TrimSpace(s.cfg.GVMSocket) != ""
	gvmHealthy := false
	if strings.TrimSpace(s.cfg.GVMSocket) != "" {
		if info, err := os.Stat(s.cfg.GVMSocket); err == nil {
			gvmHealthy = info.Mode()&os.ModeSocket != 0
		}
	} else if strings.TrimSpace(s.cfg.GVMHost) != "" {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(s.cfg.GVMHost, strconv.Itoa(s.cfg.GVMPort)), 2*time.Second)
		if err == nil {
			gvmHealthy = true
			_ = conn.Close()
		}
	}
	paths := map[string]string{
		"subfinder": s.cfg.SubfinderPath, "httpx": s.cfg.HttpxPath, "nmap": s.cfg.NmapPath,
		"nuclei": s.cfg.NucleiPath, "testssl": s.cfg.TestsslPath, "vuls": s.cfg.VulsPath,
		"trivy": s.cfg.TrivyPath, "semgrep": s.cfg.SemgrepPath, "gitleaks": s.cfg.GitleaksPath, "osv": s.cfg.OsvPath,
	}
	entries := make([]map[string]any, 0, len(scanner.Catalog()))
	for _, tool := range scanner.Catalog() {
		e := map[string]any{"name": tool.Name, "phase": tool.Phase, "selectable": tool.Selectable, "summary": tool.Summary}
		switch tool.Name {
		case "zap":
			e["available"], e["endpoint_configured"] = zapHealthy, zapConfigured
		case "openvas":
			e["available"], e["endpoint_configured"] = gvmHealthy, gvmConfigured
		default:
			e["available"], e["path"] = available(paths[tool.Name]), paths[tool.Name]
		}
		entries = append(entries, e)
	}
	// The webui client parses a body as JSON only when Content-Type says so;
	// without this header Go sniffs text/plain and the UI lists no tools.
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"scanners": entries})
}

func (s *Server) handleScannerOutput(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/scans/")
	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		http.Error(w, "invalid scanner output path", http.StatusBadRequest)
		return
	}
	scanID := parts[0]
	scanDir, rec := s.findScanByID(scanID)
	if rec == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	name := ""
	stream := ""
	artifact := false
	if len(parts) >= 4 && parts[1] == "output" {
		name, stream = parts[2], parts[3]
	} else if len(parts) >= 3 && parts[len(parts)-1] == "artifact" {
		name = parts[1]
		artifact = true
	} else {
		http.Error(w, "invalid scanner output path", http.StatusBadRequest)
		return
	}
	// ?scope= picks the run on one scope (a scan has one run per tool per
	// host). Without it the first run by name is served, as before. A legacy
	// run with empty Scope, or a per-host nmap run, also matches its folded
	// report scope.
	scope := r.URL.Query().Get("scope")
	var run *scanner.Run
	for i := range rec.ScannerRuns {
		candidate := &rec.ScannerRuns[i]
		if candidate.Scanner != name {
			continue
		}
		if scope != "" && candidate.Scope != scope && scanner.FindingScope(*candidate) != scope {
			continue
		}
		run = candidate
		break
	}
	if run == nil {
		http.Error(w, "scanner run not found", http.StatusNotFound)
		return
	}
	filePath := ""
	if artifact {
		filePath = run.ArtifactPath
	} else if stream == "stdout" {
		filePath = run.StdoutPath
	} else if stream == "stderr" {
		filePath = run.StderrPath
	} else if stream == "combined" {
		filePath = run.TranscriptPath
	} else {
		http.Error(w, "stream must be stdout, stderr, or combined", http.StatusBadRequest)
		return
	}
	filePath, ok := safeScannerPath(scanDir, filePath)
	if !ok {
		http.Error(w, "output unavailable", http.StatusNotFound)
		return
	}
	info, err := os.Stat(filePath)
	if err != nil || !info.Mode().IsRegular() {
		http.Error(w, "output unavailable", http.StatusNotFound)
		return
	}
	if artifact {
		w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(filePath)+"\"")
		http.ServeFile(w, r, filePath)
		return
	}
	offset, _ := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
	limit, _ := strconv.ParseInt(r.URL.Query().Get("limit"), 10, 64)
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > 1<<20 {
		limit = 1 << 20
	}
	if rawTail := strings.TrimSpace(r.URL.Query().Get("tail")); rawTail != "" {
		tail, err := strconv.ParseInt(rawTail, 10, 64)
		if err != nil || tail <= 0 {
			tail = limit
		}
		if tail > 1<<20 {
			tail = 1 << 20
		}
		offset = info.Size() - tail
		if offset < 0 {
			offset = 0
		}
		limit = tail
	}
	f, err := os.Open(filePath)
	if err != nil {
		http.Error(w, "output unavailable", 404)
		return
	}
	defer f.Close()
	_, _ = f.Seek(offset, io.SeekStart)
	data, _ := io.ReadAll(io.LimitReader(f, limit))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Start-Offset", strconv.FormatInt(offset, 10))
	w.Header().Set("X-Next-Offset", strconv.FormatInt(offset+int64(len(data)), 10))
	w.Header().Set("X-Total-Size", strconv.FormatInt(info.Size(), 10))
	_, _ = w.Write(data)
}

// isScanScopesPath reports whether path is exactly /api/scans/{id}/scopes.
func isScanScopesPath(path string) bool {
	parts := strings.Split(strings.TrimPrefix(path, "/api/scans/"), "/")
	return len(parts) == 2 && parts[0] != "" && parts[1] == "scopes"
}

// handleScanScopes serves GET /api/scans/{id}/scopes: the scan's runs grouped
// by scope exactly as the report's Scan Coverage section groups them, plus the
// host-less recon runs. Legacy (schema < 2) scans have no scopes.
func (s *Server) handleScanScopes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/scans/"), "/scopes")
	scanDir, rec := s.findScanByID(id)
	if rec == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	resp := struct {
		Recon  []reportScopeRun `json:"recon"`
		Scopes []reportScope    `json:"scopes"`
	}{Recon: []reportScopeRun{}, Scopes: []reportScope{}}
	if rec.SchemaVersion >= scanner.SchemaVersion {
		resp.Recon = reconRuns(rec.ScannerRuns)
		if scopes := buildReportScopes(scanDir, rec.ScannerRuns); scopes != nil {
			resp.Scopes = scopes
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func safeScannerPath(scanDir, path string) (string, bool) {
	if path == "" {
		return "", false
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(scanDir, path)
	}
	abs, _ := filepath.Abs(path)
	root, _ := filepath.Abs(scanDir)
	rel, err := filepath.Rel(root, abs)
	return abs, err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func (s *Server) handleReportAction(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/reports/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 || parts[1] != "regenerate" || r.Method != http.MethodPost {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	dir, rec := s.findScanByID(parts[0])
	if rec == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	if len(rec.ScannerRuns) == 0 || rec.Status != "finished" {
		http.Error(w, "all scanner attempts must finish before report regeneration", http.StatusConflict)
		return
	}
	for _, run := range rec.ScannerRuns {
		if !run.Terminal() {
			http.Error(w, "all scanner attempts must finish before report regeneration", http.StatusConflict)
			return
		}
	}
	reportPath := s.generateScannerReport(rec, dir, rec.InstanceID)
	if reportPath == "" {
		http.Error(w, "report generation failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready", "mode": rec.ReportMode, "url": "/api/report/" + rec.ID})
}
