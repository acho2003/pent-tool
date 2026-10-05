package web

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
	"github.com/xalgord/xalgorix/v4/internal/storage"
)

// ScannerConfig maps operator config into the scanner pipeline config. It stays
// a package-level function (no live ScopeGuard) for CLI callers that have no
// dashboard listener identity; the server wraps it via (*Server).ScannerConfig
// to add the execution-time scope guard.
func ScannerConfig(cfg *config.Config) scanner.Config {
	return scanner.Config{
		NucleiPath: cfg.NucleiPath, NucleiTemplatesDir: cfg.NucleiTemplatesDir, TrivyPath: cfg.TrivyPath, VulsPath: cfg.VulsPath, VulsSSHConfigPath: cfg.VulsSSHConfigPath,
		SubfinderPath: cfg.SubfinderPath, AmassPath: cfg.AmassPath, DNSXPath: cfg.DNSXPath, GauPath: cfg.GauPath, WaybackurlsPath: cfg.WaybackurlsPath, SSLyzePath: cfg.SSLyzePath, HttpxPath: cfg.HttpxPath, NmapPath: cfg.NmapPath, MasscanPath: cfg.MasscanPath, NiktoPath: cfg.NiktoPath, KatanaPath: cfg.KatanaPath, KatanaChromePath: cfg.BrowserPath, DalfoxPath: cfg.DalfoxPath, WapitiPath: cfg.WapitiPath, KubeBenchPath: cfg.KubeBenchPath, ProwlerPath: cfg.ProwlerPath, ScoutSuitePath: cfg.ScoutSuitePath, SSHPath: cfg.SSHPath, TestsslPath: cfg.TestsslPath,
		SemgrepPath: cfg.SemgrepPath, GitleaksPath: cfg.GitleaksPath, OsvPath: cfg.OsvPath,
		ZAPURL: cfg.ZAPURL, ZAPAPIKey: cfg.ZAPAPIKey, ZAPDedicated: cfg.ZAPDedicated, GVMHost: cfg.GVMHost, GVMPort: cfg.GVMPort, GVMSocket: cfg.GVMSocket, GVMUser: cfg.GVMUsername, GVMPass: cfg.GVMPassword,
		RateRPS: int(cfg.RateLimitRPS), MaxWorkers: cfg.MaxWorkers, ScanHeaders: append([]string(nil), cfg.ScanHeaders...), MaxOutputBytes: cfg.ScannerMaxOutputBytes,
		MasscanRate: cfg.MasscanRate, MasscanTimeout: time.Duration(cfg.MasscanTimeoutSec) * time.Second,
		NiktoTimeout:  time.Duration(cfg.NiktoTimeoutSec) * time.Second,
		NucleiTimeout: time.Duration(cfg.NucleiTimeoutSec) * time.Second, ZAPTimeout: time.Duration(cfg.ZAPTimeoutSec) * time.Second,
		OpenVASTimeout: time.Duration(cfg.OpenVASTimeoutSec) * time.Second, TrivyTimeout: time.Duration(cfg.TrivyTimeoutSec) * time.Second, VulsTimeout: time.Duration(cfg.VulsTimeoutSec) * time.Second,
		SubfinderTimeout: time.Duration(cfg.SubfinderTimeoutSec) * time.Second,
		AmassTimeout:     time.Duration(cfg.AmassTimeoutSec) * time.Second, DNSXTimeout: time.Duration(cfg.DNSXTimeoutSec) * time.Second, GauTimeout: time.Duration(cfg.GauTimeoutSec) * time.Second, WaybackurlsTimeout: time.Duration(cfg.WaybackurlsTimeoutSec) * time.Second, SSLyzeTimeout: time.Duration(cfg.SSLyzeTimeoutSec) * time.Second,
		HttpxTimeout:    time.Duration(cfg.HttpxTimeoutSec) * time.Second,
		NmapTimeout:     time.Duration(cfg.NmapTimeoutSec) * time.Second,
		TestsslTimeout:  time.Duration(cfg.TestsslTimeoutSec) * time.Second,
		SemgrepTimeout:  time.Duration(cfg.SemgrepTimeoutSec) * time.Second,
		GitleaksTimeout: time.Duration(cfg.GitleaksTimeoutSec) * time.Second,
		OsvTimeout:      time.Duration(cfg.OsvTimeoutSec) * time.Second,
	}
}

// ScannerConfig returns the pipeline config with an execution-time scope guard
// wired in (DNS-rebinding defence). The planner/preview checks hosts up front,
// but DNS can change between preview and execution, so the guard re-runs the
// self-listener/local-target check on both the raw URL and the addresses the
// host actually resolved to. Legacy scans carry no per-scan loopback allowlist,
// so pass nil (strict default: all loopback is self).
func (s *Server) ScannerConfig(cfg *config.Config) scanner.Config {
	sc := ScannerConfig(cfg)
	sc.APIFixtureDir = filepath.Join(s.dataDir, "_api_fixtures")
	sc.ScopeGuard = func(rawURL string, resolved []string) (bool, string) {
		if s.isBlockedTargetForScan(rawURL, nil) {
			return true, "scope guard: target is the scanner host or dashboard listener"
		}
		for _, addr := range resolved {
			addr = strings.TrimSpace(addr)
			if addr == "" {
				continue
			}
			if s.isBlockedTargetForScan(addr, nil) {
				return true, "scope guard: resolved address " + addr + " is the scanner host or dashboard listener"
			}
		}
		return false, ""
	}
	return sc
}

func (s *Server) executeDeterministicScanSession(sess *scanSession) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[scanner] session %s panic: %v", sess.id, r)
		}
	}()
	ctx := sess.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	sess.record = s.scanRecordForSession(sess)
	sess.record.SchemaVersion = scanner.SchemaVersion
	sess.record.Status = "running"
	sess.record.Vulns = nil
	s.saveScanRecordTo(sess.record, sess.scanDir)

	s.mu.Lock()
	s.currentScanDir, s.currentScanID = sess.scanDir, sess.id
	s.mu.Unlock()
	if sess.instanceID != "" {
		s.instancesMu.RLock()
		inst := s.instances[sess.instanceID]
		s.instancesMu.RUnlock()
		if inst != nil {
			inst.mu.Lock()
			inst.scanDir = sess.scanDir
			inst.ScannerRuns = append([]scanner.Run(nil), sess.record.ScannerRuns...)
			inst.Artifact = sess.artifact
			inst.VulsSSHHost = sess.vulsSSHHost
			inst.mu.Unlock()
		}
	}

	pipeline := scanner.NewPipeline(s.ScannerConfig(sess.cfg))
	pipeline.AttemptControl = func(attemptID string, cancel context.CancelFunc) func() {
		s.scannerControlMu.Lock()
		if s.scannerCancels == nil {
			s.scannerCancels = make(map[string]context.CancelFunc)
		}
		s.scannerCancels[attemptID] = cancel
		s.scannerControlMu.Unlock()
		return func() {
			s.scannerControlMu.Lock()
			delete(s.scannerCancels, attemptID)
			s.scannerControlMu.Unlock()
		}
	}
	var lastActivitySave atomic.Int64
	emit := func(evt scanner.Event) {
		ws := WSEvent{Type: evt.Type, Scanner: evt.Scanner, Stream: evt.Stream, Sequence: evt.Sequence, Output: evt.Output, Content: evt.Output, Target: sess.target, AgentID: sess.id, Timestamp: time.Now().Format(time.RFC3339Nano)}
		if evt.Type == "scanner_progress" {
			ws.Content = fmt.Sprintf("%s %s: %d%%", evt.Scanner, firstNonBlank(evt.Run.ProgressStage, "progress"), evt.Run.Progress)
		} else if evt.Type != "scanner_output" {
			ws.Content = firstNonBlank(evt.Run.Reason, fmt.Sprintf("%s: %s", evt.Scanner, evt.Run.Status))
		}
		// Raw chunks are append-only files and WebSocket messages. Do not embed
		// them in scan.json; only persist the small lifecycle events. Progress
		// updates live on the run itself, not in the capped event history.
		if evt.Type != "scanner_output" && evt.Type != "scanner_progress" {
			sess.record.Events = append(sess.record.Events, ws)
			if len(sess.record.Events) > 200 {
				sess.record.Events = append([]WSEvent(nil), sess.record.Events[len(sess.record.Events)-200:]...)
			}
		}
		if evt.Type == "scanner_started" || evt.Type == "scanner_output" || evt.Type == "scanner_progress" {
			for i := range sess.record.ScannerRuns {
				run := &sess.record.ScannerRuns[i]
				if run.Scanner == evt.Scanner && run.Status == "running" && (evt.Run.AttemptID == "" || run.AttemptID == evt.Run.AttemptID) {
					run.LastActivityAt = ws.Timestamp
				}
			}
			if evt.Run.Scanner != "" {
				evt.Run.LastActivityAt = ws.Timestamp
			}
		}
		if evt.Run.Scanner != "" {
			upsertScannerRun(&sess.record.ScannerRuns, evt.Run)
		}
		sess.record.ToolCalls = countTerminalRuns(sess.record.ScannerRuns)
		nowUnix := time.Now().Unix()
		previousSave := lastActivitySave.Load()
		persistActivity := evt.Type == "scanner_output" && nowUnix-previousSave >= 5 && lastActivitySave.CompareAndSwap(previousSave, nowUnix)
		if evt.Type != "scanner_output" || evt.Sequence%25 == 0 || persistActivity {
			s.saveScanRecordTo(sess.record, sess.scanDir)
		}
		if sess.instanceID != "" {
			s.broadcastToInstance(sess.instanceID, ws)
		} else {
			s.broadcast(ws)
		}
	}
	var runs []scanner.Run
	if sess.assessmentPlan != nil {
		if len(sess.assessmentPlan.Errors) > 0 {
			runs = make([]scanner.Run, 0, len(sess.assessmentPlan.Jobs))
			for _, job := range sess.assessmentPlan.Jobs {
				run := scanner.Run{Scanner: job.Scanner, Variant: job.Variant, Scope: "assessment:" + job.TargetID, Target: job.Target, Status: "failed", Reason: "assessment plan became stale or invalid before execution", PlanFingerprint: sess.planFingerprint, AssessmentTypes: job.AssessmentTypes, StartedAt: time.Now().Format(time.RFC3339Nano), FinishedAt: time.Now().Format(time.RFC3339Nano)}
				runs = append(runs, run)
				emit(scanner.Event{Type: "scanner_failed", Scanner: run.Scanner, Run: run, Output: run.Reason})
			}
			sess.record.Status = "failed"
			sess.record.StopReason = "assessment plan became stale or invalid before execution"
		} else {
			authHeaders, authErr := s.prepareAssessmentAuthentication(ctx, sess.assessmentPlan)
			if authErr != nil {
				sess.record.Status = "failed"
				sess.record.StopReason = "assessment authentication preparation failed"
				runs = nil
			} else {
				pipeline.Config.AssessmentAuthHeaders = authHeaders
				sshAliases, sshErr := s.assessmentHostAliases(sess.assessmentPlan)
				gvmCredentials, sshRequested := s.assessmentGVMSSHCredentials(sess.assessmentPlan)
				refreshers, refreshErr := s.assessmentAuthRefreshers(sess.assessmentPlan, authHeaders)
				if sshErr != nil {
					sess.record.Status = "failed"
					sess.record.StopReason = sshErr.Error()
				} else if refreshErr != nil {
					sess.record.Status = "failed"
					sess.record.StopReason = refreshErr.Error()
				} else {
					pipeline.Config.AssessmentAuthRefresh = refreshers
					pipeline.Config.AssessmentSSHAliases = sshAliases
					pipeline.Config.AssessmentGVMSSH = gvmCredentials
					pipeline.Config.AssessmentSSHRequested = sshRequested
					pipeline.Config.AssessmentCloudCreds = s.assessmentCloudCredentials(sess.assessmentPlan)
					pipeline.Config.AssessmentRepoCreds = s.assessmentRepositoryCredentials(sess.assessmentPlan)
				}
				sess.record.AssessmentPlan = sess.assessmentPlan
				if refreshErr == nil && sshErr == nil {
					runs = pipeline.RunAssessmentJobs(ctx, *sess.assessmentPlan, sess.scanDir, sess.record.ScannerRuns, emit)
				}
			}
		}
	} else {
		runs = pipeline.Run(ctx, scanner.Request{Target: sess.target, Scanners: sess.scanners, ScanDir: sess.scanDir, Artifact: sess.artifact, VulsSSHHost: sess.vulsSSHHost, TargetAuth: sess.targetAuth, Profile: sess.profile, ApplicationURL: sess.target}, sess.record.ScannerRuns, emit)
	}
	for i := range runs {
		for _, saved := range sess.record.ScannerRuns {
			if runs[i].Scanner == saved.Scanner && runs[i].Scope == saved.Scope && runs[i].AttemptID == saved.AttemptID {
				runs[i].LastActivityAt = saved.LastActivityAt
				break
			}
		}
	}
	sess.record.ScannerRuns = runs
	sess.record.ToolCalls = countTerminalRuns(runs)
	now := time.Now().Format(time.RFC3339Nano)
	if sess.record.Status == "failed" {
		// Preserve a failed preflight outcome. A stale/invalid assessment plan
		// must never be relabeled as a successful empty scan.
	} else if ctx.Err() != nil {
		sess.record.Status = "stopped"
		sess.record.StopReason = ctx.Err().Error()
	} else {
		sess.record.Status = "finished"
	}
	sess.record.FinishedAt = now
	s.saveScanRecordTo(sess.record, sess.scanDir)
	if sess.instanceID != "" {
		s.instancesMu.RLock()
		inst := s.instances[sess.instanceID]
		s.instancesMu.RUnlock()
		if inst != nil {
			inst.mu.Lock()
			inst.ScannerRuns = append([]scanner.Run(nil), runs...)
			inst.ToolCalls = len(runs)
			inst.TotalTokens = 0
			inst.VulnCount = 0
			inst.Vulns = nil
			if sess.record.Status == "failed" {
				inst.Status = "failed"
				inst.StopReason = sess.record.StopReason
			}
			inst.mu.Unlock()
		}
	}
	if sess.genReport {
		s.generateScannerReport(sess.record, sess.scanDir, sess.instanceID)
	}
}

func firstNonBlank(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
func countTerminalRuns(runs []scanner.Run) int {
	n := 0
	for _, r := range runs {
		if r.Terminal() {
			n++
		}
	}
	return n
}
func upsertScannerRun(runs *[]scanner.Run, run scanner.Run) {
	for i := range *runs {
		// Match on both Scope and Scanner: Increment 2 introduced duplicate scanner
		// names across scopes (per-host nuclei/zap/... and per-host recon nmap), so
		// keying on Scanner alone would let one host's run overwrite another's in
		// the crash-persisted record used for resume.
		if (*runs)[i].Scanner == run.Scanner && (*runs)[i].Scope == run.Scope && (*runs)[i].Variant == run.Variant {
			if run.LastActivityAt == "" {
				run.LastActivityAt = (*runs)[i].LastActivityAt
			}
			(*runs)[i] = run
			return
		}
	}
	*runs = append(*runs, run)
}

// Wildcard candidate provenance/labels. Discovered hosts are candidates, not
// authorized targets: the typed path never fans out to them, and the operator
// must re-preview and accept them before they become scope (UI in I4.T5).
const (
	wildcardCandidateProvenance = "subfinder" // discovery source for fanned-out hosts
	wildcardCandidateLabel      = "legacy wildcard candidate"
	wildcardRootProvenance      = "requested" // the originally-requested root host
)

// wildcardCandidate records a host surfaced by a legacy wildcard scan, so the
// operator can review discovered hosts without them silently becoming scope.
type wildcardCandidate struct {
	Host       string `json:"host"`
	Provenance string `json:"provenance"`
	Label      string `json:"label"`
	Root       bool   `json:"root,omitempty"` // true for the originally-requested root host
}

// subfinderCommand builds the passive subdomain-discovery command. It runs the
// operator-configured subfinder binary (so runtime pins apply) rather than a
// bare PATH lookup, and passes -duc so subfinder's own auto-update stays
// disabled during a scan (spec 5).
func subfinderCommand(ctx context.Context, subfinderPath, root, outputPath, dir string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, subfinderPath, "-silent", "-duc", "-d", root, "-o", outputPath)
	cmd.Dir = dir
	return cmd
}

// normalizeWildcardHosts lowercases, trims, dedupes and sorts hosts.
func normalizeWildcardHosts(hosts []string) []string {
	seen := map[string]bool{}
	var normalized []string
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" && !seen[h] {
			seen[h] = true
			normalized = append(normalized, h)
		}
	}
	sort.Strings(normalized)
	return normalized
}

// discoverWildcardHosts returns the normalized host list for a legacy wildcard
// scan. On resume it reuses the persisted subdomains verbatim (never re-running
// discovery); otherwise it runs the configured subfinder and merges its output
// with the root host.
func (s *Server) discoverWildcardHosts(ctx context.Context, scanCfg *config.Config, req ScanRequest, root, dir string) []string {
	hosts := []string{root}
	if req.IsResume && req.ResumeDiscoveryDone && len(req.ResumeSubdomains) > 0 {
		hosts = append([]string(nil), req.ResumeSubdomains...)
	} else if scanCfg.SubfinderPath != "" && root != "" {
		discoveryPath := filepath.Join(dir, "subfinder.txt")
		cmd := subfinderCommand(ctx, scanCfg.SubfinderPath, root, discoveryPath, dir)
		if output, err := cmd.CombinedOutput(); err != nil {
			s.broadcastToInstance(req.InstanceID, WSEvent{Type: "scanner_failed", Scanner: "discovery", Content: err.Error(), Output: string(output), Target: root, Timestamp: time.Now().Format(time.RFC3339Nano)})
		}
		if data, err := os.ReadFile(discoveryPath); err == nil {
			hosts = append(hosts, strings.Fields(string(data))...)
		}
	}
	return normalizeWildcardHosts(hosts)
}

// wildcardCandidates builds candidate records for the normalized host list. The
// root host is marked as requested; every other host is a subfinder-provenance
// candidate labelled "legacy wildcard candidate".
func wildcardCandidates(root string, normalized []string) []wildcardCandidate {
	rootHost := strings.ToLower(strings.TrimSpace(root))
	candidates := make([]wildcardCandidate, 0, len(normalized))
	for _, h := range normalized {
		c := wildcardCandidate{Host: h, Provenance: wildcardCandidateProvenance, Label: wildcardCandidateLabel}
		if h == rootHost {
			c.Provenance = wildcardRootProvenance
			c.Root = true
		}
		candidates = append(candidates, c)
	}
	return candidates
}

// writeWildcardCandidates persists the candidate host list beside the scan so a
// later re-preview (I4.T5) can offer them for acceptance.
func writeWildcardCandidates(dir, root string, normalized []string) error {
	data, err := json.MarshalIndent(wildcardCandidates(root, normalized), "", "  ")
	if err != nil {
		return err
	}
	return storage.WriteAtomic(filepath.Join(dir, "candidates.json"), data)
}

// newWildcardSubdomainSession builds the per-host scan session for a legacy
// wildcard fan-out. Credentials are deliberately NOT forwarded: discovered hosts
// are candidates, and the spec forbids sending credentials to discovered sibling
// hosts, so every wildcard session is credential-free.
func (s *Server) newWildcardSubdomainSession(ctx context.Context, scanCfg *config.Config, req ScanRequest, parentTarget, host, subDir string, resumed bool) *scanSession {
	return &scanSession{id: filepath.Base(subDir), target: host, parentTarget: parentTarget, scanDir: subDir, cfg: scanCfg, server: s, name: req.Name, userInstruction: "", genReport: true, resetState: !resumed, instanceID: req.InstanceID, scanMode: "wildcard", scanners: req.Scanners, severityFilter: req.SeverityFilter, companyName: req.CompanyName, logoPath: req.LogoPath, ctx: ctx, artifact: req.Artifact, vulsSSHHost: req.VulsSSHHost, assessment: req.Assessment, profile: req.Profile}
}

// runDeterministicWildcard performs tool-based discovery without an LLM, records
// the discovered hosts as candidates, then invokes the same five-scanner session
// for every normalized host in order. This is the explicitly-requested legacy
// wildcard path (scan_mode=wildcard); the typed assessment path never fans out.
func (s *Server) runDeterministicWildcard(ctx context.Context, scanCfg *config.Config, req ScanRequest, target string, idx, total int) {
	root := hostOnlyWeb(target)
	dir, _ := s.scanDirForResume(req, target)
	_ = os.MkdirAll(dir, 0o700)
	normalized := s.discoverWildcardHosts(ctx, scanCfg, req, root, dir)
	// Record discovered hosts as candidates (not authorized targets) with their
	// discovery provenance, so a later re-preview can offer them for acceptance.
	if err := writeWildcardCandidates(dir, root, normalized); err != nil {
		log.Printf("[scanner] wildcard candidate record failed: %v", err)
	}
	startIndex := 0
	if req.IsResume && req.ResumeDiscoveryDone {
		startIndex = clampInt(req.ResumeSubIndex, 0, len(normalized))
	}
	s.saveQueueState(idx, req, queueProgress{ActiveTarget: target, ActiveScanDir: dir, ActiveScanID: filepath.Base(dir), WildcardDiscoveryDone: true, WildcardSubdomains: append([]string(nil), normalized...), WildcardSubIndex: startIndex})
	for subIdx := startIndex; subIdx < len(normalized); subIdx++ {
		h := normalized[subIdx]
		if ctx.Err() != nil {
			return
		}
		subDir, resumed := s.scanDirForWildcardSubdomainResume(req, h, subIdx)
		s.saveQueueState(idx, req, queueProgress{ActiveTarget: target, ActiveScanDir: dir, ActiveScanID: filepath.Base(dir), WildcardDiscoveryDone: true, WildcardSubdomains: append([]string(nil), normalized...), WildcardSubIndex: subIdx, WildcardActiveTarget: h, WildcardActiveScanDir: subDir, WildcardActiveScanID: filepath.Base(subDir)})
		sess := s.newWildcardSubdomainSession(ctx, scanCfg, req, target, h, subDir, resumed)
		s.broadcastToInstance(req.InstanceID, WSEvent{Type: "target_started", Content: fmt.Sprintf("Scanning wildcard target %d/%d: %s", subIdx+1, len(normalized), h), Target: h, ParentTarget: target, SubTargetIndex: subIdx + 1, SubTargetTotal: len(normalized)})
		s.executeScanSession(sess)
		s.saveQueueState(idx, req, queueProgress{ActiveTarget: target, ActiveScanDir: dir, ActiveScanID: filepath.Base(dir), WildcardDiscoveryDone: true, WildcardSubdomains: append([]string(nil), normalized...), WildcardSubIndex: subIdx + 1})
	}
}
func hostOnlyWeb(t string) string {
	t = strings.TrimSpace(t)
	t = strings.TrimPrefix(strings.TrimPrefix(t, "https://"), "http://")
	if i := strings.IndexAny(t, "/:?"); i >= 0 {
		t = t[:i]
	}
	return strings.TrimPrefix(t, "*.")
}
