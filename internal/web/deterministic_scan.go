package web

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

func scannerConfig(cfg *config.Config) scanner.Config {
	return scanner.Config{
		NucleiPath: cfg.NucleiPath, TrivyPath: cfg.TrivyPath, VulsPath: cfg.VulsPath, VulsSSHConfigPath: cfg.VulsSSHConfigPath,
		ZAPURL: cfg.ZAPURL, ZAPAPIKey: cfg.ZAPAPIKey, GVMHost: cfg.GVMHost, GVMPort: cfg.GVMPort, GVMSocket: cfg.GVMSocket, GVMUser: cfg.GVMUsername, GVMPass: cfg.GVMPassword,
		RateRPS: int(cfg.RateLimitRPS), ScanHeaders: append([]string(nil), cfg.ScanHeaders...), MaxOutputBytes: cfg.ScannerMaxOutputBytes,
		NucleiTimeout: time.Duration(cfg.NucleiTimeoutSec) * time.Second, ZAPTimeout: time.Duration(cfg.ZAPTimeoutSec) * time.Second,
		OpenVASTimeout: time.Duration(cfg.OpenVASTimeoutSec) * time.Second, TrivyTimeout: time.Duration(cfg.TrivyTimeoutSec) * time.Second, VulsTimeout: time.Duration(cfg.VulsTimeoutSec) * time.Second,
	}
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

	pipeline := scanner.NewPipeline(scannerConfig(sess.cfg))
	runs := pipeline.Run(ctx, scanner.Request{Target: sess.target, Scanners: sess.scanners, ScanDir: sess.scanDir, Artifact: sess.artifact, VulsSSHHost: sess.vulsSSHHost, TargetAuth: sess.targetAuth}, sess.record.ScannerRuns, func(evt scanner.Event) {
		ws := WSEvent{Type: evt.Type, Scanner: evt.Scanner, Stream: evt.Stream, Sequence: evt.Sequence, Output: evt.Output, Content: evt.Output, Target: sess.target, AgentID: sess.id, Timestamp: time.Now().Format(time.RFC3339Nano)}
		if evt.Type != "scanner_output" {
			ws.Content = firstNonBlank(evt.Run.Reason, fmt.Sprintf("%s: %s", evt.Scanner, evt.Run.Status))
		}
		// Raw chunks are append-only files and WebSocket messages. Do not embed
		// them in scan.json; only persist the small lifecycle events.
		if evt.Type != "scanner_output" {
			sess.record.Events = append(sess.record.Events, ws)
			if len(sess.record.Events) > 200 {
				sess.record.Events = append([]WSEvent(nil), sess.record.Events[len(sess.record.Events)-200:]...)
			}
		}
		if evt.Run.Scanner != "" {
			upsertScannerRun(&sess.record.ScannerRuns, evt.Run)
		}
		sess.record.ToolCalls = countTerminalRuns(sess.record.ScannerRuns)
		if evt.Type != "scanner_output" || evt.Sequence%25 == 0 {
			s.saveScanRecordTo(sess.record, sess.scanDir)
		}
		if sess.instanceID != "" {
			s.broadcastToInstance(sess.instanceID, ws)
		} else {
			s.broadcast(ws)
		}
	})
	sess.record.ScannerRuns = runs
	sess.record.ToolCalls = countTerminalRuns(runs)
	now := time.Now().Format(time.RFC3339Nano)
	if ctx.Err() != nil {
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
		if (*runs)[i].Scanner == run.Scanner && (*runs)[i].Scope == run.Scope {
			(*runs)[i] = run
			return
		}
	}
	*runs = append(*runs, run)
}

// runDeterministicWildcard performs tool-based discovery without an LLM, then
// invokes the same five-scanner session for every normalized host in order.
func (s *Server) runDeterministicWildcard(ctx context.Context, scanCfg *config.Config, req ScanRequest, target string, idx, total int) {
	root := hostOnlyWeb(target)
	hosts := []string{root}
	dir, _ := s.scanDirForResume(req, target)
	_ = os.MkdirAll(dir, 0o700)
	discoveryPath := filepath.Join(dir, "subfinder.txt")
	if req.IsResume && req.ResumeDiscoveryDone && len(req.ResumeSubdomains) > 0 {
		hosts = append([]string(nil), req.ResumeSubdomains...)
	} else if p, err := exec.LookPath("subfinder"); err == nil && root != "" {
		cmd := exec.CommandContext(ctx, p, "-silent", "-d", root, "-o", discoveryPath)
		cmd.Dir = dir
		if output, err := cmd.CombinedOutput(); err != nil {
			s.broadcastToInstance(req.InstanceID, WSEvent{Type: "scanner_failed", Scanner: "discovery", Content: err.Error(), Output: string(output), Target: target, Timestamp: time.Now().Format(time.RFC3339Nano)})
		}
		if data, err := os.ReadFile(discoveryPath); err == nil {
			hosts = append(hosts, strings.Fields(string(data))...)
		}
	}
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
		sess := &scanSession{id: filepath.Base(subDir), target: h, parentTarget: target, scanDir: subDir, cfg: scanCfg, server: s, name: req.Name, userInstruction: "", genReport: true, resetState: !resumed, instanceID: req.InstanceID, scanMode: "wildcard", scanners: req.Scanners, severityFilter: req.SeverityFilter, companyName: req.CompanyName, logoPath: req.LogoPath, targetAuth: req.TargetAuth, ctx: ctx, artifact: req.Artifact, vulsSSHHost: req.VulsSSHHost}
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
