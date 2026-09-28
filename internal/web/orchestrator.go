package web

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/resources"
	"github.com/xalgord/xalgorix/v4/internal/safe"
)

// ────────────────────────────────────────────────────────

// runMultiScan processes targets sequentially, one at a time.
// Each target is scanned in a fully isolated scanSession.
func (s *Server) runMultiScan(req ScanRequest, scanCfg *config.Config, instanceIDs ...string) {
	normalizeScanRequestActivity(&req)

	// Defensively flatten req.Targets in case the frontend or API sent them as a comma-separated mega string
	var cleanTargets []string
	for _, raw := range req.Targets {
		fields := strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == ' ' || r == ';' || r == '\n' || r == '\r' || r == '\t'
		})
		for _, f := range fields {
			if f != "" {
				cleanTargets = append(cleanTargets, f)
			}
		}
	}

	// Filter out local/internal targets to prevent self-scanning. A
	// "provision" code scan opts a specific loopback port into scope
	// (req.allowLoopbackPorts); isBlockedTargetForScan honors that allowlist
	// so the deliberately-provisioned 127.0.0.1:<port> target survives the
	// filter. For all other scans allowLoopbackPorts is empty and this is
	// identical to isBlockedTarget.
	var safeTargets []string
	for _, t := range cleanTargets {
		if s.isBlockedTargetForScan(t, req.allowLoopbackPorts) {
			log.Printf("[BLOCKLIST] Skipping blocked target: %s (local/internal IP or self-listener)", t)
		} else {
			safeTargets = append(safeTargets, t)
		}
	}
	if len(safeTargets) < len(cleanTargets) {
		log.Printf("[BLOCKLIST] Filtered %d blocked targets, %d remaining", len(cleanTargets)-len(safeTargets), len(safeTargets))
	}
	req.Targets = safeTargets

	// Create instance ID immediately
	var instanceID string
	if len(instanceIDs) > 0 && instanceIDs[0] != "" {
		instanceID = instanceIDs[0]
	} else {
		instanceID = randomSlug()
	}

	// Register instance as pending initially
	instance := &ScanInstance{
		Assessment:          req.Assessment,
		Profile:             req.Profile,
		ID:                  instanceID,
		Name:                req.Name,
		Targets:             strings.Join(req.Targets, ", "),
		Status:              "pending",
		StartedAt:           time.Now().Format(time.RFC3339Nano),
		ScanMode:            req.ScanMode,
		Instruction:         req.Instruction,
		SeverityFilter:      req.SeverityFilter,
		Scanners:            append([]string(nil), req.Scanners...),
		Phases:              req.Phases,
		ReconMode:           req.ReconMode,
		ScanIntensity:       req.ScanIntensity,
		CurrentPhase:        firstSelectedPhase(req.Phases),
		CompanyName:         req.CompanyName,
		LogoPath:            req.LogoPath,
		DiscordWebhook:      req.DiscordWebhook,
		TargetAuth:          req.TargetAuth,
		TargetAuthSecondary: req.TargetAuthSecondary,
		SourceRepo:          req.SourceRepo,
		ScanContext:         req.ScanContext,
		Artifact:            req.Artifact,
		VulsSSHHost:         req.VulsSSHHost,
	}
	s.seedResumeInstanceFromRecord(instance, req)
	s.instancesMu.Lock()
	s.instances[instanceID] = instance
	s.instancesMu.Unlock()

	// Persist the queue state immediately, BEFORE the admission wait loop.
	// Previously the first saveQueueState ran only after admission (well past
	// the wait loop), so an instance parked at "pending" left ZERO disk trace.
	// On server restart both rebuildInstancesFromDisk (scan.json) and the
	// auto-resume goroutine (queue_state_*.json) found nothing → pending scans
	// were silently dropped instead of re-queued. Writing it here at CurrentIdx=0
	// means the existing auto-resume path (scanRequestFromQueueState →
	// runMultiScan) re-enters the admission loop after a restart. Thread the
	// instance ID onto the request now so the file lands at the right path.
	req.InstanceID = instanceID
	s.saveQueueState(0, req)

	// Broadcast to dashboard
	s.broadcastDashboard(WSEvent{Type: "instance_started", Content: instanceID})

	// Register cleanup before the queue wait loop so pending instances that
	// are stopped early still release server-side references.
	ranScan := false
	panicRecovered := false
	defer func() {
		if r := recover(); r != nil {
			panicRecovered = true
			log.Printf("[CRITICAL] runMultiScan goroutine panicked: %v\n%s", r, debug.Stack())
			s.broadcastToInstance(instanceID, WSEvent{Type: "error", Content: fmt.Sprintf("⛔ Scan goroutine crashed: %v — cleaning up", r)})
		}

		// Mark instance as finished (if still running)
		instance.mu.Lock()
		if instance.Status == "running" {
			if panicRecovered {
				instance.Status = "stopped"
				instance.StopReason = "panic_recovered"
			} else {
				instance.Status = "finished"
			}
		}
		instance.FinishedAt = time.Now().Format(time.RFC3339)
		instance.cancel = nil
		instance.sctx = nil
		instance.mu.Unlock()

		// Full post-scan cleanup only when the scan actually ran.
		// Pending→stopped instances skip queue/agent teardown since
		// they never acquired resources.
		if ranScan {
			// Only clear queue state when the scan really finished. Paused,
			// panicked, and signal-stopped scans keep it for resume.
			preserveQueue := false
			instance.mu.RLock()
			preserveQueue = shouldPreserveQueueStateOnExit(instance.Status, instance.StopReason, panicRecovered)
			instance.mu.RUnlock()
			if !preserveQueue {
				s.clearQueueState(instanceID)
			} else {
				log.Printf("[AUTO-RESUME] Preserving queue state after interrupted scan")
			}
		} else {
			// The instance exited pending WITHOUT ever running. A queue_state
			// file was written at creation so the scan could survive a restart;
			// decide its fate here.
			//   - server_shutdown: preserve → the auto-resume goroutine re-queues
			//     it after restart (the whole point of persisting pending scans).
			//   - user_stopped / any other reason: clear → a canceled scan must
			//     NOT be resurrected on the next boot.
			instance.mu.RLock()
			reason := instance.StopReason
			instance.mu.RUnlock()
			if reason == "server_shutdown" {
				log.Printf("[AUTO-RESUME] Preserving pending queue state (server_shutdown) for %s", instanceID)
			} else {
				s.clearQueueState(instanceID)
			}
		}

		// Always clean up server references (safe even if never set)
		s.mu.Lock()
		if s.currentScanID == instanceID {
			s.cancelScan = nil
		}
		s.mu.Unlock()

		instance.mu.RLock()
		finalStatus := instance.Status
		finalStopReason := instance.StopReason
		instance.mu.RUnlock()
		if finalStatus == "paused" {
			s.markQueueStatePaused(instanceID)
		}
		queueDoneEvt := WSEvent{Type: "queue_finished", Content: "Scan queue ended"}
		switch finalStatus {
		case "paused":
			queueDoneEvt = WSEvent{Type: "paused", Content: "Scan queue paused"}
		case "stopped":
			if strings.HasPrefix(finalStopReason, "signal_") || finalStopReason == "panic_recovered" {
				queueDoneEvt = WSEvent{Type: "stopped", Content: "Scan queue interrupted; resume state saved"}
			} else {
				queueDoneEvt = WSEvent{Type: "stopped", Content: "Scan queue stopped"}
			}
		default:
			if phaseAllowed(req.Phases, 22) {
				queueDoneEvt.CurrentPhase = 22
			}
		}
		s.broadcastToInstance(instanceID, queueDoneEvt)
		s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})
		time.Sleep(500 * time.Millisecond)

		// Only set running=false if no other instances are running
		s.instancesMu.RLock()
		stillRunning := false
		for _, inst := range s.instances {
			inst.mu.RLock()
			isRunning := inst.Status == "running" && inst.ID != instanceID
			inst.mu.RUnlock()
			if isRunning {
				stillRunning = true
				break
			}
		}
		s.instancesMu.RUnlock()
		if !stillRunning {
			s.running.Store(false)
		}
		// Wake exactly one admission waiter (if any) now that this
		// instance has finished and a slot is free. Non-blocking send:
		// the channel is buffered to len=1 so a single pending wake is
		// always queued; additional terminate signals while a wake is
		// already pending are intentionally collapsed (the recipient
		// will re-check via runningCount and either admit or wait
		// again on the safety-net ticker). This wake fires regardless
		// of whether the scan finished, errored, was stopped, or
		// panicked, because it lives in the unconditional defer.
		// (Task 11.2 / R3.2, R3.6 / Property 5.)
		select {
		case s.admissionWake <- struct{}{}:
		default:
		}
		log.Printf("[INFO] runMultiScan instance %s exited (ranScan=%v)", instanceID, ranScan)
	}()

	// Wait in queue until slot is available.
	// CRITICAL: The slot check + status transition MUST be atomic under a single
	// Lock to prevent a TOCTOU race where two goroutines both see runningCount=0
	// and start simultaneously, causing mutual process kills.
	//
	// Wakeup model (Task 11.2 / R3.2, R3.6): instead of busy-sleeping for 2s
	// between admission attempts, we park on a select that wakes when
	// (a) another instance terminates and signals s.admissionWake (fair
	// wakeup — exactly one waiter per terminate), (b) the 2s ticker fires
	// as a safety-net, or (c) the server is shutting down. The top of the
	// loop re-checks per-instance and global stop flags after every wake.
	admissionTicker := time.NewTicker(2 * time.Second)
	defer admissionTicker.Stop()
	for {
		// Check if THIS instance was stopped (via per-instance stop API,
		// Stop All, pause, or delete — all of which flip instance.Status).
		// We intentionally do NOT check the global stopReq here: it is a
		// shared flag whose lifetime is decoupled from this scan (it stays
		// true after a Stop All / SIGTERM until some other scan clears it).
		// Checking it here caused pending scans to mark themselves
		// "user_stopped" with no user action against THIS scan (the
		// stopReq.Store(false) clear-at-start hack was a workaround that in
		// turn broke Stop All). The per-instance status is the authoritative
		// signal: every stop path sets it, and we observe it on every wake.
		instance.mu.RLock()
		stopped := instance.Status == "stopped"
		instance.mu.RUnlock()
		if stopped {
			// Early return — defer is already registered and will clean up
			return
		}

		// ATOMIC: Check resource availability AND transition to running under a single lock.
		// This eliminates the TOCTOU race window between resource check and status update.
		gotSlot := false
		s.instancesMu.Lock()
		runningCount := 0
		for _, inst := range s.instances {
			inst.mu.RLock()
			if inst.Status == "running" {
				runningCount++
			}
			inst.mu.RUnlock()
		}
		canAdmit, reason := resources.CanAdmitScan(runningCount)
		if canAdmit && instance.Status == "pending" {
			instance.Status = "running"
			instance.StartedAt = time.Now().Format(time.RFC3339)
			gotSlot = true
			log.Printf("[ADMIT] Scan %s started (running: %d) — %s", instanceID, runningCount+1, reason)
		}
		s.instancesMu.Unlock()

		if gotSlot {
			break
		}
		// Admission refused — record the event and emit a structured INFO log.
		// Each refusal observation is a distinct event; ticker cadence keeps
		// counter growth proportional to wait time, while admissionWake
		// signals collapse multiple near-simultaneous terminates into a
		// single fair wakeup for the next waiter.
		safe.IncAdmissionRefusal()
		ceiling, _ := resources.EffectiveMaxInstances()
		level, _ := resources.CurrentLevel()
		log.Printf("[admission] refused level=%s reason=%q ceiling=%d running=%d scan=%s",
			level.String(), reason, ceiling, runningCount, instanceID)

		// Park on the wake channel, the safety-net ticker, or shutdown.
		select {
		case <-s.admissionWake:
			// A peer instance freed a slot — re-check immediately.
		case <-admissionTicker.C:
			// Periodic safety-net wake; prevents indefinite waits if a
			// signal is ever missed (e.g. concurrent terminates collapse
			// onto a single buffered slot).
		case <-s.shutdownChan:
			// Server is shutting down. Mark this pending instance stopped
			// and exit; the defer will run the rest of cleanup.
			instance.mu.Lock()
			if instance.Status == "pending" {
				instance.Status = "stopped"
				instance.StopReason = "server_shutdown"
				instance.FinishedAt = time.Now().Format(time.RFC3339)
			}
			instance.mu.Unlock()
			return
		}
	}

	// Instance got a slot — mark that the scan ran for full cleanup
	ranScan = true

	s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})

	// ── PRE-SESSION CLEANUP ──
	// IMPORTANT: This runs AFTER the queue wait. Do not clear the queue file
	// before the refreshed state is written; resumed scans rely on it if the
	// process exits during admission/startup.
	req.InstanceID = instanceID // (re)thread instance ID; also set before the admission wait
	s.running.Store(true)
	if req.DiscordWebhook != "" {
		s.discordWebhook = req.DiscordWebhook
	}

	if req.IsResume {
		log.Printf("[AUTO-RESUME] Skipping state reset — preserving vulns, notes, and recon files from previous session")
		// NOTE: Do NOT call terminal.KillAllProcesses() here — it kills ALL
		// processes globally, which would destroy a running instance's tools.
		// Per-context cleanup handles process termination on session boundaries.
	} else {
		// Fresh scan — only clean per-instance state, NOT global state.
		// Global resets (reporting.ResetVulnerabilities, notes.ResetNotes,
		// terminal.KillAllProcesses) would destroy another queued instance's
		// methodology workflow. Per-context resets happen in executeScanSession.
		func() {
			defer logRecover("multiScan.cleanTmpSubdomainFiles")
			cleanTmpSubdomainFiles()
		}()
	}
	totalTargets := len(req.Targets)

	// Save queue state for persistence
	s.saveQueueState(0, req)
	if req.ResumeQueueStatePath != "" && filepath.Clean(req.ResumeQueueStatePath) != filepath.Clean(s.queueStatePathForInstance(instanceID)) {
		s.clearQueueStatePath(req.ResumeQueueStatePath)
	}

	s.broadcastToInstance(instanceID, WSEvent{
		Type:         "queue_started",
		Content:      fmt.Sprintf("Starting scan queue: %d target(s)", totalTargets),
		TotalTargets: totalTargets,
		CurrentPhase: firstSelectedPhase(req.Phases),
	})

	// Discord: scan started
	s.sendDiscord(0x00ff88, "🚀 Scan Started", fmt.Sprintf("**Targets:** %s\n**Mode:** %s\n**Total:** %d target(s)", strings.Join(req.Targets, ", "), req.ScanMode, totalTargets))
	// Telegram: scan started
	if s.telegramConfigured() {
		s.sendTelegram(0x00ff88, "🚀 Scan Started", fmt.Sprintf("**Targets:** %s\n**Mode:** %s\n**Total:** %d target(s)", strings.Join(req.Targets, ", "), req.ScanMode, totalTargets))
	}

	interruptedQueue := false
	for i, target := range req.Targets {
		// Per-instance stop/pause: Stop All, single-stop, pause, and delete
		// all flip instance.Status, which we observe here. The global stopReq
		// is intentionally not consulted (see the admission-loop note above).
		instance.mu.RLock()
		instStatus := instance.Status
		instance.mu.RUnlock()
		if instStatus == "stopped" || instStatus == "paused" {
			interruptedQueue = true
			if instStatus == "paused" {
				s.broadcastToInstance(instanceID, WSEvent{Type: "paused", Content: "Scan queue paused"})
			} else {
				s.broadcastToInstance(instanceID, WSEvent{Type: "stopped", Content: "Scan queue stopped by user"})
			}
			break
		}

		// Update queue state after each target
		s.saveQueueState(i, req)

		// No per-target timeout — let scans run indefinitely; user uses stop button
		ctx, cancel := context.WithCancel(context.Background())
		s.mu.Lock()
		s.cancelScan = cancel
		s.mu.Unlock()

		// Store cancel on the instance so per-instance stop can cancel the scan context
		instance.mu.Lock()
		instance.cancel = cancel
		instance.mu.Unlock()

		switch req.ScanMode {
		case "wildcard":
			// Each target gets full wildcard treatment: tool-based subdomain
			// discovery, then the native pipeline per discovered host.
			s.runWildcardTarget(ctx, scanCfg, req, target, i, totalTargets)
		default:
			s.runSingleTarget(ctx, scanCfg, req, target, i, totalTargets)
		}

		instance.mu.RLock()
		instStatusAfterTarget := instance.Status
		instance.mu.RUnlock()
		// stopRequested=false: the global flag is not consulted for per-scan
		// queue advancement (see admission-loop note). instStatusAfterTarget
		// already reflects any per-instance stop/pause.
		if shouldAdvanceQueueAfterTarget(false, instStatusAfterTarget) {
			s.saveQueueState(i+1, req)
		} else {
			interruptedQueue = true
		}

		cancel() // always cancel context after target is done
	}

	if interruptedQueue {
		log.Printf("[INFO] runMultiScan queue interrupted before completion")
		return
	}

	// Discord: scan finished — use instance's accumulated vuln count
	// (don't read from inst.sctx.ID — it may point to a cleaned-up session context)
	vulnCount := 0
	s.instancesMu.RLock()
	if inst, ok := s.instances[instanceID]; ok {
		inst.mu.RLock()
		vulnCount = inst.VulnCount
		inst.mu.RUnlock()
	}
	s.instancesMu.RUnlock()
	if vulnCount > 0 {
		desc := fmt.Sprintf("**Targets:** %d completed\n**Vulnerabilities:** %d found\n**Completed at:** %s", totalTargets, vulnCount, time.Now().Format("15:04:05 MST"))
		s.sendDiscord(0x3b82f6, "✅ Scan Finished - Vulnerabilities Found", desc)
		if s.telegramConfigured() {
			s.sendTelegram(0x3b82f6, "✅ Scan Finished - Vulnerabilities Found", desc)
		}
	} else {
		s.sendDiscord(0x3b82f6, "✅ Scan Finished", fmt.Sprintf("**Targets:** %d completed\n**Vulnerabilities:** 0 found\n**Completed at:** %s", totalTargets, time.Now().Format("15:04:05 MST")))
		if s.telegramConfigured() {
			s.sendTelegram(0x3b82f6, "✅ Scan Finished", fmt.Sprintf("**Targets:** %d completed\n**Vulnerabilities:** 0 found\n**Completed at:** %s", totalTargets, time.Now().Format("15:04:05 MST")))
		}
	}

	log.Printf("[INFO] runMultiScan main body complete")
}

// ────────────────────────────────────────────────────────
// Mode-specific target handlers
// ────────────────────────────────────────────────────────

// makeScanDir creates a per-target scan directory with nested structure: target/date/randomslug
func (s *Server) makeScanDir(target string) string {
	dateDir := time.Now().Format("2006-01-02")
	scanDirName := fmt.Sprintf("%s_%s", sanitizeTarget(target), randomSlug())
	scanDir := filepath.Join(s.dataDir, target, dateDir, scanDirName)
	if err := os.MkdirAll(scanDir, 0700); err != nil {
		log.Printf("[ERROR] Failed to create scan directory %s: %v", scanDir, err)
	}
	return scanDir
}

func (s *Server) scanDirForResume(req ScanRequest, target string) (string, bool) {
	if !req.IsResume || req.ResumeScanDir == "" {
		return s.makeScanDir(target), false
	}
	if req.ResumeActiveTarget != "" && req.ResumeActiveTarget != target {
		return s.makeScanDir(target), false
	}
	return s.resumeScanDirOrNew(req.ResumeScanDir, target)
}

func (s *Server) scanDirForWildcardSubdomainResume(req ScanRequest, subdomain string, subIndex int) (string, bool) {
	if !req.IsResume || req.ResumeSubScanDir == "" {
		return s.makeScanDir(subdomain), false
	}
	if req.ResumeSubIndex != subIndex {
		return s.makeScanDir(subdomain), false
	}
	if req.ResumeSubScanTarget != "" && req.ResumeSubScanTarget != subdomain {
		return s.makeScanDir(subdomain), false
	}
	return s.resumeScanDirOrNew(req.ResumeSubScanDir, subdomain)
}

func (s *Server) resumeScanDirOrNew(scanDir, target string) (string, bool) {
	cleanDir := filepath.Clean(scanDir)
	dataDir := filepath.Clean(s.dataDir)
	rel, err := filepath.Rel(dataDir, cleanDir)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		log.Printf("[AUTO-RESUME] Ignoring unsafe resume scan dir %q", scanDir)
		return s.makeScanDir(target), false
	}
	if err := os.MkdirAll(cleanDir, 0700); err != nil {
		log.Printf("[AUTO-RESUME] Failed to reuse scan dir %s: %v", cleanDir, err)
		return s.makeScanDir(target), false
	}
	return cleanDir, true
}

func loadScanRecordFromDir(scanDir string) (*ScanRecord, bool) {
	if scanDir == "" {
		return nil, false
	}
	data, err := os.ReadFile(filepath.Join(scanDir, "scan.json"))
	if err != nil {
		return nil, false
	}
	var rec ScanRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, false
	}
	return &rec, true
}

func subdomainTargetsFromRecord(rec *ScanRecord) []string {
	if rec == nil {
		return nil
	}
	seen := make(map[string]bool)
	targets := make([]string, 0, len(rec.SubScans))
	for _, child := range rec.SubScans {
		target := strings.TrimSpace(child.Target)
		if target == "" || seen[target] {
			continue
		}
		seen[target] = true
		targets = append(targets, target)
	}
	return targets
}

// runSingleTarget handles a single-site mode scan for one target.
func (s *Server) runSingleTarget(ctx context.Context, scanCfg *config.Config, req ScanRequest, target string, idx, total int) {
	scanDir, resumed := s.scanDirForResume(req, target)
	s.saveQueueState(idx, req, queueProgress{
		ActiveTarget:  target,
		ActiveScanDir: scanDir,
		ActiveScanID:  filepath.Base(scanDir),
	})

	s.broadcastToInstance(req.InstanceID, WSEvent{
		Type:         "target_started",
		Content:      fmt.Sprintf("Scanning target %d/%d: %s", idx+1, total, target),
		Target:       target,
		AgentID:      filepath.Base(scanDir),
		TargetIndex:  idx + 1,
		TotalTargets: total,
		CurrentPhase: firstSelectedPhase(req.Phases),
	})

	sess := &scanSession{
		id:              filepath.Base(scanDir),
		target:          target,
		scanDir:         scanDir,
		cfg:             scanCfg,
		server:          s,
		name:            req.Name,
		userInstruction: req.Instruction,
		severityFilter:  req.SeverityFilter,
		scanners:        req.Scanners,
		discordWebhook:  req.DiscordWebhook,
		genReport:       true,
		resetState:      !resumed,
		instanceID:      req.InstanceID,
		scanMode:        "single",
		companyName:     req.CompanyName,
		logoPath:        req.LogoPath,
		phases:          req.Phases,
		reconMode:       req.ReconMode,
		scanIntensity:   req.ScanIntensity,
		targetAuth:      req.TargetAuth,
		ctx:             ctx,
		artifact:        req.Artifact,
		vulsSSHHost:     req.VulsSSHHost,
		assessment:      req.Assessment,
		profile:         req.Profile,
	}
	s.executeScanSession(sess)
	if s.instanceInterrupted(req.InstanceID) {
		return
	}

	s.broadcastToInstance(req.InstanceID, WSEvent{
		Type:         "target_completed",
		Content:      fmt.Sprintf("Target %d/%d completed: %s", idx+1, total, target),
		Target:       target,
		TargetIndex:  idx + 1,
		TotalTargets: total,
	})
}

// runWildcardTarget handles wildcard mode via deterministic tool-based
// subdomain discovery, then the native scanner pipeline per discovered host.
func (s *Server) runWildcardTarget(ctx context.Context, scanCfg *config.Config, req ScanRequest, target string, idx, total int) {
	s.runDeterministicWildcard(ctx, scanCfg, req, target, idx, total)
}

// cleanTmpSubdomainFiles removes stale subdomain-related files from /tmp
// that could contaminate subsequent scans with targets from previous runs.
func cleanTmpSubdomainFiles() {
	subdomainFileNames := []string{
		"live_subdomains.txt", "live_subdomains_clean.txt", "live_resolved.txt",
		"all_subdomains.txt", "all_discovered_subdomains.txt", "subdomains.txt",
		"live_hosts.txt", "passive_subfinder.txt", "passive_subfinder2.txt",
		"active_subfinder.txt", "passive_crt.txt", "passive_findomain.txt",
		"passive_assetfinder.txt", "passive_dnsbufferover.txt", "archive_subdomains.txt",
		"resolved_subdomains.txt", "httpx_output.txt", "dnsx_output.txt",
	}

	// Remove known subdomain file names from /tmp
	for _, name := range subdomainFileNames {
		path := filepath.Join("/tmp", name)
		if err := os.Remove(path); err == nil {
			log.Printf("[CLEANUP] Removed stale /tmp file: %s", path)
		}
	}

	// Also remove any .txt files in /tmp that contain "subdomain" or "live" in the name
	entries, err := os.ReadDir("/tmp")
	if err != nil {
		log.Printf("[CLEANUP] Failed to read /tmp for cleanup: %v", err)
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".txt") && (strings.Contains(name, "subdomain") || strings.Contains(name, "live_") || strings.Contains(name, "passive_") || strings.Contains(name, "active_")) {
			path := filepath.Join("/tmp", name)
			if err := os.Remove(path); err == nil {
				log.Printf("[CLEANUP] Removed stale /tmp file: %s", path)
			}
		}
	}
}
