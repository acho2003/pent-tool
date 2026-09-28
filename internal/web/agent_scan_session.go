package web

import (
	"fmt"
	"log"
	"runtime/debug"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/agent"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
	"github.com/xalgord/xalgorix/v4/internal/tools/notes"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

// executeAgentScanSession runs one scan through the LLM-driven agent (the
// "autonomous" engine). It is the restored pre-deterministic executor: it
// builds an agent.Agent, streams its events to the WebSocket, and finalizes the
// record + report. Selected per-scan via engine=autonomous (see engine.go).
// It NEVER panics upward — all panics are caught and logged.
func (s *Server) executeAgentScanSession(sess *scanSession) {
	// IRONCLAD: This function NEVER panics upward.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[CRITICAL] scanSession %s panicked: %v\n%s", sess.id, r, debug.Stack())
			if sess.instanceID != "" {
				s.broadcastToInstance(sess.instanceID, WSEvent{Type: "error", Content: fmt.Sprintf("⛔ Scan %s crashed: %v — continuing", sess.target, r)})
			} else {
				s.broadcast(WSEvent{Type: "error", Content: fmt.Sprintf("⛔ Scan %s crashed: %v — continuing", sess.target, r)})
			}
		}
		// ALWAYS clean up, whether normal exit or panic
		sess.cleanup()
	}()

	// 0. Create and activate a per-session ScanContext for isolation.
	//    This must happen BEFORE any tool state is touched.
	sctx := scanctx.New(sess.id, sess.scanDir)
	scanctx.Activate(sctx)
	sess.sctx = sctx
	log.Printf("[scanctx] Activated context %s for target %s (dir=%s)", sctx.ID, sess.target, sess.scanDir)

	// Panic-safe persistence: register the child→parent reporting mapping so
	// reporting.PromoteToParent runs incrementally on every report_vulnerability
	// call. CleanupContext clears the mapping on session teardown.
	if sess.parentReportingCtxID != "" {
		reporting.SetParentContext(sctx.ID, sess.parentReportingCtxID)
	}

	// Propagate ScanContext to parent instance (if multi-instance mode)
	if sess.instanceID != "" {
		s.instancesMu.RLock()
		if inst, ok := s.instances[sess.instanceID]; ok {
			inst.mu.Lock()
			inst.sctx = sctx
			inst.mu.Unlock()
		}
		s.instancesMu.RUnlock()
	}

	// 1. Reset per-context state if requested (context-aware)
	if sess.resetState {
		func() {
			defer logRecover("session.resetContextState")
			reporting.ResetVulnerabilitiesForContext(sctx.ID)
			notes.ResetNotesForContext(sctx.ID)
		}()
	}

	// 1b. Configure notes disk persistence → saves notes.json in scan directory
	notes.SetPersistPathForContext(sctx.ID, sess.scanDir)
	if !sess.resetState {
		// Resume scenario: load previously saved notes from disk
		notes.LoadFromDiskForContext(sctx.ID)
	}

	// 2. Set working directory (context-aware)
	sctx.Terminal.SetWorkDir(sess.scanDir)
	sctx.Browser.SetSessionPath(sess.scanDir)

	// 3. Create agent with session's config AND ScanContext.
	// When the per-scan code path supplied a pre-resolved llm.Client
	// (B1: provider_profile-aware endpoint), thread it through
	// agent.WithLLMClient so the agent's outbound traffic actually
	// uses the operator's chosen credentials. A nil llmClient falls
	// back to the agent's default llm.NewClient(cfg) construction,
	// preserving the legacy behavior for tests / CLI / call sites
	// that have not opted in.
	events := make(chan agent.Event, 512)
	sess.events = events
	agentOpts := []any{sctx}
	if sess.llmClient != nil {
		agentOpts = append(agentOpts, agent.WithLLMClient(sess.llmClient))
	}
	agnt := agent.NewAgent(sess.cfg, "XalgorixAgent", events, scopeguard.Config{
		BindAddr:           s.cfg.BindAddr,
		Port:               s.port,
		AllowLoopbackPorts: sess.allowLoopbackPorts,
		AllowLocalTargets:  s.cfg.AllowLocalTargets,
	}, agentOpts...)
	agnt.SetPhaseRestrictions(sess.phases)
	agnt.SetActivityPolicy(sess.reconMode, sess.scanIntensity, []string{sess.target, sess.parentTarget})
	if sess.discoveryMode || isReconReportOnlyPhaseSelection(sess.phases) {
		agnt.SetDiscoveryMode(true)
	}
	// Per-scan authenticated scanning and whitebox source. Empty values are
	// no-ops; non-empty values override the agent's cfg-derived defaults so
	// each scan can carry its own credentials/source without leaking across
	// sessions. SetSourceRepo only records intent — the clone/open happens
	// lazily inside Run via prepareScanEnvironment.
	if sess.targetAuth != "" {
		agnt.SetTargetAuth(sess.targetAuth)
	}
	if sess.targetAuthB != "" {
		agnt.SetTargetAuthSecondary(sess.targetAuthB)
	}
	if sess.sourceRepo != "" {
		agnt.SetSourceRepo(sess.sourceRepo)
	}
	if sess.scanContext != "" {
		agnt.SetScanContext(sess.scanContext)
	}
	if sess.codeScanMode != agent.CodeScanNone {
		agnt.SetCodeScanMode(sess.codeScanMode)
	}
	sess.agent = agnt

	// Store agent ref on server for handleStop/handleChat (under lock)
	s.mu.Lock()
	s.currentScanDir = sess.scanDir
	s.currentScanID = sess.id
	s.currentAgents[sess.id] = agnt
	s.mu.Unlock()

	// Register agent with parent instance if applicable
	if sess.instanceID != "" {
		s.instancesMu.RLock()
		if inst, ok := s.instances[sess.instanceID]; ok {
			inst.mu.Lock()
			inst.agent = agnt
			inst.scanDir = sess.scanDir
			inst.lastSessionTokens = 0 // reset token delta for this new session/phase
			inst.mu.Unlock()
		}
		s.instancesMu.RUnlock()
	}

	// 4. Initialize scan record. Resume paths preserve previously persisted
	// events, vulnerabilities, counters, and sub-scan progress.
	sess.record = s.scanRecordForSession(sess)
	s.saveScanRecordTo(sess.record, sess.scanDir)

	// 5. Event processing goroutine — drains events and broadcasts to WebSocket
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[PANIC] Event processor panicked: %v — continuing\n%s", r, debug.Stack())
			}
		}() // never let panic escape event processor
		for evt := range events {
			s.processEvent(evt, sess)
		}
	}()

	// 6. Build instruction with severity filter
	instruction := sess.instruction
	if len(sess.severityFilter) > 0 {
		instruction = buildSeverityPrefix(sess.severityFilter) + "\n\n" + instruction
	}

	// 7. Run agent (blocks until finished or stopped)
	agnt.Run([]string{sess.target}, instruction)

	// 8. Close events channel and wait for event processor to drain
	close(events)
	<-done

	if status, stopReason := s.instanceRunStatus(sess.instanceID); isInterruptedInstanceStatus(status) {
		sess.record.Status = status
		sess.record.StopReason = stopReason
		sess.record.FinishedAt = time.Now().Format(time.RFC3339)
		// NOTE: in-memory→record merge and child→parent reporting merge
		// are deferred to sess.cleanup() (Wave C 4.2) so they survive an
		// agent panic. The deferred path is idempotent: merge dedups by
		// vuln summary key and MergeVulnsToContext skips ID/semantic
		// duplicates, so the success path merges exactly once.
		s.saveScanRecordTo(sess.record, sess.scanDir)
		return
	}

	// 8b. Abnormal LLM-side abort (agent bailed: refused tools / empty responses
	// / repeated errors / rate-limit).
	//
	// Distinguish two very different situations that both surface as "the model
	// stopped calling tools":
	//
	//   (a) The scan already reported findings — it ran the assessment and just
	//       failed to emit the final `finish` call, then rambled until the
	//       no-tool guard fired. This is effectively a COMPLETION: the report
	//       reflects real work, so record it as "finished" (and let step 10
	//       generate the report). Failing/refunding here would throw away a real
	//       result the customer is entitled to.
	//
	//   (b) The scan bailed with NOTHING to show (no findings) — a genuine
	//       malfunction that produced no result. Record it as "failed" with a
	//       diagnostic stop reason so it is never shown as a clean completion and
	//       (on hosted) is refunded.
	//
	// For (b) we update BOTH the persisted record AND the live instance: the
	// scan-status API (applyInstanceSnapshot) overlays the in-memory instance
	// status over the record, and runMultiScan's deferred finalize would
	// otherwise flip a still-"running" instance to "finished". This runs after
	// the event processor has drained (<-done above), so there is no concurrent
	// processEvent writer.
	//
	// CRITICAL: only a TOP-LEVEL single/DAST session may fail the instance on
	// abort. A wildcard scan runs one discovery session + one session per
	// subdomain, and they ALL share the parent instance ID. Phase 1 discovery
	// routinely ends with a no-tool abort AFTER it has already enumerated the
	// subdomains, and individual subdomain sessions can abort while hundreds
	// more are still queued. Failing the instance from any of those clobbers a
	// scan that is genuinely still running (the reported "running but marked
	// failed" bug) and wrongly refunds it. Wildcard parent status is owned by
	// the orchestrator (runWildcardTarget / runMultiScan), so wildcard
	// sub-sessions fall through to the normal "finished" finalize below.
	if sess.abortReason != "" && shouldFailInstanceOnAbort(sess.scanMode, sess.parentTarget, sess.discoveryMode) {
		reportedVulns := 0
		if sess.sctx != nil {
			reportedVulns = len(reporting.GetVulnerabilitiesForContext(sess.sctx.ID))
		}
		producedResults := reportedVulns > 0 || len(sess.record.Vulns) > 0 || sess.record.CurrentPhase >= 20 || sess.record.ToolCalls >= 5
		if !producedResults {
			finishedAt := time.Now().Format(time.RFC3339)
			sess.record.Status = "failed"
			sess.record.StopReason = sess.abortReason
			sess.record.FinishedAt = finishedAt
			if sess.instanceID != "" {
				s.instancesMu.RLock()
				inst, ok := s.instances[sess.instanceID]
				s.instancesMu.RUnlock()
				if ok {
					inst.mu.Lock()
					// Never clobber a user-initiated stop/pause; only downgrade a
					// still-active instance to failed.
					if inst.Status == "running" || inst.Status == "pending" || inst.Status == "" {
						inst.Status = "failed"
						inst.StopReason = sess.abortReason
						inst.FinishedAt = finishedAt
					}
					inst.mu.Unlock()
				}
			}
			s.saveScanRecordTo(sess.record, sess.scanDir)
			return
		}
		// (a) findings exist or testing was performed → fall through to a normal "finished" completion.
		log.Printf("[SCAN] %s: agent stopped calling tools (%s) after testing (phase %d, %d tool calls); recording as completed with report intact",
			sess.id, sess.abortReason, sess.record.CurrentPhase, sess.record.ToolCalls)
	}

	// 9. Finalize record
	sess.record.Status = "finished"
	sess.record.FinishedAt = time.Now().Format(time.RFC3339)

	// NOTE: merges are deferred to sess.cleanup() (Wave C 4.2) under
	// safe.Recover boundaries to guarantee panic-safe persistence. Both
	// mergeReportedVulnerabilitiesIntoRecord and MergeVulnsToContext are
	// idempotent (each entry keyed by vuln id / summary tuple), so the
	// clean-finish path runs the merges exactly once via cleanup().

	s.saveScanRecordTo(sess.record, sess.scanDir)

	// 10. Generate report if requested (always generate, even for clean scans)
	if sess.genReport {
		if p, err := s.generateReportAt(sess.record, sess.scanDir); err == nil {
			log.Printf("PDF report saved: %s", p)
			vulnCount := len(sess.record.Vulns)
			if vulnCount > 0 {
				desc := fmt.Sprintf("**Target:** %s\n**Vulnerabilities:** %d found\n**Completed at:** %s",
					sess.target, vulnCount, time.Now().Format("15:04:05 MST"))
				s.sendDiscordWithFile(0x3b82f6, "✅ Scan Finished - Report Ready", desc, p)
				if s.telegramConfigured() {
					s.sendTelegramWithFile(0x3b82f6, "✅ Scan Finished - Report Ready", desc, p)
				}
			} else {
				desc := fmt.Sprintf("**Target:** %s\n**Result:** No vulnerabilities found (clean scan)\n**Completed at:** %s",
					sess.target, time.Now().Format("15:04:05 MST"))
				s.sendDiscordWithFile(0x2dd4bf, "✅ Scan Finished - Clean Report", desc, p)
				if s.telegramConfigured() {
					s.sendTelegramWithFile(0x2dd4bf, "✅ Scan Finished - Clean Report", desc, p)
				}
			}
			if sess.instanceID != "" {
				reportEvt := WSEvent{Type: "report_ready", Content: fmt.Sprintf("/api/report/%s", sess.id)}
				if phaseAllowed(sess.phases, 22) {
					reportEvt.CurrentPhase = 22
				}
				s.broadcastToInstance(sess.instanceID, reportEvt)
			} else {
				s.broadcast(WSEvent{Type: "report_ready", Content: fmt.Sprintf("/api/report/%s", sess.id)})
			}
		} else {
			log.Printf("Failed to generate PDF report: %v", err)
		}
	}
}
