package web

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/agent"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

// shouldFailInstanceOnAbort reports whether an LLM-abort (no-tool / empty /
// repeated-error / rate-limit) in THIS session may mark the whole scan
// instance failed.
//
// Only a top-level single/DAST scan qualifies. A wildcard scan runs a discovery
// session plus one session per subdomain, and every one of them shares the
// parent instance ID: Phase 1 discovery normally ends with a no-tool abort
// after it has already enumerated the subdomains, and a single subdomain
// session can abort while hundreds more are still queued. Failing the instance
// from any wildcard sub-session marks a scan that is still actively running as
// "failed" (and wrongly refunds it). Wildcard parent status is decided by the
// orchestrator, so those sessions must fall through to the normal finalize.
func shouldFailInstanceOnAbort(scanMode, parentTarget string, discoveryMode bool) bool {
	if strings.EqualFold(strings.TrimSpace(scanMode), "wildcard") {
		return false
	}
	if discoveryMode {
		return false
	}
	if strings.TrimSpace(parentTarget) != "" {
		return false
	}
	return true
}

// executeScanSession runs a single scan in complete isolation.
// It NEVER panics upward — all panics are caught and logged.
func (s *Server) executeScanSession(sess *scanSession) {
	s.executeDeterministicScanSession(sess)
}

func (s *Server) processEvent(evt agent.Event, sess *scanSession) {
	wsEvt := WSEvent{
		Type:        evt.Type,
		Content:     evt.Content,
		ToolName:    evt.ToolName,
		ToolArgs:    evt.ToolArgs,
		AgentID:     evt.AgentID,
		Timestamp:   evt.Timestamp.Format(time.RFC3339),
		TotalTokens: evt.TotalTokens,
	}

	if evt.Type == "tool_result" {
		wsEvt.Output = evt.ToolResult.Output
		wsEvt.Error = evt.ToolResult.Error
	}

	if evt.Type == "tool_result" {
		// Push vuln to UI in real-time when report_vulnerability succeeds
		if evt.ToolName == "report_vulnerability" && evt.ToolResult.Error == "" {
			vulnID, reported := metadataString(evt.ToolResult.Metadata, "vuln_id")
			if !reported {
				log.Printf("[VULN] report_vulnerability returned without a new vuln_id; not broadcasting stored vuln again")
			} else {
				vulns := reporting.GetVulnerabilitiesForContext(sess.sctx.ID)
				log.Printf("[VULN] report_vulnerability tool created %s, vulns in list: %d", vulnID, len(vulns))
				latest, found := findReportedVulnerabilityByID(vulns, vulnID)
				if !found {
					log.Printf("[VULN] report_vulnerability metadata referenced %s, but it was not found in context %s", vulnID, sess.sctx.ID)
				} else {
					vs := vulnToSummary(latest)
					log.Printf("[VULN] Latest vuln: %s %s (CVSS %.1f)", vs.Severity, vs.Title, vs.CVSS)

					// Severity filter is a DISPLAY/BROADCAST gate, NOT a
					// persistence gate. Every vuln the agent reports must be
					// persisted to the scan record (and thus the on-disk
					// scan.json + the PDF report) so the report reflects
					// everything found — not just the severities the operator
					// chose to surface live. Filtering here previously dropped
					// below-threshold vulns from the record entirely, causing
					// "report shows no findings but logs show critical" (#157
					// customer feedback).
					allowed := true
					if len(sess.severityFilter) > 0 {
						allowed = false
						for _, sev := range sess.severityFilter {
							if strings.EqualFold(sev, vs.Severity) {
								allowed = true
								break
							}
						}
						log.Printf("[VULN] Severity filter active: filter=%v, allowed=%v", sess.severityFilter, allowed)
					}

					// Always persist to the record (report + on-disk source of truth).
					if appendVulnSummaryUnique(&sess.record.Vulns, vs) {
						log.Printf("[VULN] Vuln persisted to record: %s %s", vs.Severity, vs.Title)
						// Broadcast + notify only when the severity filter allows it.
						if allowed {
							wsEvt.Vulns = []VulnSummary{vs}
							log.Printf("[VULN] Vuln broadcast real-time: %s %s", vs.Severity, vs.Title)

							// Discord: vulnerability found (respects XALGORIX_DISCORD_MIN_SEVERITY)
							sevColor := 0xef4444 // red for critical/high
							switch vs.Severity {
							case "medium":
								sevColor = 0xd97706
							case "low", "info":
								sevColor = 0x3b82f6
							}
							var details strings.Builder
							details.WriteString(fmt.Sprintf("**%s**\n\n", vs.Title))
							if vs.Description != "" {
								details.WriteString(fmt.Sprintf("📝 **Description:**\n%s\n\n", vs.Description))
							}
							if vs.Endpoint != "" {
								details.WriteString(fmt.Sprintf("🔗 **Endpoint:** `%s`\n", vs.Endpoint))
							}
							if vs.Method != "" {
								details.WriteString(fmt.Sprintf("📡 **Method:** `%s`\n", vs.Method))
							}
							if vs.CVE != "" {
								details.WriteString(fmt.Sprintf("🏷️ **CVE:** `%s`\n", vs.CVE))
							}
							details.WriteString(fmt.Sprintf("📊 **CVSS:** `%.1f` | **Severity:** `%s`\n\n", vs.CVSS, strings.ToUpper(vs.Severity)))
							if vs.Impact != "" {
								details.WriteString(fmt.Sprintf("💥 **Impact:**\n%s\n\n", vs.Impact))
							}
							if vs.TechnicalAnalysis != "" {
								details.WriteString(fmt.Sprintf("🔬 **Technical Analysis:**\n%s\n\n", vs.TechnicalAnalysis))
							}
							if vs.PoCDescription != "" {
								details.WriteString(fmt.Sprintf("🧪 **PoC:**\n%s\n", vs.PoCDescription))
							}
							if vs.PoCScript != "" {
								poc := vs.PoCScript
								if len(poc) > 800 {
									poc = poc[:800] + "\n... (truncated)"
								}
								details.WriteString(fmt.Sprintf("```\n%s\n```\n\n", poc))
							}
							if vs.Remediation != "" {
								details.WriteString(fmt.Sprintf("🛡️ **Remediation:**\n%s", vs.Remediation))
							}
							// Apply Discord minimum severity filter
							if severityMeetsThreshold(vs.Severity, s.discordMinSeverity) {
								s.sendDiscord(sevColor, fmt.Sprintf("🐛 %s Vulnerability Found", strings.ToUpper(vs.Severity)), details.String())
							} else {
								log.Printf("[DISCORD] Skipping %s vuln notification (min severity: %s)", vs.Severity, s.discordMinSeverity)
							}
							// Apply Telegram minimum severity filter (independent of Discord)
							if s.telegramConfigured() && severityMeetsThreshold(vs.Severity, s.telegramMinSeverity) {
								s.sendTelegram(sevColor, fmt.Sprintf("🐛 %s Vulnerability Found", strings.ToUpper(vs.Severity)), details.String())
							} else if s.telegramConfigured() {
								log.Printf("[TELEGRAM] Skipping %s vuln notification (min severity: %s)", vs.Severity, s.telegramMinSeverity)
							}
						}
					} else {
						log.Printf("[VULN] Skipping duplicate vuln already present in session record: %s %s", vs.ID, vs.Title)
					}
					if !allowed {
						log.Printf("[VULN] Vuln persisted but NOT broadcast (filtered out by severity: %s, filter: %v)", vs.Severity, sess.severityFilter)
					}
				}
			}
		}
	}

	if phase := inferCurrentPhase(wsEvt, sess.phases); phase > 0 {
		// Monotonic: the legacy phase-progress bar only ever moves forward.
		// Historical scan events can arrive out of order, so a last-wins update
		// made the bar bounce backward. Reporting the max reached keeps legacy
		// progress stable.
		if sess.record != nil {
			if phase > sess.record.CurrentPhase {
				sess.record.CurrentPhase = phase
			}
			wsEvt.CurrentPhase = sess.record.CurrentPhase
		} else {
			wsEvt.CurrentPhase = phase
		}
	}

	if evt.Type == "finished" {
		// An abnormal LLM-side abort (refused tools / empty responses / repeated
		// errors / rate-limit) reuses the "finished" event type but is NOT a
		// clean completion. Record the reason so finalize marks the scan failed.
		if evt.Aborted {
			sess.abortReason = evt.AbortReason
			if sess.abortReason == "" {
				sess.abortReason = "llm_aborted"
			}
		}
		// Build set of vulns already broadcast in real-time to avoid duplicates
		seen := make(map[string]bool)
		for _, v := range sess.record.Vulns {
			seen[vulnSummaryKey(v)] = true
		}
		vulns := reporting.GetVulnerabilitiesForContext(sess.sctx.ID)
		log.Printf("[VULN] Finished event: total vulns in system: %d, already broadcast: %d", len(vulns), len(seen))
		for _, v := range vulns {
			vs := vulnToSummary(v)
			if seen[vulnSummaryKey(vs)] {
				log.Printf("[VULN] Finished: skipping already-broadcast vuln: %s %s", v.ID, v.Title)
				continue
			}
			allowed := true
			if len(sess.severityFilter) > 0 {
				allowed = false
				for _, sev := range sess.severityFilter {
					if strings.EqualFold(sev, vs.Severity) {
						allowed = true
						break
					}
				}
			}
			if allowed {
				wsEvt.Vulns = append(wsEvt.Vulns, vs)
				seen[vulnSummaryKey(vs)] = true
				log.Printf("[VULN] Finished: adding new vuln to final broadcast: %s %s", vs.Severity, vs.Title)
			} else {
				log.Printf("[VULN] Finished: filtered vuln (not added to broadcast): %s (filter: %v)", vs.Severity, sess.severityFilter)
			}
		}
		log.Printf("[VULN] Finished: total vulns in final broadcast: %d", len(wsEvt.Vulns))
	}

	// Track stats on per-session record
	if evt.Type == "thinking" {
		sess.record.Iterations++
	}
	if evt.Type == "tool_call" {
		sess.record.ToolCalls++
		// If no thinking event was emitted for this turn, fallback to tracking iteration on tool_call
		if sess.record.Iterations < sess.record.ToolCalls {
			sess.record.Iterations = sess.record.ToolCalls
		}
	}
	if evt.TotalTokens > 0 {
		sess.record.TotalTokens = sess.recordTokenOffset + evt.TotalTokens
	}

	// Update parent instance stats — ACCUMULATE across sessions (phases/subdomains),
	// don't overwrite. Each subdomain scan creates a fresh scanSession with zeroed
	// counters, so we increment the instance counters on each event.
	if sess.instanceID != "" {
		s.instancesMu.RLock()
		if inst, ok := s.instances[sess.instanceID]; ok {
			inst.mu.Lock()
			if evt.Type == "thinking" {
				inst.Iterations++
			}
			if evt.Type == "tool_call" {
				inst.ToolCalls++
				if inst.Iterations < inst.ToolCalls {
					inst.Iterations = inst.ToolCalls
				}
			}
			if evt.TotalTokens > 0 {
				// Tokens are cumulative within a session but reset between sessions,
				// so we track the delta
				inst.TotalTokens += evt.TotalTokens - inst.lastSessionTokens
				inst.lastSessionTokens = evt.TotalTokens
			}
			// Vulns: route through effectiveVulnCount so the counter source
			// is consistent across the scan lifecycle. While running, this
			// returns the in-memory count (parent context for wildcard child
			// sessions, session context otherwise); after teardown the
			// helper falls back to len(inst.Vulns). See Task 3.1 in
			// .kiro/specs/findings-consistency-and-pagination/tasks.md.
			inst.VulnCount = s.effectiveVulnCount(inst, sess)
			inst.mu.Unlock()
		}
		s.instancesMu.RUnlock()
	}

	// Filter thinking events from being stored or broadcast to the frontend
	if evt.Type == "thinking" {
		return
	}

	// Accumulate events for persistence (limit stored output size)
	savedEvt := wsEvt
	if len(savedEvt.Output) > 500 {
		savedEvt.Output = savedEvt.Output[:500] + "..."
	}
	sess.record.Events = append(sess.record.Events, savedEvt)

	// Periodically save scan record (every 10 events)
	if len(sess.record.Events)%10 == 0 {
		s.saveScanRecordTo(sess.record, sess.scanDir)
	}

	// Use instance-scoped broadcasting
	log.Printf("[VULN] Broadcasting: type=%s, instanceID=%s, vulns=%d", evt.Type, sess.instanceID, len(wsEvt.Vulns))
	if sess.instanceID != "" {
		s.broadcastToInstance(sess.instanceID, wsEvt)
	} else {
		s.broadcast(wsEvt)
	}
}

// buildSeverityPrefix creates the severity filter instruction prefix.
func buildSeverityPrefix(severityFilter []string) string {
	severityText := "CRITICAL INSTRUCTION: You MUST ONLY look for and report "
	severities := make([]string, len(severityFilter))
	copy(severities, severityFilter)
	severityText += strings.Join(severities, " and ") + " severity vulnerabilities. "
	severityText += "DO NOT report, investigate, or mention any LOW severity, INFORMATIONAL, or INFO findings. "
	severityText += "Ignore any potential LOW/INFO issues - they are out of scope for this engagement. "
	severityText += "Focus ONLY on: " + strings.Join(severities, ", ") + "."
	return severityText
}

func firstSelectedPhase(phases []int) int {
	if len(phases) == 0 {
		return 1
	}
	first := 0
	for _, phase := range phases {
		if phase < 1 || phase > 22 {
			continue
		}
		if first == 0 || phase < first {
			first = phase
		}
	}
	if first == 0 {
		return 1
	}
	return first
}

func phaseAllowed(phases []int, phase int) bool {
	if phase < 1 || phase > 22 {
		return false
	}
	if len(phases) == 0 {
		return true
	}
	for _, allowed := range phases {
		if allowed == phase {
			return true
		}
	}
	return false
}

func isReconReportOnlyPhaseSelection(phases []int) bool {
	if len(phases) == 0 {
		return false
	}
	for _, phase := range phases {
		if phase != 1 && phase != 22 {
			return false
		}
	}
	return true
}

var phaseMentionRe = regexp.MustCompile(`(?i)\bphase\s+([0-9]{1,2})\b`)

func inferCurrentPhase(evt WSEvent, allowed []int) int {
	if phase := parsePhaseMention(evt.Content); phaseAllowed(allowed, phase) {
		return phase
	}
	switch evt.Type {
	case "queue_started", "target_started", "scan_started":
		return firstSelectedPhase(allowed)
	case "queue_finished", "report_ready":
		if phaseAllowed(allowed, 22) {
			return 22
		}
	}

	if evt.Type != "tool_call" {
		return 0
	}
	args := strings.ToLower(strings.Join(mapValues(evt.ToolArgs), " "))

	switch {
	case strings.Contains(args, "sqlmap") || strings.Contains(args, "dalfox") ||
		strings.Contains(args, "union select") || strings.Contains(args, "<script") ||
		strings.Contains(args, "sleep("):
		if phaseAllowed(allowed, 6) {
			return 6
		}
	case strings.Contains(args, "ffuf") || strings.Contains(args, "gobuster") ||
		strings.Contains(args, "dirsearch") || strings.Contains(args, "feroxbuster"):
		if phaseAllowed(allowed, 3) {
			return 3
		}
	case strings.Contains(args, "ssrf") || strings.Contains(args, "169.254.169.254"):
		if phaseAllowed(allowed, 7) {
			return 7
		}
	// Phase 8: IDOR & Broken Access Control — detect from IDOR/BAC testing patterns
	case strings.Contains(args, "idor") || strings.Contains(args, "broken access") ||
		strings.Contains(args, "access control") || strings.Contains(args, "horizontal") ||
		strings.Contains(args, "vertical privilege") || strings.Contains(args, "privilege escalation"):
		if phaseAllowed(allowed, 8) {
			return 8
		}
	// Phase 9: API & GraphQL Testing
	case strings.Contains(args, "graphql") || strings.Contains(args, "introspection") ||
		strings.Contains(args, "__schema") || strings.Contains(args, "batch query") ||
		strings.Contains(args, "rest api") || strings.Contains(args, "swagger") ||
		strings.Contains(args, "openapi"):
		if phaseAllowed(allowed, 9) {
			return 9
		}
	// Phase 10: File Upload Testing
	case strings.Contains(args, "file upload") || strings.Contains(args, "multipart") ||
		strings.Contains(args, "upload.php") || strings.Contains(args, "webshell") ||
		strings.Contains(args, "shell.php"):
		if phaseAllowed(allowed, 10) {
			return 10
		}
	// Phase 11: Deserialization & RCE
	case strings.Contains(args, "deserialize") || strings.Contains(args, "rce") ||
		strings.Contains(args, "command injection") || strings.Contains(args, "code execution") ||
		strings.Contains(args, "pickle") || strings.Contains(args, "ysoserial"):
		if phaseAllowed(allowed, 11) {
			return 11
		}
	// Phase 12: Race Conditions & Business Logic
	case strings.Contains(args, "race condition") || strings.Contains(args, "concurrent") ||
		strings.Contains(args, "business logic") || strings.Contains(args, "turbo intruder") ||
		strings.Contains(args, "time-of-check"):
		if phaseAllowed(allowed, 12) {
			return 12
		}
	// Phase 13: Subdomain Takeover
	case strings.Contains(args, "subdomain takeover") || strings.Contains(args, "dangling") ||
		strings.Contains(args, "cname") || strings.Contains(args, "can-i-take-over-xyz") ||
		strings.Contains(args, "nuclei takeover"):
		if phaseAllowed(allowed, 13) {
			return 13
		}
	// Phase 14: Open Redirect Testing
	case strings.Contains(args, "open redirect") || strings.Contains(args, "url redirect") ||
		strings.Contains(args, "redirect=") || strings.Contains(args, "next=") ||
		strings.Contains(args, "returnurl=") || strings.Contains(args, "return_to="):
		if phaseAllowed(allowed, 14) {
			return 14
		}
	// Phase 16: Cloud & Infrastructure
	case strings.Contains(args, "s3 bucket") || strings.Contains(args, "aws") ||
		strings.Contains(args, "gcp") || strings.Contains(args, "azure") ||
		strings.Contains(args, "cloud storage") || strings.Contains(args, "terraform"):
		if phaseAllowed(allowed, 16) {
			return 16
		}
	// Phase 17: WebSocket Testing
	case strings.Contains(args, "websocket") || strings.Contains(args, "ws://") ||
		strings.Contains(args, "wss://") || strings.Contains(args, "socket.io"):
		if phaseAllowed(allowed, 17) {
			return 17
		}
	// Phase 20: Exploit Verification
	case strings.Contains(args, "exploit") || strings.Contains(args, "verify exploit") ||
		strings.Contains(args, "proof of concept") || strings.Contains(args, "poc"):
		if phaseAllowed(allowed, 20) {
			return 20
		}
	// Phase 21: Novel Vulnerability Discovery
	case strings.Contains(args, "novel") || strings.Contains(args, "fuzzing") ||
		strings.Contains(args, "mutation") || strings.Contains(args, "edge case"):
		if phaseAllowed(allowed, 21) {
			return 21
		}
	// NOTE: we deliberately do NOT infer phases 4/5 from tool-arg keywords
	// like "authorization", "cookie", "login", or "session". Those tokens
	// appear in ORDINARY requests on almost every target (an authed scan
	// sends an Authorization header from the first recon request), so they
	// caused the progress bar to false-jump to a late phase during early
	// reconnaissance. Those phases advance via the agent's own phase
	// narration (parsePhaseMention above), which is a real signal.
	case strings.Contains(args, "nmap") || strings.Contains(args, "naabu") ||
		strings.Contains(args, "masscan") || strings.Contains(args, "dig ") ||
		strings.Contains(args, "nslookup") || strings.Contains(args, "host ") ||
		strings.Contains(args, "whatweb") || strings.Contains(args, "wappalyzer") ||
		strings.Contains(args, "httpx") || strings.Contains(args, "wafw00f") ||
		strings.Contains(args, "subfinder") || strings.Contains(args, "amass") ||
		strings.Contains(args, "crt.sh"):
		if phaseAllowed(allowed, 1) {
			return 1
		}
	}

	return 0
}

func parsePhaseMention(text string) int {
	match := phaseMentionRe.FindStringSubmatch(text)
	if len(match) != 2 {
		return 0
	}
	var phase int
	if _, err := fmt.Sscanf(match[1], "%d", &phase); err != nil {
		return 0
	}
	if phase < 1 || phase > 22 {
		return 0
	}
	return phase
}

func mapValues(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
