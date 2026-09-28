package web

import (
	"context"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// Scan engine selects how a scan is executed:
//
//   - engineDeterministic ("just scan"): the fixed scanner.Pipeline of native
//     tools (subfinder/httpx/nmap/nuclei/zap/testssl/…). No LLM required.
//   - engineAutonomous ("full autonomous with AI"): the LLM-driven agent
//     decides its own approach and drives the 70+ tool catalog. Requires a
//     configured AI provider.
//
// The engine is chosen per-scan from the web UI and defaults to deterministic
// so a fresh install with no AI credentials still runs.
const (
	engineDeterministic = "deterministic"
	engineAutonomous    = "autonomous"
)

// normalizeEngine canonicalizes a wire/stored engine value. Empty and any
// unrecognized value fall back to the safe deterministic default so a bad or
// missing field never silently starts a credential-requiring autonomous scan.
func normalizeEngine(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case engineAutonomous:
		return engineAutonomous
	default:
		return engineDeterministic
	}
}

// autonomousProviderConfigured is the config-only fast path for
// autonomousProviderReady: it reports whether cfg (or a per-scan provider
// profile) directly carries a usable AI credential — a global API key, a
// custom/self-hosted endpoint (e.g. Ollama), or an active credential profile.
func autonomousProviderConfigured(cfg *config.Config, providerProfile string) bool {
	if strings.TrimSpace(providerProfile) != "" {
		return true
	}
	if cfg == nil {
		return false
	}
	return strings.TrimSpace(cfg.APIKey) != "" ||
		strings.TrimSpace(cfg.APIBase) != "" ||
		strings.TrimSpace(cfg.LLMProfile) != ""
}

// autonomousProviderReady reports whether an autonomous scan has any way to
// reach an AI provider. It covers every source the agent's llm client can be
// built from: the config-only credentials above, an explicit provider or model
// (cfg.LLMProvider / cfg.LLM — e.g. a credential-free local provider), and a
// stored credential profile (a profile-store-only install). It is intentionally
// lenient: it blocks only the "nothing configured at all" case, so a genuine
// misconfiguration surfaces as the agent's own clearly-labeled abort rather
// than a false rejection here.
func (s *Server) autonomousProviderReady(ctx context.Context, req ScanRequest) bool {
	if autonomousProviderConfigured(s.cfg, req.ProviderProfile) {
		return true
	}
	if s.cfg != nil && (strings.TrimSpace(s.cfg.LLM) != "" || strings.TrimSpace(s.cfg.LLMProvider) != "") {
		return true
	}
	// A stored credential profile is enough on its own (the catalog-default
	// resolver picks it up); check the store last since it may touch disk.
	if s.profiles != nil {
		if profs, err := s.profiles.List(ctx); err == nil && len(profs) > 0 {
			return true
		}
	}
	return false
}
