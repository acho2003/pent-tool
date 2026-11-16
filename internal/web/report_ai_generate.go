package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"
)

// AI report generation is OPT-IN and reverses the default deterministic-only
// behaviour. It sends the already-sanitized report manifest (the same data the
// deterministic report exposes — redaction-capped evidence, never raw secrets)
// to the Claude API to compose a full written narrative. It authenticates with
// the operator's Claude Code / Anthropic credentials (OAuth token or mounted
// profile), never a key baked into the image. When disabled or unauthenticated
// the deterministic report is used unchanged.

const (
	defaultAIReportModel = "claude-opus-5-5"
	aiReportMaxTokens    = 16000
	oauthBetaHeader      = "oauth-2025-04-20"
)

var errAIReportDisabled = errors.New("AI report generation is not enabled")

// aiReportEnabled reports whether the operator opted into AI report generation.
func aiReportEnabled() bool {
	return strings.TrimSpace(os.Getenv("XALGORIX_AI_REPORT")) == "1"
}

// aiReportModel is the configured model, defaulting to Claude Opus 5.5.
func aiReportModel() string {
	if m := strings.TrimSpace(os.Getenv("XALGORIX_AI_REPORT_MODEL")); m != "" {
		return m
	}
	return defaultAIReportModel
}

// aiReportGenerator produces a written report from a prompt. It is an interface
// so the report flow can be tested without calling the live API.
type aiReportGenerator interface {
	Generate(ctx context.Context, model, system, user string, maxTokens int64) (string, error)
}

// anthropicReportGenerator calls the Claude Messages API through the Go SDK,
// using the operator's Anthropic credentials resolved by the SDK's default
// chain (ANTHROPIC_AUTH_TOKEN, an ant/Claude Code OAuth profile, or an API key).
type anthropicReportGenerator struct{ client anthropic.Client }

func newAnthropicReportGenerator(extra ...option.RequestOption) anthropicReportGenerator {
	var opts []option.RequestOption
	// A raw OAuth bearer in the environment (Claude Code token) needs the oauth
	// beta header; a mounted profile adds its own headers, and an API key needs
	// neither. Credentials stored in the GUI arrive as `extra` options.
	if tok := strings.TrimSpace(os.Getenv("ANTHROPIC_AUTH_TOKEN")); tok != "" {
		opts = append(opts, option.WithAuthToken(tok), option.WithHeaderAdd("anthropic-beta", oauthBetaHeader))
	}
	opts = append(opts, extra...)
	return anthropicReportGenerator{client: anthropic.NewClient(opts...)}
}

func (g anthropicReportGenerator) Generate(ctx context.Context, model, system, user string, maxTokens int64) (string, error) {
	resp, err := g.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: maxTokens,
		System:    []anthropic.TextBlockParam{{Text: system}},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(user)),
		},
	})
	if err != nil {
		return "", err
	}
	if resp.StopReason == anthropic.StopReasonRefusal {
		return "", fmt.Errorf("report generation was declined (%s)", resp.StopReason)
	}
	var b strings.Builder
	for _, block := range resp.Content {
		if t, ok := block.AsAny().(anthropic.TextBlock); ok {
			b.WriteString(t.Text)
		}
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		return "", errors.New("the model returned an empty report")
	}
	return out, nil
}

const aiReportSystemPrompt = `You are a senior penetration tester writing the final written report for an authorized security assessment. You are given the assessment's machine-generated findings as JSON. Write a clear, professional report in Markdown.

Strict rules:
- Use ONLY the data in the JSON. Never invent findings, severities, hosts, evidence, counts, CVEs or remediation that is not supported by it.
- Preserve every finding's severity and identity exactly as given. Do not upgrade or downgrade severity.
- When something is unknown or the scanner did not provide it, say so plainly ("not provided by scanner") instead of guessing.
- Call out likely false positives only when the evidence itself supports that reading, and label them as your assessment, not fact.
- Do not include raw secrets, tokens, cookies or credentials, even if present in the data.

Structure: an executive summary, scope, a severity-ranked findings section with per-finding detail (location, evidence summary, impact, remediation), scanner coverage and gaps, and prioritized recommendations. Be precise and concise; prefer plain sentences over marketing language.`

// buildAIReportPrompt serializes the sanitized manifest for the model. The
// manifest is the public report data (redaction-capped evidence, no raw
// secrets), so nothing beyond what the deterministic report already exposes is
// sent to the API.
func buildAIReportPrompt(manifest reportManifest) (string, error) {
	data, err := json.MarshalIndent(manifest, "", " ")
	if err != nil {
		return "", err
	}
	return "Assessment findings (authoritative, deterministic):\n\n```json\n" + string(data) + "\n```\n\nWrite the full report now.", nil
}

// generateAIReport composes a full written report for a scan's manifest using
// the given generator. Gating (whether the feature is enabled and credentialed)
// is the caller's responsibility; see Server.aiReportConfigured.
func generateAIReport(ctx context.Context, gen aiReportGenerator, manifest reportManifest) (string, error) {
	if gen == nil {
		gen = newAnthropicReportGenerator()
	}
	user, err := buildAIReportPrompt(manifest)
	if err != nil {
		return "", err
	}
	return gen.Generate(ctx, aiReportModel(), aiReportSystemPrompt, user, aiReportMaxTokens)
}

const aiReportArtifactName = "report-ai.md"

// generateAIReportArtifact writes the AI-composed report to the scan directory
// when the operator has opted in. It is non-fatal: a failure (no credentials,
// API error, refusal) is logged and leaves the deterministic report as the
// deliverable. Called from the report-generation path only when enabled.
func (s *Server) generateAIReportArtifact(ctx context.Context, manifest reportManifest, scanDir string, rec *ScanRecord, instanceID string) {
	gen := newAnthropicReportGenerator(s.aiCredentialOptions()...)
	md, err := generateAIReport(ctx, gen, manifest)
	if err != nil {
		if !errors.Is(err, errAIReportDisabled) {
			log.Printf("[report] AI report generation failed: %v", err)
		}
		return
	}
	if err := os.WriteFile(filepath.Join(scanDir, aiReportArtifactName), []byte(md), 0o600); err != nil {
		log.Printf("[report] saving AI report failed: %v", err)
		return
	}
	if rec != nil {
		ev := WSEvent{Type: "report_ai_ready", Content: "AI report ready", Output: "/api/report/" + rec.ID + "?format=ai", Timestamp: time.Now().Format(time.RFC3339Nano)}
		rec.Events = append(rec.Events, ev)
		s.saveScanRecordTo(rec, scanDir)
		s.broadcastToInstance(instanceID, ev)
	}
}

// serveAIReport streams the saved AI report markdown, generating it on demand
// (which also refreshes the deterministic report) when it is missing and the
// feature is enabled.
func (s *Server) serveAIReport(w http.ResponseWriter, rec *ScanRecord, scanDir string) {
	aiPath := filepath.Join(scanDir, aiReportArtifactName)
	if info, err := os.Stat(aiPath); err != nil || !info.Mode().IsRegular() {
		if !s.aiReportConfigured() {
			http.Error(w, "AI report generation is not connected (connect Claude in Settings, or set XALGORIX_AI_REPORT=1 with credentials)", http.StatusNotFound)
			return
		}
		s.generateScannerReport(rec, scanDir, rec.InstanceID)
	}
	data, err := os.ReadFile(aiPath)
	if err != nil {
		http.Error(w, "AI report is not available for this scan", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"xalgorix_report_%s.md\"", rec.ID))
	_, _ = w.Write(data)
}
