// Package web provides the Xalgorix web UI server.
package web

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/resources"
	"github.com/xalgord/xalgorix/v4/internal/safe"
	"github.com/xalgord/xalgorix/v4/internal/sandbox"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
	"github.com/xalgord/xalgorix/v4/internal/storage"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

// Version is set by main.go at startup — single source of truth.
var Version = "dev"

//go:embed static/*
var staticFiles embed.FS

// RateLimiter implements a simple in-memory rate limiter
type RateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
	stopCh   chan struct{}
	stopOnce sync.Once
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
		stopCh:   make(chan struct{}),
	}
	// Cleanup old entries every minute
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-rl.stopCh:
				return
			case <-ticker.C:
				rl.cleanup()
			}
		}
	}()
	return rl
}

// Stop signals the cleanup goroutine to exit. Safe to call multiple times.
func (rl *RateLimiter) Stop() {
	rl.stopOnce.Do(func() { close(rl.stopCh) })
}

// cleanup walks the request map and discards entries whose timestamps have
// all aged out of the active window. Done in two passes (collect → delete)
// to minimize lock contention with Allow() under high churn.
func (rl *RateLimiter) cleanup() {
	cutoff := time.Now().Add(-rl.window)

	// Pass 1: collect IPs whose buckets are fully expired. RLock would be
	// ideal, but the underlying mutex is sync.Mutex; the read cost is small.
	rl.mu.Lock()
	var toDelete []string
	for ip, times := range rl.requests {
		stillValid := false
		for _, t := range times {
			if t.After(cutoff) {
				stillValid = true
				break
			}
		}
		if !stillValid {
			toDelete = append(toDelete, ip)
		}
	}
	rl.mu.Unlock()

	if len(toDelete) == 0 {
		return
	}

	// Pass 2: re-check each IP under lock — a request could have arrived
	// between passes and re-validated the bucket.
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for _, ip := range toDelete {
		times, ok := rl.requests[ip]
		if !ok {
			continue
		}
		stillValid := false
		for _, t := range times {
			if t.After(cutoff) {
				stillValid = true
				break
			}
		}
		if !stillValid {
			delete(rl.requests, ip)
		}
	}
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	windowStart := now.Add(-rl.window)

	// Get or create the slice
	times := rl.requests[ip]
	var valid []time.Time
	for _, t := range times {
		if t.After(windowStart) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= rl.limit {
		rl.requests[ip] = valid
		return false
	}

	rl.requests[ip] = append(valid, now)
	return true
}

func rateLimitMiddleware(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip rate limiting for WebSocket, static files, and dashboard
			// polling reads. Auth still wraps this middleware, so protected
			// reads require a valid session before they reach this point.
			if r.URL.Path == "/ws" || isStaticWebAssetPath(r.URL.Path) ||
				isDashboardReadPath(r.Method, r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// Use RemoteAddr only — do not trust X-Forwarded-For as it can be
			// spoofed when running without a trusted reverse proxy. Strip the
			// port so each TCP connection from the same client shares a bucket.
			ip := r.RemoteAddr
			if host, _, err := net.SplitHostPort(ip); err == nil {
				ip = host
			}

			if !rl.Allow(ip) {
				http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isStaticWebAssetPath(path string) bool {
	if path == "" || strings.HasPrefix(path, "/api/") || path == "/ws" {
		return false
	}
	if strings.HasPrefix(path, "/static/") ||
		strings.HasPrefix(path, "/assets/") ||
		strings.HasPrefix(path, "/chunks/") {
		return true
	}
	switch filepath.Ext(path) {
	case ".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2":
		return true
	default:
		return false
	}
}

func isDashboardReadPath(method, path string) bool {
	if method != http.MethodGet {
		return false
	}
	switch path {
	case "/api/auth/status",
		"/api/status",
		"/api/version",
		"/api/scans",
		"/api/findings",
		"/api/findings/projects",
		"/api/findings/summary",
		"/api/instances",
		"/api/queue/status",
		"/api/legacy-import/status":
		return true
	default:
		return strings.HasPrefix(path, "/api/scans/") ||
			strings.HasPrefix(path, "/api/instances/")
	}
}

func setWebUICacheHeaders(w http.ResponseWriter) {
	// The embedded SPA uses stable asset names (/app.js, /style.css). Disable
	// browser caching so replacing the local binary takes effect on refresh.
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

func canStartInstanceStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "saved", "stopped", "failed", "finished":
		return true
	default:
		return false
	}
}

// ─── Authentication ─────────────────────────────────────────────────────────

// logRecover is a deferred recovery helper used by best-effort cleanup
// blocks. The previous pattern was `defer func() { recover() }()` which
// silently swallowed panics — making cleanup bugs invisible in
// production. logRecover preserves the original behavior (don't crash
// the server during shutdown) while emitting a stack trace so the bug
// can be diagnosed.
//
// Usage: defer logRecover("scanSession.cleanup.scanctx")
func logRecover(label string) {
	if r := recover(); r != nil {
		log.Printf("[recover] %s: %v\n%s", label, r, debug.Stack())
	}
}

// ScanRequest is the JSON body for starting a scan.
type ScanRequest struct {
	// Assessment is the typed mode/type/target/access configuration. It is
	// optional so legacy scan clients retain their existing request contract.
	Assessment       *assessment.AssessmentConfig `json:"assessment,omitempty"`
	PlanFingerprint  string                       `json:"plan_fingerprint,omitempty"`
	assessmentPlan   *scanner.AssessmentPlan
	Targets          []string `json:"targets"`
	Instruction      string   `json:"-"`         // legacy in-memory/resume field; not accepted by schema-v2 API
	ScanMode         string   `json:"scan_mode"` // "single" or "wildcard"
	Profile          string   `json:"profile,omitempty"`
	WebScope         string   `json:"web_scope,omitempty"`
	APIDefinitionIDs []string `json:"api_definition_ids,omitempty"`
	Model            string   `json:"-"`
	APIKey           string   `json:"-"`
	APIBase          string   `json:"-"`
	DiscordWebhook   string   `json:"discord_webhook"` // Discord webhook URL
	SeverityFilter   []string `json:"severity_filter"` // e.g. ["critical", "high"]
	// Scanners selects which of scanner.OrderedNames run. Empty = all scanners.
	// Deselected scanners still produce an explicit "skipped" run.
	Scanners      []string `json:"scanners"`
	Name          string   `json:"name"`      // user-defined scan name
	SaveOnly      bool     `json:"save_only"` // if true, save scan config without starting
	Phases        []int    `json:"-"`
	ReconMode     string   `json:"-"`
	ScanIntensity string   `json:"-"`
	CompanyName   string   `json:"company_name"` // report branding: company name
	LogoPath      string   `json:"logo_path"`    // report branding: logo file path
	// TargetAuth carries per-scan authenticated-scanning material so the
	// agent can exercise post-login attack surface. Format mirrors
	// XALGORIX_TARGET_AUTH (see httpclient/sessionauth.go): a header/cookie
	// spec applied automatically to http_request. Empty = unauthenticated.
	TargetAuth string `json:"target_auth"`
	// TargetAuthSecondary is a SECOND account's auth (same format as TargetAuth),
	// surfaced to the agent to prove horizontal access-control flaws (IDOR/BOLA).
	// Not auto-applied. Empty = single-account testing.
	TargetAuthSecondary string `json:"-"`
	// SourceRepo enables whitebox/source-assisted scanning. It is either a
	// git clone URL or a local path; the agent clones/opens it at scan
	// start and exposes it via the code_search tool. Empty = blackbox.
	SourceRepo string `json:"source_repo"`
	// CodeScan selects a code-first scan (SourceRepo becomes the subject, no
	// live target URL is required):
	//   "review"    — source review / SAST, no running target (Option 1).
	//   "provision" — build & run the source locally, then DAST it (Option 2).
	// Empty = normal target-driven scan (SourceRepo, if set, augments it).
	CodeScan string `json:"-"`
	// ScanContext is a path to operator-supplied context artifact(s) — an
	// OpenAPI/Swagger spec, HAR capture, or Postman collection (file or dir).
	// The engine parses them into a seeded attack surface (real endpoints +
	// params) and harvests any captured auth. Empty = crawl-only discovery.
	ScanContext string           `json:"-"`
	Artifact    scanner.Artifact `json:"artifact,omitempty"`
	VulsSSHHost string           `json:"vuls_ssh_host,omitempty"`
	// Internal fields — `json:"-"` makes them un-settable from the wire.
	// Critical: a client must not be able to set InstanceID to spoof
	// broadcasts to another scan, or set IsResume to bypass the resume
	// codepath's safety checks.
	InstanceID           string   `json:"-"` // parent instance ID, threaded server-side
	IsResume             bool     `json:"-"` // true when auto-resuming after restart
	ResumeQueueStatePath string   `json:"-"`
	ResumeActiveTarget   string   `json:"-"`
	ResumeScanDir        string   `json:"-"`
	ResumeScanID         string   `json:"-"`
	ResumeSubScanTarget  string   `json:"-"`
	ResumeSubScanDir     string   `json:"-"`
	ResumeSubScanID      string   `json:"-"`
	ResumeSubdomains     []string `json:"-"`
	ResumeSubIndex       int      `json:"-"`
	ResumeDiscoveryDone  bool     `json:"-"`
	ResumeOriginalTarget int      `json:"-"`

	// allowLoopbackPorts is the per-scan loopback allowlist the scope guard
	// honors (resolved server-side).
	allowLoopbackPorts []int `json:"-"`
}

// UnmarshalJSON accepts the canonical flat assessment fields documented by
// the assessment API, plus the nested form used by persisted schedule/queue
// records. Supplying both is rejected so the server never has to guess which
// configuration the operator intended.
func (req *ScanRequest) UnmarshalJSON(data []byte) error {
	type plainScanRequest ScanRequest
	var decoded plainScanRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	canonicalFields := false
	for _, name := range []string{"assessment_mode", "assessment_types", "assessment_targets", "access", "scanner_selection", "approved_origins", "exclusions", "test_environment", "discovery_providers", "manual_seeds"} {
		if _, ok := fields[name]; ok {
			canonicalFields = true
			break
		}
	}
	if canonicalFields && decoded.Assessment != nil {
		return errors.New("use either flat assessment fields or assessment, not both")
	}
	if canonicalFields {
		var cfg assessment.AssessmentConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			return err
		}
		cfg.Profile = decoded.Profile
		decoded.Assessment = &cfg
	}
	*req = ScanRequest(decoded)
	return nil
}

// WSEvent is a WebSocket message sent to clients.
type WSEvent struct {
	Type           string            `json:"type"`
	Content        string            `json:"content,omitempty"`
	ToolName       string            `json:"tool_name,omitempty"`
	ToolArgs       map[string]string `json:"tool_args,omitempty"`
	Output         string            `json:"output,omitempty"`
	Error          string            `json:"error,omitempty"`
	AgentID        string            `json:"agent_id,omitempty"`
	InstanceID     string            `json:"instance_id,omitempty"`
	Timestamp      string            `json:"timestamp,omitempty"`
	Vulns          []VulnSummary     `json:"vulns,omitempty"`
	TargetIndex    int               `json:"target_index,omitempty"`
	TotalTargets   int               `json:"total_targets,omitempty"`
	Target         string            `json:"target,omitempty"`
	TotalTokens    int               `json:"total_tokens,omitempty"`
	SubTargetIndex int               `json:"sub_target_index,omitempty"` // subdomain index within a wildcard target
	SubTargetTotal int               `json:"sub_target_total,omitempty"` // total subdomains for current wildcard target
	ParentTarget   string            `json:"parent_target,omitempty"`    // parent domain for subdomain scans
	CurrentPhase   int               `json:"current_phase,omitempty"`    // inferred active methodology phase
	Scanner        string            `json:"scanner,omitempty"`
	Stream         string            `json:"stream,omitempty"`
	Sequence       int64             `json:"sequence,omitempty"`
}

// VulnSummary is a simplified vulnerability for the UI.
type VulnSummary struct {
	ID                    string                    `json:"id"`
	Fingerprint           string                    `json:"fingerprint,omitempty"`
	NormalizedType        string                    `json:"normalized_type,omitempty"`
	DedupeScope           string                    `json:"dedupe_scope,omitempty"`
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
	Target                string                    `json:"target,omitempty"`
	Scope                 string                    `json:"scope,omitempty"` // scanner reports: host:<h> or source:main
	Endpoint              string                    `json:"endpoint"`
	CVSS                  float64                   `json:"cvss"`
	CVSSVector            string                    `json:"cvss_vector,omitempty"`
	Description           string                    `json:"description,omitempty"`
	Impact                string                    `json:"impact,omitempty"`
	Method                string                    `json:"method,omitempty"`
	Parameter             string                    `json:"parameter,omitempty"`
	CVE                   string                    `json:"cve,omitempty"`
	CWE                   string                    `json:"cwe_id,omitempty"`
	Confidence            string                    `json:"confidence,omitempty"`
	NativeConfidence      string                    `json:"native_confidence,omitempty"`
	EvidenceCompleteness  string                    `json:"evidence_completeness,omitempty"`
	OWASP                 string                    `json:"owasp,omitempty"`
	TechnicalAnalysis     string                    `json:"technical_analysis,omitempty"`
	PoCDescription        string                    `json:"poc_description,omitempty"`
	PoCScript             string                    `json:"poc_script,omitempty"`
	Remediation           string                    `json:"remediation,omitempty"`
	Fix                   string                    `json:"fix,omitempty"`
	ExploitationProof     string                    `json:"exploitation_proof,omitempty"`
	VerificationMethod    string                    `json:"verification_method,omitempty"`
	Verified              bool                      `json:"verified"`
	Tags                  []string                  `json:"tags,omitempty"`
}

// SubScanSummary is a child target scanned as part of a wildcard parent scan.
type SubScanSummary struct {
	ID          string `json:"id"`
	Target      string `json:"target"`
	StartedAt   string `json:"started_at,omitempty"`
	FinishedAt  string `json:"finished_at,omitempty"`
	Status      string `json:"status"`
	VulnCount   int    `json:"vuln_count"`
	TotalTokens int    `json:"total_tokens"`
}

// ScanRecord is a persisted scan result.
type ScanRecord struct {
	SchemaVersion            int                          `json:"schema_version,omitempty"`
	Assessment               *assessment.AssessmentConfig `json:"assessment,omitempty"`
	AssessmentPlan           *scanner.AssessmentPlan      `json:"assessment_plan,omitempty"`
	PlanFingerprint          string                       `json:"plan_fingerprint,omitempty"`
	Profile                  string                       `json:"profile,omitempty"`
	ID                       string                       `json:"id"`
	InstanceID               string                       `json:"instance_id,omitempty"` // parent queue/instance id returned by /api/scan
	Name                     string                       `json:"name,omitempty"`        // user-defined scan name
	Target                   string                       `json:"target"`
	ParentTarget             string                       `json:"parent_target,omitempty"` // parent domain for subdomain scans (wildcard mode)
	StartedAt                string                       `json:"started_at"`
	FinishedAt               string                       `json:"finished_at,omitempty"`
	Status                   string                       `json:"status"`                               // saved, running, finished, stopped
	StopReason               string                       `json:"stop_reason,omitempty"`                // why scan stopped (error, user, watchdog, etc.)
	ScanMode                 string                       `json:"scan_mode,omitempty"`                  // single, wildcard, dast
	Instruction              string                       `json:"instruction,omitempty"`                // custom scan instructions
	SeverityFilter           []string                     `json:"severity_filter,omitempty"`            // severity filter for scan
	Scanners                 []string                     `json:"scanners,omitempty"`                   // selected scanners (empty = whole pipeline)
	DiscordWebhook           string                       `json:"discord_webhook,omitempty"`            // discord notification webhook
	DiscordWebhookConfigured bool                         `json:"discord_webhook_configured,omitempty"` // true when a per-scan or global webhook is configured
	TelegramConfigured       bool                         `json:"telegram_configured,omitempty"`        // true when global Telegram notifications are configured (token never exposed)
	ReconMode                string                       `json:"recon_mode,omitempty"`                 // active or passive reconnaissance
	ScanIntensity            string                       `json:"scan_intensity,omitempty"`             // active or passive testing/scanning
	Events                   []WSEvent                    `json:"events"`
	Vulns                    []VulnSummary                `json:"vulns"`
	TotalTokens              int                          `json:"total_tokens"`
	Iterations               int                          `json:"iterations"`
	ToolCalls                int                          `json:"tool_calls"`
	CompanyName              string                       `json:"company_name,omitempty"` // report branding: company name
	LogoPath                 string                       `json:"logo_path,omitempty"`    // report branding: logo path
	Phases                   []int                        `json:"phases,omitempty"`       // selected methodology phases
	CurrentPhase             int                          `json:"current_phase,omitempty"`
	SubScans                 []SubScanSummary             `json:"sub_scans,omitempty"`
	SubScanTotal             int                          `json:"sub_scan_total,omitempty"`
	SubScanCompleted         int                          `json:"sub_scan_completed,omitempty"`
	SubScanRunning           int                          `json:"sub_scan_running,omitempty"`
	SubScanRemaining         int                          `json:"sub_scan_remaining,omitempty"`
	ScannerRuns              []scanner.Run                `json:"scanner_runs,omitempty"`
	Artifact                 scanner.Artifact             `json:"artifact,omitempty"`
	VulsSSHHost              string                       `json:"vuls_ssh_host,omitempty"`
	ReportMode               string                       `json:"report_mode,omitempty"`
	ReportGeneratedAt        string                       `json:"report_generated_at,omitempty"`
	// ReportScopes feeds the scanner report's coverage section and scope grouping.
	// It is derived at report time from ScannerRuns + recon-scopes.json and is
	// never persisted.
	ReportScopes             []reportScope               `json:"-"`
	ReportAssessmentCoverage *assessmentCoverageResponse `json:"-"`
}

// QueueState persists scan queue state for recovery after restart
type QueueState struct {
	Assessment            *assessment.AssessmentConfig `json:"assessment,omitempty"`
	PlanFingerprint       string                       `json:"plan_fingerprint,omitempty"`
	Profile               string                       `json:"profile,omitempty"`
	InstanceID            string                       `json:"instance_id,omitempty"`
	Targets               []string                     `json:"targets"`
	CurrentIdx            int                          `json:"current_idx"`
	Instruction           string                       `json:"instruction"`
	ScanMode              string                       `json:"scan_mode"`
	StartedAt             string                       `json:"started_at"`
	Active                bool                         `json:"active"`
	Name                  string                       `json:"name,omitempty"`
	SeverityFilter        []string                     `json:"severity_filter,omitempty"`
	Scanners              []string                     `json:"scanners,omitempty"`
	Phases                []int                        `json:"phases,omitempty"`
	ReconMode             string                       `json:"recon_mode,omitempty"`
	ScanIntensity         string                       `json:"scan_intensity,omitempty"`
	CompanyName           string                       `json:"company_name,omitempty"`
	LogoPath              string                       `json:"logo_path,omitempty"`
	DiscordWebhook        string                       `json:"discord_webhook,omitempty"`
	Paused                bool                         `json:"paused,omitempty"`
	ActiveTarget          string                       `json:"active_target,omitempty"`
	ActiveScanDir         string                       `json:"active_scan_dir,omitempty"`
	ActiveScanID          string                       `json:"active_scan_id,omitempty"`
	WildcardActiveTarget  string                       `json:"wildcard_active_target,omitempty"`
	WildcardActiveScanDir string                       `json:"wildcard_active_scan_dir,omitempty"`
	WildcardActiveScanID  string                       `json:"wildcard_active_scan_id,omitempty"`
	WildcardDiscoveryDone bool                         `json:"wildcard_discovery_done,omitempty"`
	WildcardSubdomains    []string                     `json:"wildcard_subdomains,omitempty"`
	WildcardSubIndex      int                          `json:"wildcard_sub_index,omitempty"`
	Artifact              scanner.Artifact             `json:"artifact,omitempty"`
	VulsSSHHost           string                       `json:"vuls_ssh_host,omitempty"`
}

// ScanInstance represents a running or completed scan instance.
type ScanInstance struct {
	Assessment      *assessment.AssessmentConfig `json:"assessment,omitempty"`
	PlanFingerprint string                       `json:"plan_fingerprint,omitempty"`
	Profile         string                       `json:"profile,omitempty"`
	ID              string                       `json:"id"`
	Name            string                       `json:"name,omitempty"` // user-defined scan name
	Targets         string                       `json:"targets"`
	ParentTarget    string                       `json:"parent_target,omitempty"` // parent domain for subdomain scans
	Status          string                       `json:"status"`                  // saved, running, paused, finished, stopped
	StartedAt       string                       `json:"started_at"`
	FinishedAt      string                       `json:"finished_at,omitempty"`
	StopReason      string                       `json:"stop_reason,omitempty"` // why stopped (user, error, watchdog)
	Iterations      int                          `json:"iterations"`
	ToolCalls       int                          `json:"tool_calls"`
	VulnCount       int                          `json:"vuln_count"`
	TotalTokens     int                          `json:"total_tokens"`
	ScanMode        string                       `json:"scan_mode"`
	Instruction     string                       `json:"instruction,omitempty"`     // custom scan instructions for restart
	SeverityFilter  []string                     `json:"severity_filter,omitempty"` // severity filter for restart
	Scanners        []string                     `json:"scanners,omitempty"`        // selected scanners for restart (empty = all)
	Phases          []int                        `json:"phases,omitempty"`          // selected methodology phases (empty = all)
	ReconMode       string                       `json:"recon_mode,omitempty"`      // active or passive reconnaissance
	ScanIntensity   string                       `json:"scan_intensity,omitempty"`  // active or passive testing/scanning
	CompanyName     string                       `json:"company_name,omitempty"`    // report branding: company name
	LogoPath        string                       `json:"logo_path,omitempty"`       // report branding: logo path
	DiscordWebhook  string                       `json:"-"`                         // discord webhook (not exposed to API)
	// Per-scan auth/whitebox/context, restored when a saved scan is started.
	// Kept in-memory only (json:"-", like DiscordWebhook) so third-party
	// credentials and token-bearing source URLs are never written to the
	// on-disk instance record or exposed via the API. Survives save→start
	// within the running process; a process restart drops them (the operator
	// re-enters auth), which is the safe default for secrets.
	TargetAuth          string           `json:"-"`
	TargetAuthSecondary string           `json:"-"`
	SourceRepo          string           `json:"-"`
	ScanContext         string           `json:"-"`
	Vulns               []VulnSummary    `json:"vulns,omitempty"`
	CurrentPhase        int              `json:"current_phase,omitempty"`
	ScannerRuns         []scanner.Run    `json:"scanner_runs,omitempty"`
	Artifact            scanner.Artifact `json:"artifact,omitempty"`
	VulsSSHHost         string           `json:"vuls_ssh_host,omitempty"`
	cancel              context.CancelFunc
	scanDir             string
	sctx                *scanctx.ScanContext // per-instance session state (vulns)
	events              []WSEvent            // buffered events for replay
	mu                  sync.RWMutex
}

// maxConcurrentInstances removed — replaced by dynamic resource-aware
// admission via resources.CanAdmitScan(). See internal/resources/.

type queueProgress struct {
	ActiveTarget          string
	ActiveScanDir         string
	ActiveScanID          string
	WildcardActiveTarget  string
	WildcardActiveScanDir string
	WildcardActiveScanID  string
	WildcardDiscoveryDone bool
	WildcardSubdomains    []string
	WildcardSubIndex      int
}

// dashboardRoutes lists every URL pattern the dashboard mux
// registers in NewServer.Start. It exists primarily as a test
// surface so that the test in internal/web asserting
// `/oauth/callback` is NOT mounted on the dashboard mux (R13.3)
// has a single source of truth to consult — without it, that
// invariant would have to be re-derived from the call sites in
// Start every time the route surface changes.
//
// The slice is updated in lockstep with the mux.HandleFunc /
// mux.Handle calls inside Server.Start; if a route is added or
// removed there, the slice should be updated to match.
//
// Validates: Requirement 13.3 ("never registers `/oauth/callback`
// on the dashboard mux"), Requirement 15.2 (existing routes
// preserved unchanged).
var dashboardRoutes = []string{
	// Static + WebSocket roots (registered as catch-all and "/ws").
	"/",
	"/ws",

	// Existing scan / status / report / settings surface (unchanged).
	"/api/scan",
	"/api/stop",
	"/api/restart",
	"/api/status",
	"/api/legacy-import/status",
	"/api/scans",
	"/api/scans/",
	"/api/data-dirs/",
	"/api/schedules",
	"/api/schedules/",
	"/api/upload-targets",
	"/api/upload-logo",
	"/api/upload-context",
	"/api/findings",
	"/api/findings/projects",
	"/api/findings/summary",
	"/uploads/logos/",
	"/api/report/",
	"/api/reports/",
	"/api/scanners/status",
	"/api/scanners/registry",
	"/api/scans/plan",
	"/api/credentials",
	"/api/credentials/",
	"/api/api-definitions",
	"/api/api-fixtures",
	"/api/api-fixtures/",
	"/api/settings/rate-limit",
	"/api/settings/environment",
	"/api/queue/status",
	"/api/queue/resume",
	"/api/queue/clear",
	"/api/version",
	"/api/instances",
	"/api/instances/",
	"/api/monitoring/",

	// Dashboard auth (login/logout/status).
	"/api/auth/login",
	"/api/auth/logout",
	"/api/auth/status",
}

// Server is the web UI server.
type Server struct {
	cfg              *config.Config
	port             int
	clients          map[*wsClient]bool
	mu               sync.RWMutex
	scannerControlMu sync.Mutex
	scannerCancels   map[string]context.CancelFunc
	cancelScan       context.CancelFunc // cancels the current scan session context
	running          atomic.Bool
	stopReq          atomic.Bool
	restartWhenIdle  atomic.Bool  // SIGUSR1 sets this; a watcher restarts once scans drain
	httpServer       *http.Server // set in Start; used to trigger graceful restart from the API
	// forceRestartFn performs an immediate restart for POST /api/restart?force=true.
	// nil in production (the handler re-execs via restartNow); tests set it to a
	// stub so the force path can be exercised without exec'ing the process.
	forceRestartFn       func()
	dataDir              string
	currentScanDir       string
	currentScanID        string
	discordWebhook       string
	discordMinSeverity   string // minimum severity to send to Discord ("info", "low", "medium", "high", "critical")
	telegramBotToken     string // XALGORIX_TELEGRAM_BOT_TOKEN (secret, never exposed via API)
	telegramChatID       string // XALGORIX_TELEGRAM_CHAT_ID (numeric ID or @channelusername)
	telegramMinSeverity  string // minimum severity to send to Telegram ("info", "low", "medium", "high", "critical")
	rateLimiter          *RateLimiter
	settingsMu           sync.Mutex
	instances            map[string]*ScanInstance // concurrent scan instances
	instancesMu          sync.RWMutex
	queueResumeMu        sync.Mutex
	queueResumeLaunching map[string]bool
	schedulesMu          sync.RWMutex
	schedules            map[string]*ScanSchedule
	shutdownChan         chan struct{}
	// scanListCache memoizes the built GET /api/scans list for a few seconds
	// so paging/filtering/polling don't each re-walk the whole data dir.
	scanListCacheMu sync.Mutex
	scanListCache   []scanListItem
	scanListCacheAt time.Time
	// scanSummaryCache memoizes the per-file parsed (events-free) scan record
	// keyed by file path. Finished scans' scan.json files are immutable, so
	// after the first parse they are reused across walks without re-reading or
	// re-parsing. Entries are validated by (modtime, size) so a running scan
	// whose file changes is re-parsed. See findAllScanSummaries.
	scanSummaryCacheMu sync.Mutex
	scanSummaryCache   map[string]scanSummaryCacheEntry
	// admissionWake is a buffered (len=1) channel used by runMultiScan's
	// admission loop to wait fairly for a freed slot. A scan instance ending
	// signals this channel non-blockingly in its defer cleanup, waking
	// exactly one waiter per terminate. The 2-second ticker in the loop is
	// retained as a safety-net so we still re-check periodically if a wake
	// signal is missed for any reason. (R3.2, R3.6 / Property 5.)
	admissionWake chan struct{}

	// legacyImportCount is the number of scan records imported from the
	// pre-migration directory (~/xalgorix-data/) into the active dataDir
	// on the current server start. It is set once by importLegacyDataDir
	// and surfaced via /api/legacy-import/status so the WebUI can render
	// a one-time banner. Not persisted; resets to 0 each restart.
	// legacyImportDismissed flips to true when the WebUI dismisses the
	// banner; only valid for the current process lifetime.
	// Guarded by legacyImportMu so the short banner-status reads/writes
	// don't contend with the WebSocket-clients lock (s.mu).
	// (See findings-consistency-and-pagination spec, Property 6.)
	legacyImportMu        sync.RWMutex
	legacyImportCount     int
	legacyImportDismissed bool

	// toolVersions caches the build-time content manifest's tool/template
	// versions, read once at start and hashed into every plan fingerprint.
	// nil (tests building a bare Server) fingerprints like an empty map.
	toolVersions map[string]string
}

// NewServer creates a new web server.
func NewServer(cfg *config.Config, port int) *Server {
	// The active Data_Dir is owned by config.resolveDataDir (R6.1, R6.3) and
	// already canonicalized + created with mode 0o700 before we get here.
	// The Web_Server is a downstream consumer; it must NOT re-derive a data
	// root from $HOME or $CWD (Task 3.6 / R6.4 / R6.6) — doing so would
	// silently bypass XALGORIX_DATA_DIR and resurrect the legacy
	// ~/xalgorix-data location.
	dataDir := cfg.DataDir
	// Rate limit from config (defaults: 60 requests per minute)
	rl := NewRateLimiter(cfg.RateLimitRequests, time.Duration(cfg.RateLimitWindow)*time.Second)

	srv := &Server{
		cfg:                  cfg,
		port:                 port,
		clients:              make(map[*wsClient]bool),
		scannerCancels:       make(map[string]context.CancelFunc),
		dataDir:              dataDir,
		discordWebhook:       cfg.DiscordWebhook,
		discordMinSeverity:   strings.ToLower(strings.TrimSpace(cfg.DiscordMinSeverity)),
		telegramBotToken:     cfg.TelegramBotToken,
		telegramChatID:       cfg.TelegramChatID,
		telegramMinSeverity:  strings.ToLower(strings.TrimSpace(cfg.TelegramMinSeverity)),
		rateLimiter:          rl,
		instances:            make(map[string]*ScanInstance),
		queueResumeLaunching: make(map[string]bool),
		schedules:            make(map[string]*ScanSchedule),
		shutdownChan:         make(chan struct{}),
		// Buffered to length 1 so a non-blocking send from a terminating
		// scan never blocks; the buffered slot guarantees a wake signal
		// is delivered to whichever waiter is currently parked in the
		// admission select.
		admissionWake: make(chan struct{}, 1),
		toolVersions:  loadToolVersions(contentManifestPath()),
	}

	// Import legacy data dir (pre-migration ~/xalgorix-data/) into the
	// active dataDir on first start. Idempotent (sentinel-gated) and
	// non-fatal — failures are logged and the server still starts. Must
	// run BEFORE rebuildInstancesFromDisk so imported scans appear in
	// the dashboard immediately.
	imported, ierr := srv.importLegacyDataDir()
	if ierr != nil {
		log.Printf("[legacy-import] error: %v (continuing)", ierr)
	}
	srv.legacyImportCount = imported
	srv.legacyImportDismissed = false

	// Rebuild instances map from disk so dashboard shows historical scans on startup
	srv.rebuildInstancesFromDisk()

	// Load schedules from disk
	srv.loadSchedulesFromDisk()

	return srv
}

func (s *Server) hasPendingOrRunningInstance() bool {
	s.instancesMu.RLock()
	defer s.instancesMu.RUnlock()
	for _, inst := range s.instances {
		inst.mu.RLock()
		active := inst.Status == "pending" || inst.Status == "running"
		inst.mu.RUnlock()
		if active {
			return true
		}
	}
	return false
}

func (s *Server) hasQueueResumeLaunchingLocked() bool {
	return len(s.queueResumeLaunching) > 0
}

func (s *Server) markQueueResumeLaunchingLocked(key string) {
	key = strings.TrimSpace(key)
	if key == "" {
		key = "legacy"
	}
	if s.queueResumeLaunching == nil {
		s.queueResumeLaunching = make(map[string]bool)
	}
	s.queueResumeLaunching[key] = true
}

func (s *Server) clearQueueResumeLaunching(key string) {
	key = strings.TrimSpace(key)
	if key == "" {
		key = "legacy"
	}
	s.queueResumeMu.Lock()
	delete(s.queueResumeLaunching, key)
	s.queueResumeMu.Unlock()
}

func queueResumeEntryKey(entry queueStateEntry) string {
	if entry.state != nil && strings.TrimSpace(entry.state.InstanceID) != "" {
		return strings.TrimSpace(entry.state.InstanceID)
	}
	if entry.path != "" {
		return filepath.Clean(entry.path)
	}
	return "legacy"
}

// Start launches the web server.
func (s *Server) Start() error {
	s.initDataDir()

	// Start the background scheduler
	go s.startScheduler()

	// Start the scan-retention sweeper. It self-disables (returns
	// immediately) when XALGORIX_SCAN_RETENTION_DAYS is 0, so this is a
	// no-op for installs that want to keep scans forever.
	go s.startRetentionSweeper()

	// Reap expired session cookies in the background so the auth map cannot
	// grow unbounded from abandoned logins.
	if authConfigured(s.cfg) {
		startSessionReaper()
	}

	// Auto-start Caido proxy in background if available
	startCaidoProxy()

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return fmt.Errorf("failed to load static files: %w", err)
	}

	mux := http.NewServeMux()
	// SPA handler: serve static files if they exist, otherwise serve index.html
	fileServer := http.FileServer(http.FS(staticFS))
	// fs.Sub on embed.FS returns an fs.FS that does implement ReadFileFS today,
	// but assert with comma-ok so a future runtime change can't crash the server.
	rfs, hasRfs := staticFS.(fs.ReadFileFS)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		setWebUICacheHeaders(w)
		// Try to serve the static file
		path := r.URL.Path
		if path == "/" {
			fileServer.ServeHTTP(w, r)
			return
		}
		// Check if it's a real static file. Vite serves assets from the
		// static root (/app.js, /style.css, /chunks/...), while older builds
		// may request /static/app.js. staticFS already points at that root.
		strippedPath := strings.TrimPrefix(path, "/")
		strippedPath = strings.TrimPrefix(strippedPath, "static/")
		if hasRfs {
			if f, err := rfs.ReadFile(strippedPath); err == nil && f != nil {
				// Rewrite URL to serve from staticFS root (which is already "static")
				r.URL.Path = "/" + strippedPath
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		// Known static asset paths that didn't resolve to a real file are
		// genuine 404s. App routes may contain dots in path params (for
		// example scan ids derived from hostnames), so don't treat every
		// dotted path as a file.
		if isStaticWebAssetPath(path) {
			http.NotFound(w, r)
			return
		}
		// Not a static file — serve index.html (SPA catch-all)
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
	mux.HandleFunc("/ws", s.handleWebSocket)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/stop", s.handleStop)
	mux.HandleFunc("/api/restart", s.handleRestart)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/legacy-import/status", s.handleLegacyImportStatus)
	mux.HandleFunc("/api/scans", s.handleListScans)
	mux.HandleFunc("/api/scans/plan", s.handleAssessmentPlan)
	mux.HandleFunc("/api/scans/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/endpoints/") && strings.HasSuffix(r.URL.Path, "/trace") {
			s.handleEndpointTrace(w, r)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/discovery") {
			s.handleDiscoveryRevision(w, r)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/stop") && strings.Contains(r.URL.Path, "/runs/") {
			s.handleStopScannerRun(w, r)
			return
		}
		if isFindingsRoutePath(r.URL.Path) {
			s.handleFindingsAPI(w, r)
			return
		}
		if r.Method == http.MethodGet && isScanAttackSurfacePath(r.URL.Path) {
			s.handleAttackSurface(w, r)
			return
		}
		if r.Method == http.MethodGet && isScanScopesPath(r.URL.Path) {
			s.handleScanScopes(w, r)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/coverage/items") {
			s.handleCoverageItems(w, r)
			return
		}
		if isScanCoveragePath(r.URL.Path) {
			s.handleAssessmentCoverage(w, r)
			return
		}
		if strings.Contains(r.URL.Path, "/output/") || strings.HasSuffix(r.URL.Path, "/artifact") {
			s.handleScannerOutput(w, r)
			return
		}
		if strings.Contains(r.URL.Path, "/vulns/") && r.Method == http.MethodDelete {
			s.handleDeleteVuln(w, r)
			return
		}
		s.handleGetScan(w, r)
	})
	// DELETE /api/data-dirs/{name} — delete one top-level Scan_Folder under
	// Data_Dir. Distinct prefix from /api/scans/ (no collision, R5.3); inherits
	// authMiddleware + CSRF and stays subject to rate limiting as a mutating
	// route (intentionally NOT added to isDashboardReadPath). R5.1, R5.2.
	mux.HandleFunc("/api/data-dirs/", s.handleDeleteDataDir)
	mux.HandleFunc("/api/schedules", s.handleSchedules)
	mux.HandleFunc("/api/schedules/", s.handleScheduleDetail)
	mux.HandleFunc("/api/upload-targets", s.handleUploadTargets)
	mux.HandleFunc("/api/upload-logo", s.handleUploadLogo)
	mux.HandleFunc("/api/upload-context", s.handleUploadContext)
	// Findings surface (read-only). Handlers exist independently of the
	// /api/scans/ dispatcher; register them explicitly so the SPA's
	// findings table + severity summary resolve to real JSON instead of
	// falling through to the static catch-all.
	mux.HandleFunc("/api/findings", s.handleFindingsList)
	mux.HandleFunc("/api/findings/projects", s.handleFindingsProjects)
	mux.HandleFunc("/api/findings/summary", s.handleFindingsSummary)
	// Serve uploaded logos
	logosDir := filepath.Join(s.dataDir, "logos")
	_ = os.MkdirAll(logosDir, 0700)
	mux.Handle("/uploads/logos/", http.StripPrefix("/uploads/logos/", http.FileServer(http.Dir(logosDir))))
	mux.HandleFunc("/api/report/", s.handleDownloadReport)
	mux.HandleFunc("/api/reports/", s.handleReportAction)
	mux.HandleFunc("/api/scanners/status", s.handleScannerStatus)
	mux.HandleFunc("/api/scanners/registry", s.handleScannerRegistry)
	mux.HandleFunc("/api/credentials", s.handleCredentials)
	mux.HandleFunc("/api/credentials/", s.handleCredentialDetail)
	mux.HandleFunc("/api/api-definitions", s.handleAPIDefinitions)
	mux.HandleFunc("/api/api-fixtures", s.handleAPIFixtures)
	mux.HandleFunc("/api/api-fixtures/", s.handleAPIFixture)
	mux.HandleFunc("/api/settings/rate-limit", s.handleRateLimit)
	mux.HandleFunc("/api/settings/environment", s.handleEnvironmentSettings)
	mux.HandleFunc("/api/queue/status", s.handleQueueStatus)
	mux.HandleFunc("/api/queue/resume", s.handleQueueResume)
	mux.HandleFunc("/api/queue/clear", s.handleQueueClear)
	mux.HandleFunc("/api/version", s.handleVersion)
	mux.HandleFunc("/api/instances", s.handleInstances)
	mux.HandleFunc("/api/instances/", s.handleInstanceAction)
	mux.HandleFunc("/api/monitoring/", s.handleMonitoring)

	// Auth routes (these are public — authMiddleware skips them)
	mux.HandleFunc("/api/auth/login", s.handleLogin)
	mux.HandleFunc("/api/auth/logout", s.handleLogout)
	mux.HandleFunc("/api/auth/status", s.handleAuthStatus)

	// Wrap with auth middleware (outermost) then rate limiting
	authMw := authMiddleware(s.cfg)
	rlMiddleware := rateLimitMiddleware(s.rateLimiter)

	// Bind to a specific interface. Default is 127.0.0.1 (loopback) so a
	// fresh install isn't exposed to the network. Operators who want
	// external access set XALGORIX_BIND=0.0.0.0 explicitly — and in that
	// case auth MUST be configured or we refuse to start. This is a
	// deliberate safety choice: the dashboard can launch arbitrary scans
	// and a chat tool with the LLM, so an open port is a control plane.
	bindAddr := s.cfg.BindAddr
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}
	isLoopback := bindAddr == "127.0.0.1" || bindAddr == "::1" || bindAddr == "localhost"
	if !isLoopback && !authConfigured(s.cfg) {
		return fmt.Errorf(
			"refusing to bind to non-loopback address %q without auth: set XALGORIX_USERNAME and either XALGORIX_PASSWORD_HASH (bcrypt) or XALGORIX_PASSWORD in ~/.xalgorix.env, or set XALGORIX_BIND=127.0.0.1",
			bindAddr,
		)
	}
	addr := fmt.Sprintf("%s:%d", bindAddr, s.port)
	if isLoopback {
		log.Printf("Xalgorix Web UI → http://%s:%d (loopback only)", bindAddr, s.port)
	} else {
		log.Printf("Xalgorix Web UI → http://%s:%d (NETWORK-EXPOSED)", bindAddr, s.port)
	}
	log.Printf("Scan data → %s", s.dataDir)
	log.Printf("Rate limiting: %d requests/%ds per IP", s.cfg.RateLimitRequests, s.cfg.RateLimitWindow)
	if authConfigured(s.cfg) {
		authMode := "plaintext"
		if s.cfg.PasswordHash != "" {
			authMode = "bcrypt"
		}
		log.Printf("Authentication enabled (user: %s, password: %s)", s.cfg.Username, authMode)
	} else {
		log.Printf("Authentication disabled — listening on loopback only. Set XALGORIX_USERNAME and XALGORIX_PASSWORD_HASH in ~/.xalgorix.env to enable.")
	}

	// ── Auto-resume interrupted scan queue after short startup delay ──
	// Gate the resume on no scan having started in the meantime — without
	// this, a user request arriving in the first 5 seconds would race with
	// the auto-resume goroutine and both runMultiScan calls would stomp
	// on the same cancelScan field.
	go func() {
		time.Sleep(5 * time.Second) // let HTTP server fully initialize
		s.queueResumeMu.Lock()
		defer s.queueResumeMu.Unlock()
		if s.running.Load() || s.hasPendingOrRunningInstance() || s.hasQueueResumeLaunchingLocked() {
			log.Printf("[AUTO-RESUME] Skipping — a scan is already pending or running.")
			return
		}
		entries := autoResumeQueueEntries(s.validQueueStateEntries(true))
		if len(entries) == 0 {
			return
		}
		log.Printf("[AUTO-RESUME] Resuming %d interrupted scan queue(s)", len(entries))
		for _, entry := range entries {
			req := scanRequestFromQueueState(entry.state, entry.path)
			if len(req.Targets) == 0 {
				continue
			}
			instanceID := entry.state.InstanceID
			log.Printf("[AUTO-RESUME] Resuming interrupted scan queue %s: %d targets from index %d", instanceID, len(req.Targets), entry.state.CurrentIdx)
			scanCfg := *s.cfg
			resumeKey := queueResumeEntryKey(entry)
			s.markQueueResumeLaunchingLocked(resumeKey)
			go func(req ScanRequest, scanCfg config.Config, instanceID, resumeKey string) {
				defer s.clearQueueResumeLaunching(resumeKey)
				s.runMultiScan(req, &scanCfg, instanceID)
			}(req, scanCfg, instanceID, resumeKey)
		}
	}()

	// ── Graceful shutdown on SIGTERM/SIGINT ──
	httpServer := &http.Server{
		Addr: addr,
		// safe.HTTPMiddleware MUST be the outermost wrapper so it catches
		// panics from every layer below it (auth, rate-limit, mux,
		// individual handlers). On panic it increments PanicsRecovered,
		// emits a structured log line with stack trace, and returns 500.
		Handler: safe.HTTPMiddleware(authMw(rlMiddleware(mux))),
		// Bound the time spent reading request headers so a slow client
		// cannot hold a connection open indefinitely (Slowloris). The
		// dashboard serves interactive traffic, so keep this generous.
		ReadHeaderTimeout: 30 * time.Second,
	}
	// Expose the server so the /api/restart handler can trigger a graceful
	// restart-when-idle through the same path as the SIGUSR1 watcher.
	s.httpServer = httpServer

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
		sig := <-sigCh
		log.Printf("[SHUTDOWN] Received signal %s — saving state and shutting down gracefully", sig)

		// Stop the background scheduler
		close(s.shutdownChan)

		// Stop all running scans so they save queue state
		s.stopReq.Store(true)
		s.mu.Lock()
		if s.cancelScan != nil {
			s.cancelScan()
		}
		s.mu.Unlock()

		// Stop all instances
		s.instancesMu.RLock()
		for _, inst := range s.instances {
			inst.mu.Lock()
			if inst.Status == "running" {
				inst.Status = "stopped"
				inst.StopReason = "signal_" + sig.String()
				inst.FinishedAt = time.Now().Format(time.RFC3339)
			}
			inst.mu.Unlock()
		}
		s.instancesMu.RUnlock()

		// Send Discord notification. Use sig.String() explicitly so we get
		// "terminated"/"interrupt" rather than a numeric fallback for any
		// os.Signal implementation that doesn't satisfy fmt.Stringer.
		if s.discordWebhook != "" {
			s.sendDiscord(0xff6b6b, "🔄 Xalgorix Restarting", fmt.Sprintf("Service received %s signal. Saving state and restarting.\nInterrupted scans will auto-resume.", sig.String()))
		}
		if s.telegramConfigured() {
			s.sendTelegram(0xff6b6b, "🔄 Xalgorix Restarting", fmt.Sprintf("Service received %s signal. Saving state and restarting.\nInterrupted scans will auto-resume.", sig.String()))
		}

		// Give scans a moment to save their queue state
		time.Sleep(2 * time.Second)

		// Graceful HTTP shutdown (5s deadline for in-flight requests)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Printf("[SHUTDOWN] HTTP shutdown error: %v", err)
		}

		s.rateLimiter.Stop()
		log.Printf("[SHUTDOWN] Graceful shutdown complete")
	}()

	// ── Graceful restart-when-idle on SIGUSR1 ──
	// `xalgorix --restart-when-idle` sends SIGUSR1 to this process. We do not
	// restart immediately: a watcher waits until no scan instance is active
	// and no tool process is leased, then restarts cleanly (so in-flight
	// engagements are never interrupted).
	go func() {
		usrCh := make(chan os.Signal, 1)
		signal.Notify(usrCh, syscall.SIGUSR1)
		for range usrCh {
			if !s.scheduleGracefulRestart() {
				log.Printf("[RESTART] Graceful restart already pending — ignoring duplicate SIGUSR1")
			}
		}
	}()

	err = httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil // graceful shutdown
	}
	return err
}

// scheduleGracefulRestart marks the server for a restart-when-idle and starts
// the watcher that performs the restart once no scan/instance is active. It is
// the shared entry point for both the SIGUSR1 signal and the POST /api/restart
// endpoint. Returns false if a restart was already pending (idempotent), so
// duplicate requests don't spawn multiple watchers.
func (s *Server) scheduleGracefulRestart() bool {
	if s.restartWhenIdle.Swap(true) {
		return false
	}
	log.Printf("[RESTART] Graceful restart requested — will restart once all scans finish")
	if s.discordWebhook != "" {
		s.sendDiscord(0x4dabf7, "🕓 Xalgorix Restart Scheduled",
			"A restart was requested. Xalgorix will restart automatically once all running scans finish and no tools are active.")
	}
	if s.telegramConfigured() {
		s.sendTelegram(0x4dabf7, "🕓 Xalgorix Restart Scheduled",
			"A restart was requested. Xalgorix will restart automatically once all running scans finish and no tools are active.")
	}
	go s.restartWhenIdleWatcher(s.httpServer)
	return true
}

// scannerIdle reports whether it is safe to restart: no scan instance is// active (running/pending/paused/queued/starting) and no terminal tool is
// currently leased. Completed/stopped/failed instances are historical and
// do not block a restart.
func (s *Server) scannerIdle() bool {
	s.instancesMu.RLock()
	for _, inst := range s.instances {
		inst.mu.RLock()
		st := strings.ToLower(strings.TrimSpace(inst.Status))
		inst.mu.RUnlock()
		switch st {
		case "running", "pending", "paused", "queued", "starting":
			s.instancesMu.RUnlock()
			return false
		}
	}
	s.instancesMu.RUnlock()
	if s.running.Load() {
		return false
	}
	if resources.Capacity().ActiveToolLeases > 0 {
		return false
	}
	return true
}

// restartWhenIdleWatcher polls scanner state after a SIGUSR1 request and
// triggers a restart once the scanner has been idle for a few consecutive
// checks (debounced so a brief gap between queued targets does not trigger an
// early restart).
func (s *Server) restartWhenIdleWatcher(httpServer *http.Server) {
	const interval = 5 * time.Second
	const idleChecksNeeded = 3 // ~15s of sustained idle before restarting
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	idleStreak := 0
	for range ticker.C {
		if !s.restartWhenIdle.Load() {
			return // request was cleared elsewhere
		}
		if s.scannerIdle() {
			idleStreak++
			if idleStreak >= idleChecksNeeded {
				s.restartNow(httpServer)
				return
			}
		} else {
			idleStreak = 0
		}
	}
}

// restartNow performs the actual restart. Under systemd (Restart=always) a
// clean exit is enough — systemd re-runs ExecStart, reloading the env file.
// Outside systemd (background mode) we re-exec the binary in place so the
// service comes back without an external supervisor. Either path also picks
// up a newly-installed binary on disk.
func (s *Server) restartNow(httpServer *http.Server) {
	log.Printf("[RESTART] Scanner idle — restarting now")
	if s.discordWebhook != "" {
		s.sendDiscord(0x4dabf7, "🔄 Xalgorix Restarting", "Scanner is idle. Restarting now; interrupted work (if any) auto-resumes.")
	}
	if s.telegramConfigured() {
		s.sendTelegram(0x4dabf7, "🔄 Xalgorix Restarting", "Scanner is idle. Restarting now; interrupted work (if any) auto-resumes.")
	}

	// Release the listening socket so the restarted process can rebind.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if httpServer != nil {
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Printf("[RESTART] HTTP shutdown error: %v", err)
		}
	}

	// systemd-managed: INVOCATION_ID is set by systemd for service units.
	// A clean exit triggers Restart=always with a freshly-loaded env file.
	if os.Getenv("INVOCATION_ID") != "" {
		log.Printf("[RESTART] Exiting for systemd to restart (fresh environment)")
		os.Exit(0)
	}

	// Background mode: re-exec in place.
	exe, err := os.Executable()
	if err != nil || strings.TrimSpace(exe) == "" {
		exe = os.Args[0]
	}
	log.Printf("[RESTART] Re-executing %s", exe)
	if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil {
		log.Printf("[RESTART] re-exec failed: %v — exiting for supervisor restart", err)
		os.Exit(0)
	}
}

// initDataDir is a thin wrapper around cfg.DataDir (Task 3.6 / R6.4, R6.6):
// the directory is already canonicalized and created with mode 0o700 by
// config.resolveDataDir at startup, so the MkdirAll below is belt-and-
// suspenders — it covers the narrow window where a test or operator
// removes the directory between config load and Server.Start. The
// function's real job is the per-startup cleanup of stale scan dirs and
// the surfacing of any interrupted scan queues for auto-resume.
func (s *Server) initDataDir() {
	if err := os.MkdirAll(s.dataDir, 0o700); err != nil {
		log.Printf("Error: failed to create data directory %s: %v", s.dataDir, err)
	}

	// Cleanup scans older than 30 days
	entries, _ := os.ReadDir(s.dataDir)
	cutoff := time.Now().AddDate(0, 0, -30)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// Explicitly skip folder names starting with '_' or named 'logos'
		if strings.HasPrefix(e.Name(), "_") || e.Name() == "logos" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.RemoveAll(filepath.Join(s.dataDir, e.Name()))
			log.Printf("Cleaned up old scan: %s", e.Name())
		}
	}

	// Check for interrupted queues — will auto-resume after server starts
	if entries := s.validQueueStateEntries(true); len(entries) > 0 {
		remaining := 0
		for _, entry := range entries {
			remaining += len(entry.state.Targets) - entry.state.CurrentIdx
		}
		log.Printf("Found %d interrupted scan queue(s): %d targets remaining (will auto-resume in 5s)", len(entries), remaining)
	}
}

// planHasRunnableJobs reports whether starting the plan would attempt any job.
// Conditional jobs (a repository clone, a local path or image check) are
// prepared at run time and record a reason if preparation fails, so a
// source-only assessment made only of conditional jobs is runnable.
func planHasRunnableJobs(plan scanner.AssessmentPlan) bool {
	for _, job := range plan.Jobs {
		if job.State == scanner.PlanSelected || job.State == scanner.PlanConditional {
			return true
		}
	}
	return false
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Assessment != nil {
		normalizedAssessment := assessment.Normalize(*req.Assessment)
		req.Assessment = &normalizedAssessment
		for _, problem := range assessment.Validate(*req.Assessment) {
			if problem.Blocking {
				http.Error(w, problem.Message, http.StatusBadRequest)
				return
			}
		}
		if req.Profile != "" && req.Assessment.Profile != "" && req.Profile != req.Assessment.Profile {
			http.Error(w, "profile conflicts with assessment.profile", http.StatusBadRequest)
			return
		}
		if req.Profile == "" {
			req.Profile = req.Assessment.Profile
		}
		canonicalTargets := make([]string, 0, len(req.Assessment.Targets))
		for _, target := range req.Assessment.Targets {
			canonicalTargets = append(canonicalTargets, target.Value)
		}
		if len(req.Targets) == 0 {
			req.Targets = canonicalTargets
		} else if !slices.Equal(req.Targets, canonicalTargets) {
			http.Error(w, "targets conflict with assessment_targets", http.StatusBadRequest)
			return
		}
	}

	// Schema v2 accepts "dast" only as a compatibility alias. Source inputs
	// are deterministic Trivy artifacts; arbitrary AI build/provision mode is
	// intentionally unsupported.
	if req.ScanMode == "dast" {
		req.ScanMode = "single"
	}
	if req.ScanMode == "" {
		req.ScanMode = "single"
	}
	if req.ScanMode != "single" && req.ScanMode != "wildcard" {
		http.Error(w, "scan_mode must be single or wildcard", http.StatusBadRequest)
		return
	}
	if req.Profile == "" {
		req.Profile = scanner.ProfileGentle
	}
	if _, ok := scanner.ResolveWebProfile(req.Profile); !ok {
		http.Error(w, "profile must be web-gentle or web-thorough", http.StatusBadRequest)
		return
	}
	if req.Assessment != nil {
		req.Assessment.Profile = req.Profile
		workflowConfig := newAssessmentWorkflowConfig(*req.Assessment)
		req.Assessment = &workflowConfig
		plan := s.buildAssessmentPlanForScan(*req.Assessment, req.allowLoopbackPorts)
		if len(plan.Errors) > 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnprocessableEntity)
			_ = json.NewEncoder(w).Encode(plan)
			return
		}
		if !req.SaveOnly && strings.TrimSpace(req.PlanFingerprint) == "" {
			http.Error(w, "plan_fingerprint from a current assessment preview is required to start", http.StatusBadRequest)
			return
		}
		if req.PlanFingerprint != "" && req.PlanFingerprint != plan.Fingerprint {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "assessment plan changed; review the refreshed plan", "plan": plan})
			return
		}
		if !req.SaveOnly && !planHasRunnableJobs(plan) {
			http.Error(w, "assessment has no runnable jobs; resolve the plan gaps before starting", http.StatusUnprocessableEntity)
			return
		}
		if req.Assessment.ParentAssessmentID != "" {
			parentDir, parent := s.findScanByID(req.Assessment.ParentAssessmentID)
			if parent == nil {
				http.Error(w, "parent assessment not found", 409)
				return
			}
			revision, err := scanner.LoadDiscoveryRevision(parentDir, plan.Fingerprint)
			if err != nil || revision.ParentFingerprint != parent.PlanFingerprint || revision.PreviewFingerprint != req.Assessment.ApprovalPreviewFingerprint {
				http.Error(w, "approved revision is missing or stale", 409)
				return
			}
		}
		req.PlanFingerprint = plan.Fingerprint
		req.assessmentPlan = &plan
	}
	selectedScanners, err := scanner.NormalizeScanners(req.Scanners)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Scanners = selectedScanners
	if strings.TrimSpace(req.CodeScan) == "provision" {
		http.Error(w, "code provisioning is no longer supported; submit artifact.kind and artifact.ref for Trivy", http.StatusBadRequest)
		return
	}
	if req.Artifact.Ref == "" && strings.TrimSpace(req.SourceRepo) != "" {
		req.Artifact.Ref = strings.TrimSpace(req.SourceRepo)
		req.Artifact.Kind = "repository"
		if !strings.Contains(req.Artifact.Ref, "://") {
			req.Artifact.Kind = "filesystem"
		}
	}
	if req.Artifact.Ref != "" {
		req.Artifact.Kind = strings.ToLower(strings.TrimSpace(req.Artifact.Kind))
		switch req.Artifact.Kind {
		case "filesystem", "repository", "image", "sbom":
		default:
			http.Error(w, "artifact.kind must be filesystem, repository, image, or sbom", http.StatusBadRequest)
			return
		}
	}
	if len(req.Targets) == 0 && req.Artifact.Ref != "" {
		// Artifact-only scans still produce five explicit statuses: network
		// scanners are not applicable to this synthetic target, while Trivy runs.
		req.Targets = []string{"artifact://" + req.Artifact.Kind}
	}

	if len(req.Targets) == 0 {
		http.Error(w, "targets required (or provide artifact.kind and artifact.ref)", http.StatusBadRequest)
		return
	}
	normalizeScanRequestActivity(&req)

	// Reject up front when every requested target is a local/internal IP or
	// the dashboard's own listener. runMultiScan filters these out anyway,
	// but without this check a fully-blocked request produces a "started"
	// instance with zero effective targets that the operator must then
	// clean up. Surface a 400 instead. Mixed requests (at least one allowed
	// target) proceed and the blocked entries are filtered downstream.
	// Code scans are exempt: a "provision" target is a deliberate loopback
	// address the scope guard allowlists for this scan only.
	if !req.SaveOnly && req.Artifact.Ref == "" {
		allBlocked := true
		networkTargets := req.Targets
		if req.Assessment != nil {
			networkTargets = nil
			for _, target := range req.Assessment.Targets {
				switch target.Kind {
				case assessment.KindDomain, assessment.KindURL, assessment.KindIP, assessment.KindCIDR, assessment.KindHost:
					networkTargets = append(networkTargets, target.Value)
				}
			}
		}
		if len(networkTargets) == 0 {
			allBlocked = false // source/image/schema-only resources are not network targets
		}
		for _, t := range networkTargets {
			if strings.TrimSpace(t) == "" {
				continue
			}
			if !s.isBlockedTarget(t) {
				allBlocked = false
				break
			}
		}
		if allBlocked {
			msg := "All targets are local/internal addresses or the dashboard's own listener, so the scan was refused (self-scan protection)."
			if s.cfg.AllowLocalTargets {
				// Local scanning is already on, so the only things still blocked
				// are the dashboard itself and the unspecified address.
				msg += " The dashboard's own listener and the unspecified address (0.0.0.0 / ::) are never scannable, even with local targets enabled — point the scan at the app's actual host:port instead."
			} else {
				// Self-hosted operators can opt in; tell them exactly how.
				msg += " To scan a locally-hosted app on a self-hosted install, enable local targets: Settings → Security → \"Allow local targets\", or set XALGORIX_ALLOW_LOCAL_TARGETS=true in ~/.xalgorix.env and restart. (The dashboard's own listener stays protected either way. Leave this OFF on shared/hosted deployments.)"
			}
			http.Error(w, msg, http.StatusBadRequest)
			return
		}
	}

	// Scanner execution never resolves or copies model/provider credentials.
	// Report AI reads the server's Report AI settings only after all attempts.
	scanCfg := *s.cfg

	// Save-only mode: create a persistent scan config without starting execution
	if req.SaveOnly {
		instanceID := randomSlug()
		now := time.Now().Format(time.RFC3339Nano)
		inst := &ScanInstance{
			Assessment:      req.Assessment,
			PlanFingerprint: req.PlanFingerprint,
			Profile:         req.Profile,
			ID:              instanceID,
			Name:            req.Name,
			Targets:         strings.Join(req.Targets, ", "),
			Status:          "saved",
			StartedAt:       now,
			ScanMode:        req.ScanMode,
			Instruction:     req.Instruction,
			SeverityFilter:  req.SeverityFilter,
			Scanners:        req.Scanners,
			Phases:          req.Phases,
			ReconMode:       req.ReconMode,
			ScanIntensity:   req.ScanIntensity,
			CurrentPhase:    firstSelectedPhase(req.Phases),
			CompanyName:     req.CompanyName,
			LogoPath:        req.LogoPath,
			DiscordWebhook:  req.DiscordWebhook,
			// Retained in-memory so "Save for later" → start keeps the
			// operator's authenticated-scanning + whitebox + context config.
			TargetAuth:          req.TargetAuth,
			TargetAuthSecondary: req.TargetAuthSecondary,
			SourceRepo:          req.SourceRepo,
			ScanContext:         req.ScanContext,
			Artifact:            req.Artifact,
			VulsSSHHost:         req.VulsSSHHost,
			ScannerRuns:         nil,
		}
		s.instancesMu.Lock()
		s.instances[instanceID] = inst
		s.instancesMu.Unlock()

		// Persist to disk so saved targets survive server restarts
		targetStr := strings.Join(req.Targets, ", ")
		savedDir := filepath.Join(s.dataDir, "_saved", instanceID)
		if err := os.MkdirAll(savedDir, 0700); err != nil {
			log.Printf("[ERROR] failed to create saved-target dir %s: %v", savedDir, err)
		} else {
			rec := &ScanRecord{
				SchemaVersion:            3,
				Assessment:               req.Assessment,
				AssessmentPlan:           req.assessmentPlan,
				PlanFingerprint:          req.PlanFingerprint,
				Profile:                  req.Profile,
				ID:                       instanceID,
				Name:                     req.Name,
				Target:                   targetStr,
				Status:                   "saved",
				StartedAt:                now,
				ScanMode:                 req.ScanMode,
				Instruction:              req.Instruction,
				SeverityFilter:           req.SeverityFilter,
				Scanners:                 append([]string(nil), req.Scanners...),
				Phases:                   req.Phases,
				ReconMode:                req.ReconMode,
				ScanIntensity:            req.ScanIntensity,
				CurrentPhase:             firstSelectedPhase(req.Phases),
				CompanyName:              req.CompanyName,
				LogoPath:                 req.LogoPath,
				DiscordWebhook:           req.DiscordWebhook,
				DiscordWebhookConfigured: req.DiscordWebhook != "" || s.discordWebhook != "",
				TelegramConfigured:       s.telegramConfigured(),
				Artifact:                 req.Artifact,
				VulsSSHHost:              req.VulsSSHHost,
			}
			s.saveScanRecordTo(rec, savedDir)
		}

		s.broadcastDashboard(WSEvent{
			Type:    "instance_started",
			Content: instanceID,
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "saved", "instance_id": instanceID})
		return
	}

	instanceID := randomSlug()
	req.Name = strings.TrimSpace(req.Name) // propagate name to running scans too
	go s.runMultiScan(req, &scanCfg, instanceID)

	// The ack reflects the scan's actual local state: it is QUEUED as
	// "pending" (orchestrator.go registers it pending, then the admission
	// gate flips it to "running" only once a concurrency slot is granted).
	// Previously this returned "started", which external callers (e.g. a SaaS
	// control plane) misread as "running" — producing a SaaS=running /
	// worker=pending desync whenever the worker was at its RAM-derived cap.
	// Callers wanting the authoritative status should poll GET /api/instances
	// (or /api/scans), whose "status" field is pending until admission.
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "pending", "instance_id": instanceID})
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	s.stopReq.Store(true)

	// Cancel the current scan session context (interrupts tool execution)
	s.mu.Lock()
	cancel := s.cancelScan
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}

	// Stop ALL running instances (use write lock since we're modifying instance state)
	s.instancesMu.Lock()
	for _, inst := range s.instances {
		inst.mu.Lock()
		if inst.Status == "running" || inst.Status == "pending" || inst.Status == "paused" {
			inst.Status = "stopped"
			inst.StopReason = "user_stopped"
			inst.FinishedAt = time.Now().Format(time.RFC3339Nano)
			if inst.cancel != nil {
				inst.cancel()
			}
		}
		inst.mu.Unlock()
	}
	s.instancesMu.Unlock()

	// A global user stop is terminal for every queue — clear all persisted
	// resume files so the dashboard queue counter clears and nothing is
	// auto-resumed on the next start (issue #239).
	s.clearQueueState()

	s.broadcast(WSEvent{Type: "stopped", Content: "All instances stopped by user"})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
}

// handleRestart restarts the backend. By default the restart is graceful: it
// waits until no scan instance is active and no tool process is leased, then
// restarts cleanly (in-flight scans auto-resume afterwards). This is the HTTP
// equivalent of `xalgorix --restart-when-idle` (SIGUSR1) and shares the watcher.
//
// With force=true (query param ?force=true or JSON body {"force":true}) the
// restart is IMMEDIATE: it interrupts any in-flight scans/tools and restarts
// right now. Interrupted scans are marked "stopped" (reason "server_restart")
// when the process comes back and rebuilds instances from disk. Use force when
// the scanner is wedged and would never reach idle on its own.
//
// POST /api/restart            → { "status": "scheduled"|"already_pending", "idle": bool }
// POST /api/restart?force=true → { "status": "restarting", "idle": bool, "forced": true }
func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	idle := s.scannerIdle()

	if restartForceRequested(r) {
		log.Printf("[RESTART] /api/restart FORCE requested (idle=%v) — restarting immediately, interrupting any in-flight work", idle)
		if s.discordWebhook != "" {
			s.sendDiscord(0xff6b6b, "🔁 Xalgorix Force Restart",
				"An immediate restart was requested. Xalgorix is restarting now; any in-flight scans are interrupted and marked stopped.")
		}
		if s.telegramConfigured() {
			s.sendTelegram(0xff6b6b, "🔁 Xalgorix Force Restart",
				"An immediate restart was requested. Xalgorix is restarting now; any in-flight scans are interrupted and marked stopped.")
		}
		// Prevent an already-scheduled idle watcher from also firing.
		s.restartWhenIdle.Store(true)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "restarting",
			"idle":   idle,
			"forced": true,
		})
		// Flush the response so the caller sees 200 BEFORE the process re-execs
		// (restartNow replaces/exits the process), then restart out-of-band.
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if s.forceRestartFn != nil {
			go s.forceRestartFn()
			return
		}
		go func() {
			time.Sleep(500 * time.Millisecond)
			s.restartNow(s.httpServer)
		}()
		return
	}

	scheduled := s.scheduleGracefulRestart()

	status := "scheduled"
	if !scheduled {
		status = "already_pending"
	}
	log.Printf("[RESTART] /api/restart requested (idle=%v, status=%s)", idle, status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": status,
		"idle":   idle,
	})
}

// restartForceRequested reports whether the caller asked for an immediate
// restart, via either the ?force=true query param or a JSON body {"force":true}.
func restartForceRequested(r *http.Request) bool {
	if isTrueish(r.URL.Query().Get("force")) {
		return true
	}
	if r.Body == nil {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil || len(body) == 0 {
		return false
	}
	var payload struct {
		Force bool `json:"force"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return false
	}
	return payload.Force
}

func isTrueish(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s.mu.RLock()
	scanID := s.currentScanID
	s.mu.RUnlock()

	// Count running instances
	s.instancesMu.RLock()
	runningCount := 0
	runningInstanceID := ""
	currentPhase := 0
	for _, inst := range s.instances {
		inst.mu.RLock()
		if inst.Status == "running" {
			runningCount++
			if runningInstanceID == "" {
				runningInstanceID = inst.ID
				currentPhase = inst.CurrentPhase
			}
		}
		inst.mu.RUnlock()
	}
	s.instancesMu.RUnlock()

	// Aggregate vulns across all active instances via their per-session context
	totalVulns := 0
	s.instancesMu.RLock()
	for _, inst := range s.instances {
		inst.mu.RLock()
		if inst.sctx != nil {
			totalVulns += len(reporting.GetVulnerabilitiesForContext(inst.sctx.ID))
		}
		inst.mu.RUnlock()
	}
	s.instancesMu.RUnlock()

	// Take a single atomic snapshot of safe counters so the values are
	// internally consistent (Task 11.4 / R9.5).
	counters := safe.Snapshot()
	allowList := sandbox.Default().Roots()
	readDeny := sandbox.Default().ReadDenyRoots()

	// vulns_persisted: total count from on-disk corpus across every scan
	// record. Stable across teardown — survives reporting.CleanupContext.
	// Additive change; the existing `vulns` field keeps its in-memory
	// semantics for backward compatibility. See Task 3.3 in
	// .kiro/specs/findings-consistency-and-pagination/tasks.md.
	persistedVulns := s.totalPersistedVulnCount()

	_ = json.NewEncoder(w).Encode(map[string]any{
		"running":            s.running.Load() || runningCount > 0,
		"scan_id":            scanID,
		"instance_id":        runningInstanceID,
		"current_phase":      currentPhase,
		"vulns":              totalVulns,
		"vulns_persisted":    persistedVulns,
		"running_instances":  runningCount,
		"panics_recovered":   counters.PanicsRecovered,
		"path_rejections":    counters.PathRejections,
		"watchdog_kills":     counters.WatchdogKills,
		"admission_refusals": counters.AdmissionRefusals,
		"llm_inflight_cap":   resources.LLMInFlightCap(),
		"data_dir":           s.cfg.DataDir,
		"allow_list":         allowList,
		// read_deny is the deny-list applied to Filesystem_Tool reads.
		// Reads outside allow_list succeed by default; only paths under
		// these roots are rejected. Set XALGORIX_READ_DENY_LIST
		// (colon-separated) to extend the defaults.
		"read_deny": readDeny,
	})
}

// handleFindingsSummary returns a stable on-disk severity tally across
// every scan record under cfg.DataDir. Used by the WebUI Findings and
// Overview totals widgets to surface a counter that does NOT collapse
// when reporting.CleanupContext wipes in-memory stores during teardown.
//
// Counts are deduplicated by (target, endpoint, title, severity) — the
// same key the WebUI's dedupFindings helper uses. Without this, a
// vulnerability that recurs across N rescans of the same target would
// inflate the totals strip relative to the deduped row count rendered
// below it on /findings.
//
// Response shape:
//
//	{
//	  "totals": {"critical": N, "high": N, "medium": N, "low": N, "info": N},
//	  "as_of": "<RFC3339>",
//	  "etag": "<hex sha256>"
//	}
//
// Honors If-None-Match: returns 304 Not Modified when the etag matches.
// The etag is derived from the marshaled totals plus the seconds-truncated
// as_of timestamp, so it is stable for short polling windows but rotates
// at least once per second when totals change.
//
// See Task 3.2 in .kiro/specs/findings-consistency-and-pagination/tasks.md
// and Property 2 (counter monotonicity) in design.md.
func (s *Server) handleFindingsSummary(w http.ResponseWriter, r *http.Request) {
	totals := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}
	statusTotals := make(map[string]int)
	rawObservations, uniqueFindings, activeFindings := 0, 0, 0

	// Wrap the iteration in safe.Recover so a corrupt scan record cannot
	// kill the handler. (defer + named recover keeps response writing in
	// scope even when the walk panics.)
	func() {
		defer safe.Recover("findings-summary", "")
		seen := make(map[string]struct{})
		for _, entry := range s.findAllScanSummaries() {
			if snapshot, ok := scanner.LoadFindingsSnapshot(entry.dir); ok {
				rawObservations += len(snapshot.RawObservations)
			} else {
				rawObservations += len(entry.rec.Vulns)
			}
			vulns := normalizedVulnsForEntry(entry)
			uniqueFindings += len(vulns)
			for _, v := range vulns {
				status := v.Status
				if status == "" {
					status = string(scanner.StatusPotential)
				}
				statusTotals[status]++
				if scanner.FindingActive(scanner.FindingStatus(status)) {
					activeFindings++
				}
				if !scanner.FindingActive(scanner.FindingStatus(status)) {
					continue
				}
				key := dedupFindingKey(entry.rec.Target, v)
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				bucket := normalizeSeverityBucket(v.Severity)
				totals[bucket]++
			}
		}
	}()

	asOf := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)

	// etag: sha256 over (marshaled totals || as_of). Truncating as_of to
	// seconds keeps the etag stable for sub-second polling windows.
	totalsJSON, _ := json.Marshal(totals)
	hash := sha256.New()
	hash.Write(totalsJSON)
	hash.Write([]byte(asOf))
	etag := hex.EncodeToString(hash.Sum(nil))

	if match := r.Header.Get("If-None-Match"); match != "" && match == etag {
		w.Header().Set("ETag", etag)
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"totals":                   totals,
		"raw_observations":         rawObservations,
		"unique_findings":          uniqueFindings,
		"active_security_findings": activeFindings,
		"status":                   statusTotals,
		"severity":                 totals,
		"as_of":                    asOf,
		"etag":                     etag,
	})
}

// flatFinding is a single vulnerability flattened across scans and augmented
// with its owning scan's identity. The embedded VulnSummary inlines its JSON
// fields, so the wire shape matches the WebUI's FlatFinding type exactly.
type flatFinding struct {
	VulnSummary
	ScanID        string `json:"scan_id"`
	ScanTarget    string `json:"scan_target"`
	ScanStartedAt string `json:"scan_started_at"`
}

// severityRankValue mirrors the WebUI's severityRank so server-side ordering
// matches the client (critical > high > medium > low > info).
func severityRankValue(severity string) int {
	switch normalizeSeverityBucket(severity) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// handleFindingsList returns every finding flattened across all scans, deduped
// by (target, endpoint, title, severity) and sorted by severity desc then
// scan_started_at desc. This replaces the previous WebUI behavior of fetching
// every scan record individually (an N+1 of full-record requests, each
// carrying the scan's entire event log) just to build the findings table.
// One server-side walk returns only the vuln fields the table needs.
func (s *Server) handleFindingsList(w http.ResponseWriter, r *http.Request) {
	deduped := make(map[string]flatFinding)

	func() {
		defer safe.Recover("findings-list", "")
		for _, entry := range s.findAllScanSummaries() {
			rec := entry.rec
			for _, v := range normalizedVulnsForEntry(entry) {
				key := dedupFindingKey(rec.Target, v)
				candidate := flatFinding{
					VulnSummary:   v,
					ScanID:        rec.ID,
					ScanTarget:    rec.Target,
					ScanStartedAt: rec.StartedAt,
				}
				if existing, ok := deduped[key]; ok && existing.ScanStartedAt >= candidate.ScanStartedAt {
					continue
				}
				deduped[key] = candidate
			}
		}
	}()

	findings := make([]flatFinding, 0, len(deduped))
	for _, f := range deduped {
		findings = append(findings, f)
	}
	sort.Slice(findings, func(i, j int) bool {
		ri, rj := severityRankValue(findings[i].Severity), severityRankValue(findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return findings[i].ScanStartedAt > findings[j].ScanStartedAt
	})

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	_ = json.NewEncoder(w).Encode(findings)
}

// handleLegacyImportStatus exposes the in-memory legacy import counter
// surfaced once to the WebUI on the run that did the import. The count
// originates from importLegacyDataDir at startup; this endpoint just
// reads the cached value so the WebUI can render a one-time dismissible
// banner on first load.
//
// Response shape:
//
//	{"count": N, "dismissed": false}
//
// Methods:
//   - GET  → return the current state.
//   - POST → flip dismissed=true for the remainder of the process and
//     return the updated state. Restart re-shows the banner once.
//
// The dismissed flag is in-memory only; restart re-shows. When count==0
// the WebUI suppresses the banner outright (so dismissal of a zero
// state is a harmless no-op).
//
// See Task 5.2 in .kiro/specs/findings-consistency-and-pagination/tasks.md
// and Property 6 (legacy-import idempotence) in design.md.
func (s *Server) handleLegacyImportStatus(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.legacyImportMu.RLock()
		count := s.legacyImportCount
		dismissed := s.legacyImportDismissed
		s.legacyImportMu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"count":     count,
			"dismissed": dismissed,
		})
	case http.MethodPost:
		s.legacyImportMu.Lock()
		s.legacyImportDismissed = true
		count := s.legacyImportCount
		dismissed := s.legacyImportDismissed
		s.legacyImportMu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"count":     count,
			"dismissed": dismissed,
		})
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleInstances returns all scan instances (running + recent)
func (s *Server) handleInstances(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s.instancesMu.RLock()
	instances := make([]*ScanInstance, 0, len(s.instances))
	for _, inst := range s.instances {
		inst.mu.RLock()
		instances = append(instances, &ScanInstance{
			Assessment:      inst.Assessment,
			PlanFingerprint: inst.PlanFingerprint,
			Profile:         inst.Profile,
			ID:              inst.ID,
			Name:            inst.Name,
			Targets:         inst.Targets,
			Status:          inst.Status,
			StartedAt:       inst.StartedAt,
			FinishedAt:      inst.FinishedAt,
			Iterations:      inst.Iterations,
			ToolCalls:       inst.ToolCalls,
			VulnCount:       inst.VulnCount,
			TotalTokens:     inst.TotalTokens,
			ScanMode:        inst.ScanMode,
			Instruction:     inst.Instruction,
			SeverityFilter:  append([]string(nil), inst.SeverityFilter...),
			Scanners:        append([]string(nil), inst.Scanners...),
			Phases:          inst.Phases,
			ReconMode:       inst.ReconMode,
			ScanIntensity:   inst.ScanIntensity,
			CompanyName:     inst.CompanyName,
			LogoPath:        inst.LogoPath,
			CurrentPhase:    inst.CurrentPhase,
		})
		inst.mu.RUnlock()
	}
	s.instancesMu.RUnlock()

	// Sort: running first, then by start time descending
	sort.Slice(instances, func(i, j int) bool {
		if instances[i].Status == "running" && instances[j].Status != "running" {
			return true
		}
		if instances[i].Status != "running" && instances[j].Status == "running" {
			return false
		}
		return instances[i].StartedAt > instances[j].StartedAt
	})

	// Distinct scan modes across ALL instances, computed before filtering so
	// the UI's mode dropdown always offers the full set of options.
	modeSet := make(map[string]struct{})
	for _, inst := range instances {
		if inst.ScanMode != "" {
			modeSet[inst.ScanMode] = struct{}{}
		}
	}
	modes := make([]string, 0, len(modeSet))
	for m := range modeSet {
		modes = append(modes, m)
	}
	sort.Strings(modes)

	// Optional server-side filtering (no-ops when the params are absent).
	if q := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("q"))); q != "" {
		filtered := make([]*ScanInstance, 0, len(instances))
		for _, inst := range instances {
			if strings.Contains(strings.ToLower(inst.Name), q) ||
				strings.Contains(strings.ToLower(inst.Targets), q) ||
				strings.Contains(strings.ToLower(inst.ID), q) {
				filtered = append(filtered, inst)
			}
		}
		instances = filtered
	}
	if st := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("status"))); st != "" && st != "all" {
		filtered := make([]*ScanInstance, 0, len(instances))
		for _, inst := range instances {
			if strings.ToLower(inst.Status) == st {
				filtered = append(filtered, inst)
			}
		}
		instances = filtered
	}
	if mode := strings.TrimSpace(r.URL.Query().Get("mode")); mode != "" && mode != "all" {
		filtered := make([]*ScanInstance, 0, len(instances))
		for _, inst := range instances {
			if inst.ScanMode == mode {
				filtered = append(filtered, inst)
			}
		}
		instances = filtered
	}

	// Pagination is opt-in: only slice when a page/size param is present, so
	// the default GET /api/instances response still returns every instance.
	total := len(instances)
	pageStr := r.URL.Query().Get("page")
	sizeStr := r.URL.Query().Get("size")
	page, size := 1, 0
	if pageStr != "" || sizeStr != "" {
		page, size = parsePageParams(pageStr, sizeStr)
		start := (page - 1) * size
		if start < 0 {
			start = 0
		}
		if start > total {
			start = total
		}
		end := start + size
		if end > total {
			end = total
		}
		instances = instances[start:end]
	}
	if instances == nil {
		instances = []*ScanInstance{}
	}

	// Include resource stats so the UI can explain why scans are pending
	stats := resources.GetStats()
	level, _ := resources.CurrentLevel()
	effectiveMax, reason := resources.EffectiveMaxInstances()
	capacity := resources.Capacity()
	response := map[string]any{
		"instances": instances,
		"total":     total,
		"page":      page,
		"size":      size,
		"modes":     modes,
		"resources": map[string]any{
			"cpu_cores":                stats.CPUCores,
			"cpu_load_1m":              stats.LoadAvg1m,
			"ram_total_mb":             stats.MemTotalMB,
			"ram_available_mb":         stats.MemAvailableMB,
			"disk_free_mb":             stats.DiskFreeMB,
			"process_rss_mb":           stats.ProcessRSSMB,
			"go_heap_alloc_mb":         stats.GoHeapAllocMB,
			"go_heap_sys_mb":           stats.GoHeapSysMB,
			"goroutines":               stats.Goroutines,
			"level":                    level.String(),
			"reason":                   reason,
			"max_instances":            effectiveMax,
			"manual_max_instances":     resources.MaxInstances(),
			"effective_max_instances":  effectiveMax,
			"active_tool_leases":       capacity.ActiveToolLeases,
			"active_heavy_tool_leases": capacity.ActiveHeavyToolLeases,
			"heavy_tool_slots":         capacity.HeavyToolSlots,
			"light_tool_slots":         capacity.LightToolSlots,
			"tool_mem_limit_mb":        capacity.ToolMemLimitMB,
			"scan_memory_budget_mb":    capacity.ScanMemoryBudgetMB,
			"heavy_tool_cpu_load":      capacity.HeavyToolCPULoad,
			"go_memory_limit_mb":       capacity.GoMemoryLimitMB,
		},
	}
	_ = json.NewEncoder(w).Encode(response)
}

// handleInstanceAction handles per-instance operations (stop, etc)
// resolveInstanceForAction maps a URL id to a live ScanInstance for the
// per-instance action endpoints (stop/pause/resume/restart/start/events).
//
// The exact in-memory instance id always wins. But the scan-detail page routes
// by the scan RECORD id (and sometimes a short hex alias), which for wildcard
// scans differs from the instance id — so a plain map lookup 404'd and the
// Stop/Delete buttons silently did nothing there, while the Instances page
// (which passes the real instance id) worked. Fall back to resolving the id as
// a record id / short alias and mapping that record to its instance.
func (s *Server) resolveInstanceForAction(id string) (*ScanInstance, bool) {
	if id == "" {
		return nil, false
	}
	s.instancesMu.RLock()
	inst, ok := s.instances[id]
	s.instancesMu.RUnlock()
	if ok {
		return inst, true
	}
	// Not a live instance id — try to resolve it as a scan record id, then as a
	// recent short alias, and map the resolved record back to its instance.
	_, rec := s.findScanByID(id)
	if rec == nil {
		_, rec = s.findRecentScanForShortAlias(id)
	}
	if rec != nil {
		if inst := s.instanceForRecord(rec); inst != nil {
			return inst, true
		}
	}
	return nil, false
}

func (s *Server) handleInstanceAction(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// Path: /api/instances/{id}/stop or /api/instances/{id}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/instances/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "instance ID required", http.StatusBadRequest)
		return
	}
	instanceID := parts[0]

	inst, ok := s.resolveInstanceForAction(instanceID)
	if !ok {
		http.Error(w, "instance not found", http.StatusNotFound)
		return
	}

	// GET /api/instances/{id} — return instance details
	if r.Method == http.MethodGet && (len(parts) == 1 || parts[1] == "") {
		inst.mu.RLock()
		_ = json.NewEncoder(w).Encode(inst)
		inst.mu.RUnlock()
		return
	}

	// POST /api/instances/{id}/stop — stop specific instance
	if len(parts) >= 2 && parts[1] == "stop" && r.Method == http.MethodPost {
		inst.mu.Lock()
		// Queued scans are stoppable too, even before they acquire resources.
		if inst.Status == "running" || inst.Status == "pending" || inst.Status == "paused" {
			inst.Status = "stopped"
			inst.StopReason = "user_stopped"
			inst.FinishedAt = time.Now().Format(time.RFC3339Nano)
			if inst.cancel != nil {
				inst.cancel()
			}
		}
		inst.mu.Unlock()

		// Drop the persisted resume file now so the dashboard's queue counter
		// clears immediately and the startup auto-resume never replays it. A
		// user stop is terminal (non-resumable); the runMultiScan defer also
		// clears it on exit, so this is just the prompt path (issue #239).
		s.clearQueueState(instanceID)

		// Broadcast stop to clients watching this instance
		s.broadcastToInstance(instanceID, WSEvent{Type: "stopped", Content: "Instance stopped by user"})
		// Broadcast update to dashboard clients
		s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})

		_ = json.NewEncoder(w).Encode(map[string]string{"status": "stopped", "instance_id": instanceID})
		return
	}

	// POST /api/instances/{id}/restart — restart scan with same config
	if len(parts) >= 2 && parts[1] == "restart" && r.Method == http.MethodPost {
		// Avoid creating a duplicate scan against the same targets while this
		// instance is still active.
		inst.mu.RLock()
		currentStatus := inst.Status
		inst.mu.RUnlock()
		if currentStatus == "running" || currentStatus == "pending" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "cannot restart: instance is still " + currentStatus,
			})
			return
		}
		inst.mu.RLock()
		typedAssessment := inst.Assessment != nil
		assessmentConfig := inst.Assessment
		acceptedFingerprint := inst.PlanFingerprint
		inst.mu.RUnlock()
		if typedAssessment {
			plan := s.buildAssessmentPlan(*assessmentConfig)
			if acceptedFingerprint == "" || acceptedFingerprint != plan.Fingerprint {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "saved assessment plan changed; review the refreshed plan", "plan": plan})
				return
			}
		}

		inst.mu.RLock()
		targets := strings.Split(inst.Targets, ", ")
		profile := inst.Profile
		instruction := inst.Instruction
		scanMode := inst.ScanMode
		severityFilter := inst.SeverityFilter
		selectedScanners := append([]string(nil), inst.Scanners...)
		discordWebhook := inst.DiscordWebhook
		phases := inst.Phases
		reconMode := inst.ReconMode
		scanIntensity := inst.ScanIntensity
		companyName := inst.CompanyName
		logoPath := inst.LogoPath
		instName := inst.Name
		targetAuth := inst.TargetAuth
		targetAuthB := inst.TargetAuthSecondary
		sourceRepo := inst.SourceRepo
		scanContext := inst.ScanContext
		inst.mu.RUnlock()

		// Build a new ScanRequest from stored config
		req := ScanRequest{
			Assessment:          assessmentConfig,
			PlanFingerprint:     acceptedFingerprint,
			Profile:             profile,
			Targets:             targets,
			Instruction:         instruction,
			ScanMode:            scanMode,
			SeverityFilter:      severityFilter,
			Scanners:            selectedScanners,
			DiscordWebhook:      discordWebhook,
			Name:                instName,
			Phases:              phases,
			ReconMode:           reconMode,
			ScanIntensity:       scanIntensity,
			CompanyName:         companyName,
			LogoPath:            logoPath,
			TargetAuth:          targetAuth,
			TargetAuthSecondary: targetAuthB,
			SourceRepo:          sourceRepo,
			ScanContext:         scanContext,
		}

		scanCfg := *s.cfg // shallow copy
		go s.runMultiScan(req, &scanCfg)

		_ = json.NewEncoder(w).Encode(map[string]string{"status": "restarted"})
		return
	}

	// POST /api/instances/{id}/start — start a saved scan, or start a new
	// run from an existing finished/stopped/failed scan's saved config.
	if len(parts) >= 2 && parts[1] == "start" && r.Method == http.MethodPost {
		inst.mu.RLock()
		currentStatus := strings.ToLower(strings.TrimSpace(inst.Status))
		inst.mu.RUnlock()
		if !canStartInstanceStatus(currentStatus) {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "cannot start: instance is " + currentStatus,
			})
			return
		}
		inst.mu.RLock()
		typedAssessment := inst.Assessment != nil
		assessmentConfig := inst.Assessment
		acceptedFingerprint := inst.PlanFingerprint
		inst.mu.RUnlock()
		if typedAssessment {
			plan := s.buildAssessmentPlan(*assessmentConfig)
			if acceptedFingerprint == "" || acceptedFingerprint != plan.Fingerprint {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "saved assessment plan changed; review the refreshed plan", "plan": plan})
				return
			}
		}

		inst.mu.RLock()
		targets := strings.Split(inst.Targets, ", ")
		req := ScanRequest{
			Assessment:          inst.Assessment,
			PlanFingerprint:     inst.PlanFingerprint,
			Profile:             inst.Profile,
			Targets:             targets,
			Instruction:         inst.Instruction,
			ScanMode:            inst.ScanMode,
			SeverityFilter:      inst.SeverityFilter,
			Scanners:            append([]string(nil), inst.Scanners...),
			DiscordWebhook:      inst.DiscordWebhook,
			Name:                inst.Name,
			Phases:              inst.Phases,
			ReconMode:           inst.ReconMode,
			ScanIntensity:       inst.ScanIntensity,
			CompanyName:         inst.CompanyName,
			LogoPath:            inst.LogoPath,
			TargetAuth:          inst.TargetAuth,
			TargetAuthSecondary: inst.TargetAuthSecondary,
			SourceRepo:          inst.SourceRepo,
			ScanContext:         inst.ScanContext,
		}
		inst.mu.RUnlock()

		if currentStatus == "saved" {
			// Remove the saved placeholder — runMultiScan creates a new
			// pending/running instance. Finished scans are kept so their
			// reports remain available while the new run starts separately.
			s.instancesMu.Lock()
			delete(s.instances, instanceID)
			s.instancesMu.Unlock()

			savedDir := filepath.Join(s.dataDir, "_saved", instanceID)
			_ = os.RemoveAll(savedDir)
		}

		scanCfg := *s.cfg
		newID := randomSlug()
		go s.runMultiScan(req, &scanCfg, newID)

		s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "started", "instance_id": newID})
		return
	}

	// POST /api/instances/{id}/pause — gracefully pause a running scan
	if len(parts) >= 2 && parts[1] == "pause" && r.Method == http.MethodPost {
		inst.mu.Lock()
		if inst.Status != "running" {
			inst.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "cannot pause: instance is " + inst.Status,
			})
			return
		}
		inst.Status = "paused"
		inst.StopReason = "user_paused"
		if inst.cancel != nil {
			inst.cancel()
		}
		inst.mu.Unlock()

		s.broadcastToInstance(instanceID, WSEvent{Type: "paused", Content: "Scan paused by user"})
		s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "paused", "instance_id": instanceID})
		return
	}

	// POST /api/instances/{id}/resume — resume a paused scan
	if len(parts) >= 2 && parts[1] == "resume" && r.Method == http.MethodPost {
		inst.mu.RLock()
		currentStatus := inst.Status
		inst.mu.RUnlock()
		if currentStatus != "paused" {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "cannot resume: instance is " + currentStatus + ", expected paused",
			})
			return
		}

		req, ok, reason := s.scanRequestForPausedInstance(instanceID, inst)
		if !ok {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "cannot resume: " + reason,
			})
			return
		}

		// Remove the paused instance — a new one will be created by runMultiScan
		s.instancesMu.Lock()
		delete(s.instances, instanceID)
		s.instancesMu.Unlock()

		scanCfg := *s.cfg
		newID := randomSlug()
		go s.runMultiScan(req, &scanCfg, newID)

		s.broadcastToInstance(instanceID, WSEvent{Type: "resumed", Content: "Scan resumed"})
		s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "resumed", "instance_id": newID})
		return
	}

	// GET /api/instances/{id}/events — return buffered event history
	if len(parts) >= 2 && parts[1] == "events" && r.Method == http.MethodGet {
		inst.mu.RLock()
		events := make([]WSEvent, len(inst.events))
		copy(events, inst.events)
		inst.mu.RUnlock()
		_ = json.NewEncoder(w).Encode(events)
		return
	}

	http.Error(w, "not found", http.StatusNotFound)
}

// ────────────────────────────────────────────────────────
// scanSession — self-contained unit for a single scan run
// ────────────────────────────────────────────────────────

// scanSession isolates all per-scan state. Crashes in one session
// cannot corrupt server-level state or leak into subsequent scans.
type scanSession struct {
	id                 string
	target             string
	parentTarget       string // parent domain for subdomain scans (wildcard mode)
	scanDir            string
	cfg                *config.Config
	record             *ScanRecord
	server             *Server
	name               string
	userInstruction    string
	severityFilter     []string
	scanners           []string // selected scanners (empty = whole pipeline)
	discordWebhook     string
	genReport          bool
	resetState         bool
	instanceID         string // parent instance ID for multi-instance tracking
	scanMode           string // single, wildcard — persisted so dashboard shows correct mode
	profile            string // web-gentle or web-thorough
	assessment         *assessment.AssessmentConfig
	assessmentPlan     *scanner.AssessmentPlan
	planFingerprint    string
	sctx               *scanctx.ScanContext // per-session isolated state
	companyName        string               // report branding: company name
	logoPath           string               // report branding: logo path
	phases             []int                // selected methodology phases
	reconMode          string               // active or passive reconnaissance
	scanIntensity      string               // active or passive testing/scanning
	targetAuth         string               // per-scan authenticated-scanning material (see ScanRequest.TargetAuth)
	allowLoopbackPorts []int                // per-scan loopback allowlist (scope-guard exemption)
	ctx                context.Context
	artifact           scanner.Artifact
	vulsSSHHost        string
}

// cleanup tears down per-session resources. Every sub-operation has its own
// panic guard so cleanup NEVER panics upward. The deterministic pipeline does
// not allocate a per-session ScanContext, so cleanup is a no-op in the common
// case; the guarded teardown remains for any path that does set one.
func (sess *scanSession) cleanup() {
	if sess.sctx == nil {
		return
	}
	func() {
		defer logRecover("cleanup.scanctx.close")
		scanctx.Deactivate(sess.sctx.ID)
		sess.sctx.Close()
	}()
	// Persist any in-memory vulns into the on-disk record before dropping the
	// reporting store. Idempotent: mergeReportedVulnerabilitiesIntoRecord dedups
	// by title|target|endpoint|method|CVE.
	func() {
		defer safe.Recover("cleanup.scanrecord.merge", sess.sctx.ID)
		if sess.record == nil {
			return
		}
		before := len(sess.record.Vulns)
		mergeReportedVulnerabilitiesIntoRecord(sess.record, reporting.GetVulnerabilitiesForContext(sess.sctx.ID))
		if added := len(sess.record.Vulns) - before; added > 0 {
			log.Printf("[cleanup] Persisted %d in-memory vulns into scan.json for session %s", added, sess.sctx.ID)
		}
		sess.server.saveScanRecordTo(sess.record, sess.scanDir)
	}()
	func() {
		defer logRecover("cleanup.reporting.cleanup")
		reporting.CleanupContext(sess.sctx.ID)
	}()
}

// randomSlug generates a short random hex string for scan IDs.
func randomSlug() string {
	b := make([]byte, 4)
	if _, err := cryptorand.Read(b); err != nil {
		log.Printf("Warning: crypto/rand failed, falling back to time-based slug: %v", err)
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}

// sanitizeTarget creates a safe directory name from a target URL/domain.
func sanitizeTarget(target string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9._-]`)
	clean := re.ReplaceAllString(target, "_")
	clean = strings.TrimPrefix(clean, "https___")
	clean = strings.TrimPrefix(clean, "http___")
	clean = strings.Trim(clean, "_")
	if len(clean) > 60 {
		clean = clean[:60]
	}
	return clean
}

// saveScanRecordTo saves a scan record to a specific directory.
func (s *Server) saveScanRecordTo(rec *ScanRecord, scanDir string) {
	if scanDir == "" {
		return
	}

	// Check disk space before writing (50MB minimum)
	if avail := diskAvailable(scanDir); avail > 0 && avail < 50*1024*1024 {
		log.Printf("Warning: low disk space (%d MB available), scan record may fail to save", avail/1024/1024)
		s.broadcast(WSEvent{Type: "error", Content: fmt.Sprintf("⚠️ Low disk space: %d MB remaining. Scan data may not be saved.", avail/1024/1024)})
	}

	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		log.Printf("Error: failed to marshal scan record: %v", err)
		return
	}
	// Temp file + rename so a crash mid-write never leaves a truncated scan.json.
	if err := storage.WriteAtomic(filepath.Join(scanDir, "scan.json"), data); err != nil {
		log.Printf("Error: failed to save scan record to %s: %v", scanDir, err)
		s.broadcast(WSEvent{Type: "error", Content: fmt.Sprintf("⚠️ Failed to save scan data: %v", err)})
	}
}

// diskAvailable returns available bytes on the filesystem containing path, or 0 on error.
func diskAvailable(path string) uint64 {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0
	}
	return stat.Bavail * uint64(stat.Bsize) //nolint:gosec // G115: filesystem block size is small and non-negative
}

func (s *Server) handleDownloadReport(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/api/report/")
	// Normalise: strip any path separators so a crafted /api/report/../etc/passwd
	// can never escape the scan-dir even if a future caller forgets.
	scanID = filepath.Base(scanID)
	if scanID == "" || scanID == "." || scanID == "/" {
		http.Error(w, "scan ID required", http.StatusBadRequest)
		return
	}

	scanDir, rec := s.findScanByID(scanID)
	if scanDir == "" || rec == nil {
		s.instancesMu.RLock()
		inst := s.instances[scanID]
		s.instancesMu.RUnlock()
		if inst != nil {
			rec = s.scanRecordFromInstance(inst)
			inst.mu.RLock()
			scanDir = inst.scanDir
			inst.mu.RUnlock()
		}
		if scanDir == "" || rec == nil {
			http.Error(w, "scan not found", http.StatusNotFound)
			return
		}
	}

	var reportPath string
	var err error
	if rec.SchemaVersion >= scanner.SchemaVersion {
		reportPath = filepath.Join(scanDir, fmt.Sprintf("xalgorix_report_%s.pdf", rec.ID))
		info, statErr := os.Stat(reportPath)
		if statErr != nil || !info.Mode().IsRegular() || reportManifestNeedsRefresh(scanDir) {
			reportPath = s.generateScannerReport(rec, scanDir, rec.InstanceID)
			if reportPath == "" {
				err = fmt.Errorf("scanner report generation failed")
			}
		}
	} else {
		reportPath, err = s.generateReportAt(rec, scanDir)
	}
	if err != nil {
		log.Printf("Report generation error: %v", err)
		fallbackPath := filepath.Join(scanDir, fmt.Sprintf("xalgorix_report_%s.pdf", scanID))
		if info, statErr := os.Stat(fallbackPath); statErr == nil && info.Mode().IsRegular() {
			reportPath = fallbackPath
		} else {
			http.Error(w, "failed to generate report: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Defense-in-depth: confirm the resolved target is a regular file before
	// handing it to http.ServeFile. ServeFile will happily render a directory
	// index if asked for a directory.
	info, err := os.Stat(reportPath)
	if err != nil {
		log.Printf("Report stat failed for %s: %v", reportPath, err)
		http.Error(w, "report not available", http.StatusNotFound)
		return
	}
	if !info.Mode().IsRegular() {
		log.Printf("Report path is not a regular file: %s (mode=%s)", reportPath, info.Mode())
		http.Error(w, "report not available", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"xalgorix_report_%s.pdf\"", scanID))
	http.ServeFile(w, r, reportPath)
}

// handleRateLimit handles GET and POST for rate limit settings.
func (s *Server) handleRateLimit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		// Return current rate limit settings
		_ = json.NewEncoder(w).Encode(map[string]int{
			"requests": s.cfg.RateLimitRequests,
			"window":   s.cfg.RateLimitWindow,
		})

	case "POST":
		// Update rate limit settings
		var req struct {
			Requests int `json:"requests"`
			Window   int `json:"window"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		// Validate values
		if req.Requests < 1 {
			req.Requests = 1
		}
		if req.Requests > 1000 {
			req.Requests = 1000
		}
		if req.Window < 10 {
			req.Window = 10
		}
		if req.Window > 3600 {
			req.Window = 3600
		}

		if _, err := s.applyEnvironmentUpdates(map[string]string{
			"XALGORIX_RATE_LIMIT_REQUESTS": strconv.Itoa(req.Requests),
			"XALGORIX_RATE_LIMIT_WINDOW":   strconv.Itoa(req.Window),
		}); err != nil {
			log.Printf("Failed to save rate limit settings: %v", err)
			http.Error(w, "failed to save rate limit settings", http.StatusInternalServerError)
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]int{
			"requests": s.cfg.RateLimitRequests,
			"window":   s.cfg.RateLimitWindow,
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleVersion returns the current Xalgorix version
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"version": Version,
	})
}

// handleStopNotify sends a stop notification to Discord if a scan was running
func (s *Server) handleStopNotify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Send Discord notification if webhook is configured
	if s.discordWebhook != "" {
		s.sendDiscord(0xff6b6b, "🛑 Xalgorix Stopped", "The Xalgorix service has been stopped by the user.")
	}
	if s.telegramConfigured() {
		s.sendTelegram(0xff6b6b, "🛑 Xalgorix Stopped", "The Xalgorix service has been stopped by the user.")
	}

	_ = json.NewEncoder(w).Encode(map[string]string{"status": "notified"})
}

// handleQueueStatus returns the current queue state for recovery
func (s *Server) handleQueueStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	entries := s.validQueueStateEntries(true)
	if len(entries) > 0 {
		state := entries[0].state
		totalRemaining := 0
		for _, entry := range entries {
			totalRemaining += len(entry.state.Targets) - entry.state.CurrentIdx
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"available":                 true,
			"queue_count":               len(entries),
			"total_remaining":           totalRemaining,
			"instance_id":               state.InstanceID,
			"targets":                   state.Targets,
			"current_idx":               state.CurrentIdx,
			"remaining":                 len(state.Targets) - state.CurrentIdx,
			"instruction":               state.Instruction,
			"scan_mode":                 state.ScanMode,
			"started_at":                state.StartedAt,
			"paused":                    state.Paused,
			"name":                      state.Name,
			"severity_filter":           state.SeverityFilter,
			"scanners":                  state.Scanners,
			"phases":                    state.Phases,
			"recon_mode":                normalizeActivityMode(state.ReconMode),
			"scan_intensity":            normalizeActivityMode(state.ScanIntensity),
			"company_name":              state.CompanyName,
			"logo_path":                 state.LogoPath,
			"active_target":             state.ActiveTarget,
			"active_scan_id":            state.ActiveScanID,
			"wildcard_active_target":    state.WildcardActiveTarget,
			"wildcard_active_scan_id":   state.WildcardActiveScanID,
			"wildcard_sub_index":        state.WildcardSubIndex,
			"wildcard_subdomains_total": len(state.WildcardSubdomains),
		})
	} else {
		_ = json.NewEncoder(w).Encode(map[string]any{"available": false})
	}
}

// handleQueueResume resumes an interrupted scan queue
func (s *Server) handleQueueResume(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	s.queueResumeMu.Lock()
	defer s.queueResumeMu.Unlock()

	if s.running.Load() || s.hasPendingOrRunningInstance() || s.hasQueueResumeLaunchingLocked() {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "A scan is already pending or running"})
		return
	}

	entries := s.validQueueStateEntries(true)
	if len(entries) == 0 {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "No interrupted queue found"})
		return
	}

	totalRemaining := 0
	firstIdx := entries[0].state.CurrentIdx
	for _, entry := range entries {
		req := scanRequestFromQueueState(entry.state, entry.path)
		if len(req.Targets) == 0 {
			continue
		}
		totalRemaining += len(req.Targets)
		scanCfg := *s.cfg
		instanceID := entry.state.InstanceID
		resumeKey := queueResumeEntryKey(entry)
		s.markQueueResumeLaunchingLocked(resumeKey)
		go func(req ScanRequest, scanCfg config.Config, instanceID, resumeKey string) {
			defer s.clearQueueResumeLaunching(resumeKey)
			s.runMultiScan(req, &scanCfg, instanceID)
		}(req, scanCfg, instanceID, resumeKey)
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "resumed",
		"resumed_queues": len(entries),
		"from_index":     firstIdx,
		"targets_left":   totalRemaining,
	})
}

// handleQueueClear clears an interrupted queue state
func (s *Server) handleQueueClear(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s.clearQueueState()
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "cleared"})
}

// handleGetScan returns a specific scan's full data.
func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	// Extract scan ID from URL: /api/scans/{id}
	scanID := strings.TrimPrefix(r.URL.Path, "/api/scans/")
	if scanID == "" || scanID == "latest" {
		// Find latest scan by StartedAt timestamp
		allScans := []scanEntry{}
		for _, entry := range s.findAllScans() {
			if entry.rec.ParentTarget != "" {
				continue
			}
			allScans = append(allScans, entry)
		}
		if len(allScans) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`null`))
			return
		}
		sort.Slice(allScans, func(i, j int) bool {
			return allScans[i].rec.StartedAt > allScans[j].rec.StartedAt
		})
		rec := allScans[0].rec
		s.applyInstanceSnapshot(&rec, true)
		s.attachWildcardSubScans(&rec)
		finalizeScanRecordForResponse(&rec)
		s.markDiscordWebhookConfigured(&rec)
		s.markTelegramConfigured(&rec)
		data, _ := json.Marshal(rec)
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}

	// DELETE /api/scans/{id} — delete scan from disk and in-memory instances
	// Handle this BEFORE findScanByID because instance IDs (from runMultiScan)
	// may differ from scan record IDs (directory slugs). We need to clean up both.
	if r.Method == http.MethodDelete {
		// Try to find and delete from disk
		dir, rec := s.findScanByID(scanID)
		if dir != "" {
			_ = os.RemoveAll(dir)
		}
		if rec != nil {
			for _, entry := range s.findAllScans() {
				if entry.dir == dir {
					continue
				}
				if isChildOfScan(rec, &entry.rec) {
					_ = os.RemoveAll(entry.dir)
				}
			}
		}
		instanceIDs := []string{scanID}
		if rec != nil {
			instanceIDs = append(instanceIDs, rec.ID, rec.InstanceID)
		}
		seenInstanceIDs := make(map[string]bool, len(instanceIDs))
		s.instancesMu.Lock()
		for _, id := range instanceIDs {
			if id == "" || seenInstanceIDs[id] {
				continue
			}
			seenInstanceIDs[id] = true
			// Deleting a scan must HALT it, not just drop the map entry. Mark
			// the instance stopped (so runMultiScan's queue loop breaks on its
			// captured pointer), cancel the in-flight target's context, and
			// stop the agent so the current LLM/tool loop aborts immediately.
			// Without this the queue kept scanning in the background and
			// consuming tokens after deletion (issue #239).
			if inst := s.instances[id]; inst != nil {
				inst.mu.Lock()
				if inst.Status == "running" || inst.Status == "pending" || inst.Status == "paused" {
					inst.Status = "stopped"
					inst.StopReason = "user_deleted"
					inst.FinishedAt = time.Now().Format(time.RFC3339Nano)
				}
				if inst.cancel != nil {
					inst.cancel()
				}
				inst.mu.Unlock()
			}
			// Remove the persisted resume file so the startup auto-resume
			// goroutine never replays this queue (previously the only fix was
			// wiping the whole .xalgorix data dir).
			s.clearQueueState(id)
			delete(s.instances, id)
		}
		s.instancesMu.Unlock()
		s.invalidateScanListCache()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"deleted"}`))
		return
	}

	if r.Method == http.MethodGet {
		s.instancesMu.RLock()
		inst := s.instances[scanID]
		s.instancesMu.RUnlock()
		if rec := s.scanRecordFromInstance(inst); rec != nil {
			if _, persisted := s.findScanByID(scanID); persisted != nil {
				s.applyInstanceSnapshot(persisted, true)
				s.attachWildcardSubScans(persisted)
				finalizeScanRecordForResponse(persisted)
				s.markDiscordWebhookConfigured(persisted)
				s.markTelegramConfigured(persisted)
				data, _ := json.Marshal(persisted)
				w.Header().Set("Content-Type", "application/json")
				w.Write(data)
				return
			}
			s.attachWildcardSubScans(rec)
			finalizeScanRecordForResponse(rec)
			s.markDiscordWebhookConfigured(rec)
			s.markTelegramConfigured(rec)
			data, _ := json.Marshal(rec)
			w.Header().Set("Content-Type", "application/json")
			w.Write(data)
			return
		}
	}

	dir, rec := s.findScanByID(scanID)
	_ = dir
	if rec == nil {
		dir, rec = s.findRecentScanForShortAlias(scanID)
		_ = dir
	}
	if rec == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`null`))
		return
	}

	s.applyInstanceSnapshot(rec, true)
	s.attachWildcardSubScans(rec)
	finalizeScanRecordForResponse(rec)
	s.markDiscordWebhookConfigured(rec)
	s.markTelegramConfigured(rec)
	data, _ := json.Marshal(rec)
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// handleDeleteVuln removes a single vulnerability from a scan record.
// DELETE /api/scans/{scanId}/vulns/{vulnId}
func (s *Server) handleDeleteVuln(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "DELETE only", http.StatusMethodNotAllowed)
		return
	}
	// Parse: /api/scans/{scanId}/vulns/{vulnId}
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/scans/")
	parts := strings.SplitN(trimmed, "/vulns/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		http.Error(w, "invalid path: expected /api/scans/{id}/vulns/{id}", http.StatusBadRequest)
		return
	}
	scanID := parts[0]
	vulnID, err := url.PathUnescape(parts[1])
	if err != nil {
		http.Error(w, "invalid vuln id encoding", http.StatusBadRequest)
		return
	}

	dir, rec := s.findScanByID(scanID)
	if rec == nil {
		dir, rec = s.findRecentScanForShortAlias(scanID)
	}
	if rec == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"scan not found"}`))
		return
	}
	if snapshot, ok := scanner.LoadFindingsSnapshot(dir); ok {
		for _, finding := range snapshot.UniqueFindings {
			if finding.ID == vulnID {
				http.Error(w, "scanner-backed findings are immutable; update status instead", http.StatusConflict)
				return
			}
		}
	}

	// Remove matching vulns
	filtered := make([]VulnSummary, 0, len(rec.Vulns))
	removed := 0
	for _, v := range rec.Vulns {
		if v.ID == vulnID {
			removed++
			continue
		}
		filtered = append(filtered, v)
	}
	if removed == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"vulnerability not found"}`))
		return
	}
	rec.Vulns = filtered

	// Persist to disk
	if dir != "" {
		s.saveScanRecordTo(rec, dir)
	}

	// Update in-memory instance if present
	s.instancesMu.Lock()
	if inst := s.instances[scanID]; inst != nil {
		inst.mu.Lock()
		inst.Vulns = filtered
		inst.VulnCount = len(filtered)
		inst.mu.Unlock()
	}
	s.instancesMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "deleted", "removed": removed, "remaining": len(filtered)})
}

// logMemStats logs current memory usage and goroutine count.
// Called between subdomain scans to track memory growth and detect leaks.
func logMemStats(label string) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	log.Printf("[MEM] %s — HeapAlloc: %d MB, HeapInuse: %d MB, Sys: %d MB, NumGC: %d, Goroutines: %d",
		label,
		m.HeapAlloc/1024/1024,
		m.HeapInuse/1024/1024,
		m.Sys/1024/1024,
		m.NumGC,
		runtime.NumGoroutine(),
	)
}

func llmProviderKey(model, apiBase string) string {
	model = strings.ToLower(strings.TrimSpace(model))
	apiBase = strings.ToLower(strings.TrimSpace(apiBase))
	if strings.Contains(apiBase, "vercel") || strings.HasPrefix(model, "vercel/") {
		return "vercel"
	}
	if idx := strings.Index(model, "/"); idx > 0 {
		return model[:idx]
	}
	switch {
	case strings.Contains(apiBase, "minimax"):
		return "minimax"
	case strings.Contains(apiBase, "anthropic"):
		return "anthropic"
	case strings.Contains(apiBase, "generativelanguage") || strings.Contains(apiBase, "googleapis"):
		return "google"
	case strings.Contains(apiBase, "deepseek"):
		return "deepseek"
	case strings.Contains(apiBase, "groq"):
		return "groq"
	case strings.Contains(apiBase, "openai"):
		return "openai"
	case strings.Contains(apiBase, "ollama") || strings.Contains(apiBase, "localhost:11434"):
		return "ollama"
	case model != "":
		return model
	default:
		return ""
	}
}

// startCaidoProxy launches Caido proxy in background if it's installed and not already running.
func startCaidoProxy() {
	cfg := config.Get()
	port := cfg.CaidoPort
	if port == 0 {
		port = 8080
	}

	// Check if something is already listening on the Caido port
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 1*time.Second)
	if err == nil {
		_ = conn.Close()
		log.Printf("Caido proxy already running on port %d", port)
		return
	}

	// Check if caido binary exists
	caidoPath, err := exec.LookPath("caido")
	if err != nil {
		log.Printf("Caido not installed — proxy features will use direct HTTP (install from https://caido.io)")
		return
	}

	// Start Caido in background with --no-open (headless)
	cmd := exec.Command(caidoPath, "--no-open", "--listen", fmt.Sprintf("127.0.0.1:%d", port))
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		log.Printf("⚠️  Failed to start Caido proxy: %v", err)
		return
	}

	// Don't wait for the process — let it run in background
	go func() {
		_ = cmd.Wait() // Reap zombie process
	}()

	log.Printf("✅ Caido proxy started on port %d (PID: %d)", port, cmd.Process.Pid)
}
