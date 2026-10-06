package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

const wapitiMaxDuration = 20 * time.Minute

// wapitiRunner is the web-fuzzing stage. It is an assessment-only, opt-in
// runner like nikto/dalfox, and restricted to declared test environments
// (AdapterPolicyRestriction): Wapiti attacks the dispatcher-approved endpoints
// it is given as entry points with a reviewed GET-only module allowlist and
// does not crawl beyond them.
type wapitiRunner struct{}

func (wapitiRunner) Name() string { return "wapiti" }
func (wapitiRunner) Descriptor() Descriptor {
	return Descriptor{Name: "wapiti", Summary: "Bounded web fuzzing of a web host and its discovered endpoints", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightHeavy, Applies: appliesToHost}
}
func (r wapitiRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	if req.WapitiPostApproval != nil {
		return runWapitiPost(ctx, req, cfg, emit)
	}
	if expandedWorkflowRequest(req) && len(req.EndpointTargets) > 50 && req.TestEnvironment {
		return runWapitiBatches(ctx, req, cfg, emit)
	}
	return executePolicySpec(ctx, r.Name(), req, cfg, buildWapiti(req, cfg), emit)
}

// wapitiMaxStartURLs bounds how many discovered endpoints are added as extra
// crawl entry points, so a large crawl result can't blow up the fuzz scope.
const wapitiMaxStartURLs = 50

// wapitiTestEnvironmentModules is the reviewed -m allowlist (module names
// verified against the pinned wapiti 3.3.2 wapitiCore/attack/modules/core.py;
// "name:get" restricts a module to GET requests). It keeps the passive
// response checks and read-only reflected/error-based GET probes. Left out:
// ssrf, xxe, log4shell (external callbacks), exec, shellshock, spring4shell
// (code execution), upload, permanentxss, csrf (form replay/stored payloads),
// methods, htaccess (non-GET methods), brute_login_form, buster, nikto,
// backup, timesql (brute-force or heavy), takeover, htp, wapp, cms, wp_enum
// (external lookups or broad enumeration) and the remaining device probes.
const wapitiTestEnvironmentModules = "passive,xss:get,sql:get,file:get,redirect:get,crlf:get"

func buildWapiti(req Request, cfg Config) commandSpec {
	if restricted, reason := requestPolicyRestriction("wapiti", req); restricted {
		return commandSpec{notApp: reason, timeout: cfg.WapitiTimeout}
	}
	if strings.TrimSpace(cfg.WapitiPath) == "" {
		return commandSpec{notApp: "Wapiti executable is not configured", timeout: cfg.WapitiTimeout}
	}
	targets := wapitiAllowedTargets(req.AppScope, requestEndpointTargets(req))
	if req.StructuredDispatch && len(targets) == 0 {
		return commandSpec{notApp: "Wapiti has no dispatcher-approved parameter or form endpoint to test", timeout: cfg.WapitiTimeout}
	}
	target := strings.TrimSpace(req.Target)
	if req.StructuredDispatch {
		target = targets[0]
	}
	u, err := url.Parse(target)
	if err != nil || !u.IsAbs() || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return commandSpec{notApp: "Wapiti requires an explicit HTTP(S) URL", timeout: cfg.WapitiTimeout}
	}
	if len(wapitiAllowedTargets(req.AppScope, []string{target})) == 0 {
		return commandSpec{notApp: "Wapiti target is outside the approved scope or excluded", timeout: cfg.WapitiTimeout}
	}

	base := filepath.Join(req.ScanDir, "scanner-output", "wapiti")
	artifact := filepath.Join(base, "results.json")

	duration := cfg.WapitiTimeout
	if duration <= 0 || duration > wapitiMaxDuration {
		duration = wapitiMaxDuration
	}
	// Reserve a little headroom so wapiti flushes its JSON before the outer
	// process deadline fires.
	scanSeconds := int(duration / time.Second)
	if scanSeconds > 30 {
		scanSeconds -= 15
	}
	if scanSeconds < 1 {
		scanSeconds = 1
	}

	// Bounded run (flags verified against wapiti 3.3.2 commandline.py):
	//   --scope url -d 0 : explore only the given entry points; discovered
	//                      links and forms are never followed or submitted
	//   -m <allowlist>   : reviewed GET-only modules
	//   --tasks 1        : one concurrent exploration task
	//   capped scan time, JSON output, flushed session so reruns don't reuse
	//   stale state, and no interactive prompts.
	args := []string{
		"-u", target,
		"--scope", "url",
		"-d", "0",
		"-m", wapitiTestEnvironmentModules,
		"--tasks", "1",
		"--max-scan-time", strconv.Itoa(scanSeconds),
		"--flush-session",
		"--format", "json",
		"-o", artifact,
		"--verify-ssl", "0",
	}
	// Add the other dispatcher-approved URLs as entry points (bounded).
	var starts []string
	for _, e := range targets {
		if e == target {
			continue
		}
		if len(starts) >= wapitiMaxStartURLs {
			break
		}
		if isHTTPish(e) {
			starts = append(starts, e)
		}
	}
	for _, x := range wapitiExcludePatterns(req.AppScope, append([]string{target}, starts...)) {
		args = append(args, "-x", x)
	}
	for _, e := range starts {
		args = append(args, "--start", e)
	}
	for _, h := range cfg.ScanHeaders {
		if strings.TrimSpace(h) != "" {
			args = append(args, "-H", strings.TrimSpace(h))
		}
	}
	for _, h := range strings.Split(req.TargetAuth, "\n") {
		if strings.TrimSpace(h) != "" {
			args = append(args, "-H", strings.TrimSpace(h))
		}
	}

	return commandSpec{
		path:     cfg.WapitiPath,
		args:     args,
		artifact: artifact,
		timeout:  duration,
		prepare: func() error {
			return os.MkdirAll(base, 0o700)
		},
	}
}

// wapitiAllowedTargets drops URLs the application scope does not allow or
// excludes for GET. The dispatch gate already filters endpoints; this keeps an
// excluded route from ever becoming a Wapiti entry point. A nil scope (legacy)
// keeps every URL.
func wapitiAllowedTargets(scope *assessment.AppScope, urls []string) []string {
	if scope == nil {
		return urls
	}
	var out []string
	for _, raw := range urls {
		if ok, _ := scope.Allows(raw); !ok {
			continue
		}
		if excluded, _ := scope.Excluded("GET", raw); excluded {
			continue
		}
		out = append(out, raw)
	}
	return out
}

// wapitiExcludePatterns renders each configured exclusion as a Wapiti -x
// wildcard URL for every entry-point origin it applies to. Wapiti matches -x
// against the whole URL ("*" is any run, anchored at both ends), so a trailing
// "*" also covers sub-paths and query strings; over-matching (e.g. /logout2)
// only excludes more. Wapiti matches case-sensitively and for every method,
// so the dispatch gate stays the authoritative exclusion check.
func wapitiExcludePatterns(scope *assessment.AppScope, urls []string) []string {
	if scope == nil {
		return nil
	}
	exclusions := scope.Exclusions()
	if len(exclusions) == 0 {
		return nil
	}
	var origins []string
	normalized := map[string]string{}
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		origin := u.Scheme + "://" + u.Host
		if _, seen := normalized[origin]; seen {
			continue
		}
		key := origin
		if o, err := assessment.ParseApprovedOrigin("", origin); err == nil {
			key = o.Origin()
		}
		normalized[origin] = key
		origins = append(origins, origin)
	}
	var out []string
	seen := map[string]bool{}
	for _, e := range exclusions {
		pattern := strings.TrimSpace(e.PathPattern)
		if pattern == "" {
			continue
		}
		if !strings.HasPrefix(pattern, "/") {
			pattern = "/" + pattern
		}
		for _, origin := range origins {
			if e.Origin != "" && e.Origin != normalized[origin] {
				continue
			}
			x := origin + strings.TrimSuffix(pattern, "/") + "*"
			if !seen[x] {
				seen[x] = true
				out = append(out, x)
			}
		}
	}
	return out
}

// wapitiReport is the subset of wapiti's JSON output we consume.
type wapitiReport struct {
	Vulnerabilities map[string][]wapitiEntry `json:"vulnerabilities"`
	Classifications map[string]wapitiClass   `json:"classifications"`
}

type wapitiEntry struct {
	Method    string `json:"method"`
	Path      string `json:"path"`
	Info      string `json:"info"`
	Level     int    `json:"level"`
	Parameter string `json:"parameter"`
	HTTPReq   string `json:"http_request"`
	CURLCmd   string `json:"curl_command"`
	WSTG      any    `json:"wstg"`
}

type wapitiClass struct {
	Ref map[string]string `json:"ref"`
}

// wapitiLevelToSeverity maps wapiti's numeric level to our severity scale.
func wapitiLevelToSeverity(level int) string {
	switch {
	case level >= 3:
		return "high"
	case level == 2:
		return "medium"
	case level == 1:
		return "low"
	default:
		return "info"
	}
}

// parseWapiti reads wapiti's JSON report into normalized findings. The CWE is
// pulled from the classifications block when present.
func parseWapiti(artifact string) ([]Finding, error) {
	data, err := os.ReadFile(artifact)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}
	var rep wapitiReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("parse wapiti json: %w", err)
	}

	var findings []Finding
	i := 0
	for category, entries := range rep.Vulnerabilities {
		cwe := wapitiCWE(rep.Classifications, category)
		for _, e := range entries {
			findings = append(findings, Finding{
				SourceID:    fmt.Sprintf("wapiti:%s:%d", category, i),
				Scanner:     "wapiti",
				Title:       category,
				Severity:    wapitiLevelToSeverity(e.Level),
				Endpoint:    e.Path,
				Method:      strings.ToUpper(strings.TrimSpace(e.Method)),
				Parameter:   e.Parameter,
				Description: strings.TrimSpace(e.Info),
				Evidence:    strings.TrimSpace(e.CURLCmd),
				EvidenceRef: e.HTTPReq,
				CWE:         cwe,
			})
			i++
		}
	}
	return findings, nil
}

// wapitiCWE extracts a CWE-xxx identifier from the classification ref map for a
// vulnerability category, if wapiti provided one.
func wapitiCWE(classes map[string]wapitiClass, category string) string {
	c, ok := classes[category]
	if !ok {
		return ""
	}
	for k, v := range c.Ref {
		if strings.EqualFold(k, "cwe") || strings.HasPrefix(strings.ToUpper(k), "CWE") {
			id := strings.TrimSpace(v)
			if id == "" {
				continue
			}
			if !strings.HasPrefix(strings.ToUpper(id), "CWE-") {
				id = "CWE-" + id
			}
			return id
		}
	}
	return ""
}
