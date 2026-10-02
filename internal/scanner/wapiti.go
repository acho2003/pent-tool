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
)

const wapitiMaxDuration = 20 * time.Minute

// wapitiRunner is the web-fuzzing stage. Wapiti crawls from the seed URL (within
// a bounded scope) and fuzzes discovered parameters. It is an assessment-only,
// opt-in runner like nikto/dalfox. Katana-discovered URLs are added as extra
// crawl entry points so unlinked routes are still covered.
type wapitiRunner struct{}

func (wapitiRunner) Name() string { return "wapiti" }
func (wapitiRunner) Descriptor() Descriptor {
	return Descriptor{Name: "wapiti", Summary: "Bounded web fuzzing of a web host and its discovered endpoints", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightHeavy, Applies: appliesToHost}
}
func (r wapitiRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	return executeSpec(ctx, r.Name(), req, cfg, buildWapiti(req, cfg), emit)
}

// wapitiMaxStartURLs bounds how many discovered endpoints are added as extra
// crawl entry points, so a large crawl result can't blow up the fuzz scope.
const wapitiMaxStartURLs = 50

func buildWapiti(req Request, cfg Config) commandSpec {
	if strings.TrimSpace(cfg.WapitiPath) == "" {
		return commandSpec{notApp: "Wapiti executable is not configured", timeout: cfg.WapitiTimeout}
	}
	targets := requestEndpointTargets(req)
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

	// Bounded run: URL-scoped crawl, capped scan time, JSON output, flushed
	// session so reruns don't reuse stale state, and no interactive prompts.
	args := []string{
		"-u", target,
		"--scope", "folder",
		"--max-scan-time", strconv.Itoa(scanSeconds),
		"--flush-session",
		"--format", "json",
		"-o", artifact,
		"--verify-ssl", "0",
	}
	// Add katana-discovered in-scope URLs as extra entry points (bounded).
	added := 0
	for _, e := range targets {
		if e == target {
			continue
		}
		if added >= wapitiMaxStartURLs {
			break
		}
		if isHTTPish(e) {
			args = append(args, "--start", e)
			added++
		}
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
