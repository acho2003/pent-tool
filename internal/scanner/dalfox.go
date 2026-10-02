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

const dalfoxMaxDuration = 15 * time.Minute

// dalfoxRunner is the reflected/DOM XSS detection stage. It runs over the
// parameterized URLs the katana crawl discovered (Request.WebEndpoints), so it
// only tests endpoints that actually take input. It is an assessment-only,
// opt-in runner (not part of legacy scans), consistent with nikto.
type dalfoxRunner struct{}

func (dalfoxRunner) Name() string { return "dalfox" }
func (dalfoxRunner) Descriptor() Descriptor {
	return Descriptor{Name: "dalfox", Summary: "XSS detection over discovered parameterized URLs", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightLight, Applies: appliesToHost}
}
func (r dalfoxRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	run := executeSpec(ctx, r.Name(), req, cfg, buildDalfox(req, cfg), emit)
	if run.Status == "completed" {
		// A completed run still did not attempt headless DOM XSS verification.
		run.Limitations = append(run.Limitations, RunLimitation{Kind: LimitationHeadlessExcluded, Reason: dalfoxHeadlessLimitation})
	}
	return run
}

// dalfoxHeadlessLimitation explains the excluded headless verification on
// completed Dalfox runs.
const dalfoxHeadlessLimitation = "headless DOM XSS verification is disabled: its browser requests bypass the rate delay and cannot be scope-checked"

// parameterizedURLs returns the subset of candidate URLs that carry a query
// string, since XSS parameter testing needs an input to fuzz. The seed target is
// included when it is itself parameterized. Order is preserved and duplicates
// dropped.
func parameterizedURLs(target string, endpoints []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(raw string) {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.RawQuery == "" {
			return
		}
		if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return
		}
		if seen[raw] {
			return
		}
		seen[raw] = true
		out = append(out, raw)
	}
	add(target)
	for _, e := range endpoints {
		add(e)
	}
	return out
}

func buildDalfox(req Request, cfg Config) commandSpec {
	if strings.TrimSpace(cfg.DalfoxPath) == "" {
		return commandSpec{notApp: "Dalfox executable is not configured", timeout: cfg.DalfoxTimeout}
	}
	target := req.Target
	if req.StructuredDispatch {
		target = ""
	}
	urls := parameterizedURLs(target, requestEndpointTargets(req))
	if len(urls) == 0 {
		return commandSpec{notApp: "Dalfox needs at least one discovered URL with a query parameter to test", timeout: cfg.DalfoxTimeout}
	}

	base := filepath.Join(req.ScanDir, "scanner-output", "dalfox")
	artifact := filepath.Join(base, "results.json")
	listPath := filepath.Join(base, "targets.txt")

	duration := cfg.DalfoxTimeout
	if duration <= 0 || duration > dalfoxMaxDuration {
		duration = dalfoxMaxDuration
	}

	// Bounded, machine-readable detection run (flags verified against the
	// pinned dalfox v2.13.0 cmd/root.go):
	//   file <list>   : test the discovered parameterized URLs
	//   --format json : structured PoC output for the parser
	//   --silence --no-color : quiet, parseable stdout
	//   --skip-bav    : skip basic-another-vuln probing (stay focused on XSS)
	//   --skip-mining-all : no DOM/dictionary parameter mining; only the
	//                   dispatcher-approved parameters are tested
	//   --skip-headless : the headless DOM verifier runs beside the workers,
	//                   outside the --delay limiter, and its browser requests
	//                   cannot be scope-checked
	//   --worker 1    : one request at a time, so --delay bounds the rate
	//   --timeout     : per-request timeout in seconds
	args := []string{
		"file", listPath,
		"--format", "json",
		"-o", artifact,
		"--silence",
		"--no-color",
		"--skip-bav",
		"--skip-mining-all",
		"--skip-headless",
		"--worker", "1",
		"--timeout", "10",
	}
	if cfg.RateRPS > 0 {
		// With a single worker, a per-request delay (ms) rounded up from the
		// profile rate keeps Dalfox at or below RateRPS.
		delayMS := (1000 + cfg.RateRPS - 1) / cfg.RateRPS
		args = append(args, "--delay", strconv.Itoa(delayMS))
	}
	// Only a typed assessment's TargetAuth is the verified, target-bound
	// session (RunAssessmentJobs attaches it after verification); operator
	// scan headers and legacy TargetAuth are never forwarded.
	if req.TypedAssessment {
		for _, h := range strings.Split(req.TargetAuth, "\n") {
			if h = strings.TrimSpace(h); h != "" {
				args = append(args, "-H", h)
			}
		}
	}

	endpoints := append([]string(nil), urls...)
	return commandSpec{
		path:     cfg.DalfoxPath,
		args:     args,
		artifact: artifact,
		timeout:  duration,
		prepare: func() error {
			if err := os.MkdirAll(base, 0o700); err != nil {
				return fmt.Errorf("create Dalfox output directory: %w", err)
			}
			return os.WriteFile(listPath, []byte(strings.Join(endpoints, "\n")+"\n"), 0o600)
		},
	}
}

// dalfoxPoC is one entry of dalfox's `--format json` output array.
type dalfoxPoC struct {
	Type       string `json:"type"`
	InjectType string `json:"inject_type"`
	Method     string `json:"method"`
	Data       string `json:"data"` // the tested URL
	Param      string `json:"param"`
	Evidence   string `json:"evidence"`
	CWE        string `json:"cwe"`
	Severity   string `json:"severity"`
	Message    string `json:"message_str"`
	PoC        string `json:"poc"`
}

// parseDalfox reads dalfox's JSON PoC array into normalized findings. Only actual
// vulnerability entries (type "V" / "G") are reported; informational grep/analysis
// lines are ignored.
func parseDalfox(artifact string) ([]Finding, error) {
	data, err := os.ReadFile(artifact)
	if err != nil {
		return nil, err
	}
	data = []byte(strings.TrimSpace(string(data)))
	if len(data) == 0 {
		return nil, nil
	}
	var pocs []dalfoxPoC
	if err := json.Unmarshal(data, &pocs); err != nil {
		return nil, fmt.Errorf("parse dalfox json: %w", err)
	}
	var findings []Finding
	for i, p := range pocs {
		if !strings.EqualFold(p.Type, "V") && !strings.EqualFold(p.Type, "G") {
			continue // skip non-vulnerability rows
		}
		target := p.Data
		if target == "" {
			target = p.PoC
		}
		cwe := strings.TrimSpace(p.CWE)
		if cwe != "" && !strings.HasPrefix(strings.ToUpper(cwe), "CWE-") {
			cwe = "CWE-" + cwe
		}
		sev := strings.ToLower(strings.TrimSpace(p.Severity))
		if sev == "" {
			sev = "medium"
		}
		findings = append(findings, Finding{
			SourceID:    fmt.Sprintf("dalfox:%d", i),
			Scanner:     "dalfox",
			Title:       "Cross-Site Scripting (XSS)",
			Severity:    sev,
			Target:      target,
			Endpoint:    target,
			Method:      strings.ToUpper(strings.TrimSpace(p.Method)),
			Parameter:   p.Param,
			Description: strings.TrimSpace(p.Message),
			Evidence:    strings.TrimSpace(p.Evidence),
			EvidenceRef: p.PoC,
			CWE:         cwe,
		})
	}
	return findings, nil
}
