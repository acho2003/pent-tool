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
	return executeSpec(ctx, r.Name(), req, cfg, buildDalfox(req, cfg), emit)
}

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
	urls := parameterizedURLs(req.Target, req.WebEndpoints)
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

	// Bounded, machine-readable detection run:
	//   file <list>   : test the discovered parameterized URLs
	//   --format json : structured PoC output for the parser
	//   --silence --no-color : quiet, parseable stdout
	//   --skip-bav    : skip basic-another-vuln probing (stay focused on XSS)
	//   --worker/-d   : bounded concurrency and a per-request delay
	//   --timeout     : per-request timeout in seconds
	args := []string{
		"file", listPath,
		"--format", "json",
		"-o", artifact,
		"--silence",
		"--no-color",
		"--skip-bav",
		"--worker", "10",
		"--timeout", "10",
	}
	if cfg.RateRPS > 0 {
		// Translate the profile rate into a per-request delay (ms) so the scan
		// respects the same gentleness the rest of the web track uses.
		delayMS := 1000 / cfg.RateRPS
		if delayMS > 0 {
			args = append(args, "--delay", strconv.Itoa(delayMS))
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
