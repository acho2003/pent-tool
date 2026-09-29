package scanner

import (
	"context"
	"encoding/csv"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const sqlmapMaxDuration = 20 * time.Minute

// sqlmapRunner is the SQL-injection DETECTION stage. It is the most sensitive
// adapter, so it is doubly constrained:
//
//  1. Opt-in only: it runs exclusively against Request.SQLMapApprovedURLs —
//     parameterized URLs an operator explicitly approved. It never touches
//     auto-discovered URLs.
//  2. Detection-only: buildSqlmap emits a fixed, bounded, non-destructive flag
//     set. Data exfiltration, OS/SQL shells, and file read/write are never
//     requested; sqlmapForbiddenFlags documents the invariant the test enforces.
type sqlmapRunner struct{}

func (sqlmapRunner) Name() string { return "sqlmap" }
func (sqlmapRunner) Descriptor() Descriptor {
	return Descriptor{Name: "sqlmap", Summary: "Opt-in, detection-only SQL injection checks on approved parameters", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightHeavy, Applies: appliesToHost}
}
func (r sqlmapRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	return executeSpec(ctx, r.Name(), req, cfg, buildSqlmap(req, cfg), emit)
}

// sqlmapForbiddenFlags are options that would make sqlmap do more than detect.
// buildSqlmap must never emit any of these; the safety test asserts it.
var sqlmapForbiddenFlags = []string{
	"--dump", "--dump-all", "--dumps", "--os-shell", "--os-pwn", "--os-cmd",
	"--sql-shell", "--sql-query", "--file-read", "--file-write", "--file-dest",
	"--priv-esc", "--reg-read", "--reg-add", "--reg-del", "--passwords",
	"--users", "--tables", "--columns", "--schema", "--all",
}

// approvedSQLMapURLs returns the explicitly approved parameterized URLs, keeping
// only valid http(s) URLs that carry a query string (SQLi detection needs a
// parameter). Order preserved, duplicates dropped.
func approvedSQLMapURLs(approved []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, raw := range approved {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.RawQuery == "" || u.Host == "" {
			continue
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			continue
		}
		if seen[raw] {
			continue
		}
		seen[raw] = true
		out = append(out, raw)
	}
	return out
}

func buildSqlmap(req Request, cfg Config) commandSpec {
	if strings.TrimSpace(cfg.SqlmapPath) == "" {
		return commandSpec{notApp: "SQLMap executable is not configured", timeout: cfg.SqlmapTimeout}
	}
	urls := approvedSQLMapURLs(req.SQLMapApprovedURLs)
	if len(urls) == 0 {
		return commandSpec{notApp: "SQLMap runs only on explicitly approved parameterized URLs; none were approved for this scan", timeout: cfg.SqlmapTimeout}
	}

	base := filepath.Join(req.ScanDir, "scanner-output", "sqlmap")
	outputDir := filepath.Join(base, "session")
	resultsCSV := filepath.Join(base, "results.csv")
	listPath := filepath.Join(base, "targets.txt")

	duration := cfg.SqlmapTimeout
	if duration <= 0 || duration > sqlmapMaxDuration {
		duration = sqlmapMaxDuration
	}

	// Fixed detection-only flag set. Nothing here reads/writes files on the
	// target, opens a shell, or exfiltrates data.
	//   -m <list>          : the approved URL list (bulk mode)
	//   --batch            : never prompt (and never take a destructive default)
	//   --level 1 --risk 1 : lowest, safest probing depth
	//   --technique=BEUST  : detection techniques only
	//   --threads 2        : bounded concurrency
	//   --timeout/--retries: bounded per-request budget
	//   --smart --skip-waf : reduce noise; do not attempt WAF bypass tricks
	//   --results-file     : machine-readable CSV of injectable params
	//   --output-dir       : contain sqlmap's session/artifacts under the scan dir
	//   --disable-coloring : clean logs
	args := []string{
		"-m", listPath,
		"--batch",
		"--level", "1",
		"--risk", "1",
		"--technique=BEUST",
		"--threads", "2",
		"--timeout", "10",
		"--retries", "1",
		"--smart",
		"--disable-coloring",
		"--results-file", resultsCSV,
		"--output-dir", outputDir,
	}
	if cfg.RateRPS > 0 {
		delay := 1 / cfg.RateRPS
		if delay > 0 {
			args = append(args, "--delay", strconv.Itoa(delay))
		}
	}
	for _, h := range strings.Split(req.TargetAuth, "\n") {
		if strings.TrimSpace(h) != "" {
			args = append(args, "-H", strings.TrimSpace(h))
		}
	}

	endpoints := append([]string(nil), urls...)
	return commandSpec{
		path:     cfg.SqlmapPath,
		args:     args,
		artifact: resultsCSV,
		timeout:  duration,
		prepare: func() error {
			if err := os.MkdirAll(outputDir, 0o700); err != nil {
				return fmt.Errorf("create SQLMap output directory: %w", err)
			}
			return os.WriteFile(listPath, []byte(strings.Join(endpoints, "\n")+"\n"), 0o600)
		},
	}
}

// parseSqlmap reads sqlmap's --results-file CSV into findings. The CSV header is
// "Target URL,Place,Parameter,Technique(s),Note(s)"; each data row is one
// injectable parameter -> one SQL-injection finding.
func parseSqlmap(artifact string) ([]Finding, error) {
	f, err := os.Open(artifact)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse sqlmap csv: %w", err)
	}
	var findings []Finding
	for i, row := range rows {
		if len(row) < 3 {
			continue
		}
		// Skip the header row.
		if i == 0 && strings.EqualFold(strings.TrimSpace(row[0]), "Target URL") {
			continue
		}
		target := strings.TrimSpace(row[0])
		place := strings.TrimSpace(row[1])
		param := strings.TrimSpace(row[2])
		technique := ""
		if len(row) >= 4 {
			technique = strings.TrimSpace(row[3])
		}
		if target == "" || param == "" {
			continue
		}
		findings = append(findings, Finding{
			SourceID:    fmt.Sprintf("sqlmap:%d", i),
			Scanner:     "sqlmap",
			Title:       "SQL Injection",
			Severity:    "high",
			Target:      target,
			Endpoint:    target,
			Parameter:   param,
			Description: strings.TrimSpace(fmt.Sprintf("Injectable %s parameter %q (%s)", place, param, technique)),
			CWE:         "CWE-89",
		})
	}
	return findings, nil
}
