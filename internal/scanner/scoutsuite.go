package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// scoutSuiteRunner runs Scout Suite, a read-only multi-cloud security posture
// audit. Assessment-only, opt-in Cloud/Compliance adapter. Credentials go to the
// child via environment variables (never argv), are redacted from output, and are
// never persisted.
type scoutSuiteRunner struct{}

func (scoutSuiteRunner) Name() string { return "scoutsuite" }
func (scoutSuiteRunner) Descriptor() Descriptor {
	return Descriptor{Name: "scoutsuite", Summary: "Read-only multi-cloud security posture audit", Phase: PhaseCloud, Weight: WeightLight, Applies: appliesToHost}
}
func (r scoutSuiteRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	req.Secrets = append(append([]string(nil), req.Secrets...), credentialSecretValues(req.CloudCredential)...)
	return executeSpec(ctx, r.Name(), req, cfg, buildScoutSuite(req, cfg), emit)
}

// scoutSuiteProviders maps our provider id to Scout Suite's subcommand.
var scoutSuiteProviders = map[string]string{"aws": "aws", "gcp": "gcp", "azure": "azure"}

func buildScoutSuite(req Request, cfg Config) commandSpec {
	if strings.TrimSpace(cfg.ScoutSuitePath) == "" {
		return commandSpec{notApp: "Scout Suite executable is not configured", timeout: cfg.ScoutSuiteTimeout}
	}
	provider := strings.ToLower(strings.TrimSpace(req.CloudCredential.Provider))
	sub, ok := scoutSuiteProviders[provider]
	if !ok {
		return commandSpec{notApp: "Scout Suite adapter supports aws, gcp, or azure providers", timeout: cfg.ScoutSuiteTimeout}
	}
	env := credentialEnv(req.CloudCredential)
	if len(env) == 0 {
		return commandSpec{notApp: "Scout Suite needs a supplied read-only cloud credential; none was resolved", timeout: cfg.ScoutSuiteTimeout}
	}

	base := filepath.Join(req.ScanDir, "scanner-output", "scoutsuite")
	reportDir := filepath.Join(base, "report")
	// Read-only audit: --no-browser (never open a UI), --result-format json,
	// --report-dir under the scan dir, --force to overwrite on rerun.
	args := []string{
		sub,
		"--no-browser",
		"--result-format", "json",
		"--report-dir", reportDir,
		"--force",
	}
	return commandSpec{
		path:     cfg.ScoutSuitePath,
		args:     args,
		artifact: reportDir,
		timeout:  cfg.ScoutSuiteTimeout,
		env:      env,
		prepare:  func() error { return os.MkdirAll(reportDir, 0o700) },
		// Scout Suite's results filename embeds the provider/account, so locate it.
		findOutput: func() string { return findScoutSuiteResults(reportDir) },
	}
}

// findScoutSuiteResults locates the results file Scout Suite wrote under the
// report dir (scoutsuite-results/scoutsuite_results_*.{js,json}).
func findScoutSuiteResults(reportDir string) string {
	for _, pat := range []string{
		filepath.Join(reportDir, "scoutsuite-results", "scoutsuite_results_*.js"),
		filepath.Join(reportDir, "scoutsuite-results", "scoutsuite_results_*.json"),
		filepath.Join(reportDir, "scoutsuite_results_*.js"),
		filepath.Join(reportDir, "scoutsuite_results_*.json"),
	} {
		if matches, _ := filepath.Glob(pat); len(matches) > 0 {
			return matches[0]
		}
	}
	return ""
}

// scoutSuiteResults is the subset we consume: services -> findings.
type scoutSuiteResults struct {
	Services map[string]struct {
		Findings map[string]struct {
			Description  string `json:"description"`
			Rationale    string `json:"rationale"`
			Remediation  string `json:"remediation"`
			Level        string `json:"level"` // "danger" | "warning"
			FlaggedItems int    `json:"flagged_items"`
		} `json:"findings"`
	} `json:"services"`
}

// parseScoutSuite reads the results file (stripping the "scoutsuite_results ="
// JS prefix when present) and emits a finding per flagged service finding.
func parseScoutSuite(artifact string) ([]Finding, error) {
	data, err := os.ReadFile(artifact)
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		return nil, nil
	}
	// The .js variant is `scoutsuite_results = { ... }`; keep only the JSON body.
	if idx := strings.Index(text, "{"); idx > 0 && !strings.HasPrefix(text, "{") {
		text = text[idx:]
	}
	var results scoutSuiteResults
	if err := json.Unmarshal([]byte(text), &results); err != nil {
		return nil, fmt.Errorf("parse scoutsuite results: %w", err)
	}
	var findings []Finding
	for service, svc := range results.Services {
		for id, f := range svc.Findings {
			if f.FlaggedItems <= 0 {
				continue // only flagged findings are issues
			}
			findings = append(findings, Finding{
				SourceID:    fmt.Sprintf("scoutsuite:%s:%s", service, id),
				Scanner:     "scoutsuite",
				Title:       firstNonEmptyKB(f.Description, id),
				Severity:    scoutSuiteLevelSeverity(f.Level),
				Endpoint:    service,
				Description: strings.TrimSpace(f.Rationale),
				Remediation: strings.TrimSpace(f.Remediation),
				CWE:         "CWE-1008",
			})
		}
	}
	return findings, nil
}

func scoutSuiteLevelSeverity(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "danger":
		return "high"
	case "warning":
		return "medium"
	default:
		return "low"
	}
}
