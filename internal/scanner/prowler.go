package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// prowlerRunner runs Prowler, a read-only AWS security & configuration audit. It
// is an assessment-only, opt-in Cloud/Compliance adapter. Credentials are passed
// to the child process via environment variables (never argv), added to the
// scan's redaction set, and never written to scan records.
type prowlerRunner struct{}

func (prowlerRunner) Name() string { return "prowler" }
func (prowlerRunner) Descriptor() Descriptor {
	return Descriptor{Name: "prowler", Summary: "Read-only AWS security & configuration audit", Phase: PhaseCloud, Weight: WeightLight, Applies: appliesToHost}
}
func (r prowlerRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	// Redact every credential value from output before running.
	req.Secrets = append(append([]string(nil), req.Secrets...), credentialSecretValues(req.CloudCredential)...)
	return executeSpec(ctx, r.Name(), req, cfg, buildProwler(req, cfg), emit)
}

func buildProwler(req Request, cfg Config) commandSpec {
	if strings.TrimSpace(cfg.ProwlerPath) == "" {
		return commandSpec{notApp: "Prowler executable is not configured", timeout: cfg.ProwlerTimeout}
	}
	provider := strings.ToLower(strings.TrimSpace(req.CloudCredential.Provider))
	if provider == "" {
		provider = "aws"
	}
	if provider != "aws" {
		return commandSpec{notApp: "this Prowler adapter supports the AWS provider only", timeout: cfg.ProwlerTimeout}
	}
	env := credentialEnv(req.CloudCredential)
	if len(env) == 0 {
		return commandSpec{notApp: "Prowler needs a supplied read-only AWS credential; none was resolved", timeout: cfg.ProwlerTimeout}
	}

	base := filepath.Join(req.ScanDir, "scanner-output", "prowler")
	// Prowler writes <output-directory>/<output-filename>.ocsf.json for the
	// json-ocsf format.
	artifact := filepath.Join(base, "results.ocsf.json")
	args := []string{
		"aws",
		"--output-formats", "json-ocsf",
		"--output-directory", base,
		"--output-filename", "results",
		"--ignore-exit-code-3", // findings present must not read as a run failure
	}
	return commandSpec{
		path:     cfg.ProwlerPath,
		args:     args,
		artifact: artifact,
		timeout:  cfg.ProwlerTimeout,
		env:      env,
		okExit:   map[int]bool{3: true},
		prepare:  func() error { return os.MkdirAll(base, 0o700) },
	}
}

// parseProwler reads Prowler's OCSF JSON (an array of finding objects) and emits
// a finding per FAIL. The OCSF shape varies across Prowler versions, so field
// extraction is defensive with fallbacks; unknown-shape rows are skipped rather
// than failing the whole parse.
func parseProwler(artifact string) ([]Finding, error) {
	data, err := os.ReadFile(artifact)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}
	var rows []map[string]any
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, fmt.Errorf("parse prowler ocsf json: %w", err)
	}
	var findings []Finding
	for i, row := range rows {
		status := strings.ToUpper(firstMapString(row, "status_code", "status"))
		if status != "FAIL" && status != "FAILED" {
			continue // only report failing checks
		}
		info, _ := row["finding_info"].(map[string]any)
		title := firstMapString(info, "title")
		if title == "" {
			title = firstMapString(row, "title", "check_title")
		}
		if title == "" {
			title = "Prowler check failed"
		}
		checkID := firstMapString(info, "uid")
		if checkID == "" {
			checkID = firstMapString(row, "check_id", "uid")
		}
		remediation := ""
		if rem, ok := row["remediation"].(map[string]any); ok {
			remediation = firstMapString(rem, "desc", "description")
		}
		findings = append(findings, Finding{
			SourceID:    fmt.Sprintf("prowler:%s", firstNonEmptyKB(checkID, fmt.Sprintf("%d", i))),
			Scanner:     "prowler",
			Title:       title,
			Severity:    normalizeCloudSeverity(firstMapString(row, "severity")),
			Endpoint:    resourceIdentifier(row),
			Description: strings.TrimSpace(firstMapString(info, "desc", "description")),
			Remediation: strings.TrimSpace(remediation),
			CWE:         "CWE-1008",
		})
	}
	return findings, nil
}

// credentialEnv turns a resolved cloud credential into "KEY=value" env entries,
// sorted for deterministic command construction.
func credentialEnv(c CloudCredential) []string {
	if len(c.Env) == 0 {
		return nil
	}
	keys := make([]string, 0, len(c.Env))
	for k := range c.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+c.Env[k])
	}
	return out
}

// credentialSecretValues returns the raw secret values for redaction.
func credentialSecretValues(c CloudCredential) []string {
	out := make([]string, 0, len(c.Env))
	for _, v := range c.Env {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}

func normalizeCloudSeverity(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "informational", "info":
		return "info"
	default:
		return "medium"
	}
}

func firstMapString(m map[string]any, keys ...string) string {
	if m == nil {
		return ""
	}
	for _, k := range keys {
		if v, ok := m[k].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// resourceIdentifier best-effort extracts the first affected resource UID/name.
func resourceIdentifier(row map[string]any) string {
	res, ok := row["resources"].([]any)
	if !ok || len(res) == 0 {
		return ""
	}
	first, ok := res[0].(map[string]any)
	if !ok {
		return ""
	}
	return firstMapString(first, "uid", "name", "id")
}
