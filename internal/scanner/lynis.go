package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var lynisAliasPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var lynisIssuePattern = regexp.MustCompile(`^\s*[-*!]?\s*(.+?)\s+\[([A-Z][A-Z0-9]+-\d+)\]\s*$`)

type lynisRunner struct{}

func (lynisRunner) Name() string { return "lynis" }
func (lynisRunner) Descriptor() Descriptor {
	return Descriptor{Name: "lynis", Summary: "Bounded remote host audit through an SSH alias", Phase: PhaseServer, Weight: WeightLight}
}
func (r lynisRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	return executeSpec(ctx, r.Name(), req, cfg, buildLynis(req, cfg), emit)
}

func buildLynis(req Request, cfg Config) commandSpec {
	alias := strings.TrimSpace(req.VulsSSHHost)
	if !req.TypedAssessment || !lynisAliasPattern.MatchString(alias) {
		return commandSpec{notApp: "Lynis requires a target-bound operator-managed SSH alias"}
	}
	if cfg.SSHPath == "" {
		cfg.SSHPath = "ssh"
	}
	duration := cfg.LynisTimeout
	if duration <= 0 || duration > 30*time.Minute {
		duration = 30 * time.Minute
	}
	args := []string{"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10", "-o", "ClearAllForwardings=yes", "-o", "RequestTTY=no"}
	if cfg.VulsSSHConfigPath != "" {
		if info, err := os.Stat(cfg.VulsSSHConfigPath); err != nil || !info.Mode().IsRegular() {
			return commandSpec{notApp: "operator-managed SSH config file is unavailable"}
		}
		args = append(args, "-F", cfg.VulsSSHConfigPath)
	}
	// The remote command is fixed. Target input appears only as a validated
	// SSH alias, never in remote shell text or a local shell invocation.
	args = append(args, alias, "lynis audit system --quick --nocolors")
	return commandSpec{path: cfg.SSHPath, args: args, artifact: filepath.Join(req.ScanDir, "scanner-output", "lynis", "stdout.log"), timeout: duration,
		classify: func(exitCode int, output string) (string, string, bool) {
			if exitCode == 255 {
				return "failed", "SSH connection or host-key verification failed; host audit was not completed", true
			}
			if exitCode == 127 || strings.Contains(output, "lynis: command not found") {
				return "not_applicable", "Lynis is unavailable on the bound remote host", true
			}
			return "", "", false
		}}
}

// parseLynis records only summary warnings and suggestions with a Lynis test
// identifier. Other display text is retained in the native artifact, not
// interpreted as a vulnerability.
func parseLynis(path string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	section := ""
	var findings []Finding
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		switch {
		case strings.HasPrefix(lower, "warnings (") || lower == "warnings":
			section = "warning"
			continue
		case strings.HasPrefix(lower, "suggestions (") || lower == "suggestions":
			section = "suggestion"
			continue
		case strings.HasPrefix(lower, "follow-up") || strings.HasPrefix(lower, "hardening index"):
			section = ""
		}
		if section == "" {
			continue
		}
		match := lynisIssuePattern.FindStringSubmatch(trimmed)
		if len(match) != 3 {
			continue
		}
		id := match[2]
		key := section + ":" + id
		if seen[key] {
			continue
		}
		seen[key] = true
		severity := "low"
		if section == "warning" {
			severity = "medium"
		}
		findings = append(findings, Finding{SourceID: fmt.Sprintf("lynis:%s:%s", section, id), Scanner: "lynis", Title: strings.TrimSpace(match[1]), Severity: severity, Description: "Lynis " + section + " for control " + id, Evidence: trimmed, Confidence: "LOW"})
	}
	return findings, nil
}
