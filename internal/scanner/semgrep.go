package scanner

import (
	"fmt"
	"path/filepath"
	"strings"
)

// buildSemgrep uses an explicit registry ruleset: auto configuration refuses
// to run when the runtime's metrics policy disables telemetry.
func buildSemgrep(req Request, cfg Config) commandSpec {
	src := strings.TrimSpace(req.Target)
	if src == "" {
		return commandSpec{notApp: "semgrep requires a source path", timeout: cfg.SemgrepTimeout}
	}
	artifact := filepath.Join(req.ScanDir, "scanner-output", "semgrep", "results.json")
	args := []string{"scan", "--config", "p/default", "--metrics", "off", "--json", "--output", artifact, "--quiet", src}
	return commandSpec{path: cfg.SemgrepPath, args: args, artifact: artifact, timeout: cfg.SemgrepTimeout, classify: semgrepFailure}
}

func semgrepFailure(exitCode int, output string) (string, string, bool) {
	text := strings.ToLower(output)
	if strings.Contains(text, "cannot create auto config when metrics are off") {
		return "failed", "Semgrep auto configuration is incompatible with disabled metrics; use an explicit ruleset", true
	}
	if strings.Contains(text, "failed to download") || strings.Contains(text, "invalid configuration") || strings.Contains(text, "no valid configuration") {
		return "failed", "Semgrep could not load its configured ruleset; see scanner stderr for details", true
	}
	return "failed", fmt.Sprintf("Semgrep exited with code %d; see scanner stderr for details", exitCode), true
}
