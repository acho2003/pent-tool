package scanner

import (
	"path/filepath"
	"strings"
)

// buildSemgrep runs semgrep's auto ruleset over the resolved source directory.
// semgrep exits 0 whether or not it finds issues (no --error), so no okExit is
// needed. --config auto fetches the registry ruleset; offline scans yield a
// failed run and no findings, which is acceptable (best-effort SAST).
func buildSemgrep(req Request, cfg Config) commandSpec {
	src := strings.TrimSpace(req.Target)
	if src == "" {
		return commandSpec{notApp: "semgrep requires a source path", timeout: cfg.SemgrepTimeout}
	}
	artifact := filepath.Join(req.ScanDir, "scanner-output", "semgrep", "results.json")
	args := []string{"scan", "--config", "auto", "--json", "--output", artifact, "--quiet", src}
	return commandSpec{path: cfg.SemgrepPath, args: args, artifact: artifact, timeout: cfg.SemgrepTimeout}
}
