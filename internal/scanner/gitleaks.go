package scanner

import (
	"path/filepath"
	"strings"
)

// buildGitleaks scans the source working tree for secrets. --no-git scans files
// directly so a provided (non-repo) directory works; --exit-code and okExit both
// ensure a "leaks found" run still records completed. Report is written even on a
// non-zero exit.
func buildGitleaks(req Request, cfg Config) commandSpec {
	src := strings.TrimSpace(req.Target)
	if src == "" {
		return commandSpec{notApp: "gitleaks requires a source path", timeout: cfg.GitleaksTimeout}
	}
	artifact := filepath.Join(req.ScanDir, "scanner-output", "gitleaks", "results.json")
	args := []string{"detect", "--source", src, "--no-git", "--report-format", "json", "--report-path", artifact, "--no-banner", "--exit-code", "1"}
	return commandSpec{path: cfg.GitleaksPath, args: args, artifact: artifact, timeout: cfg.GitleaksTimeout, okExit: map[int]bool{1: true}}
}
