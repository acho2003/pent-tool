package scanner

import (
	"path/filepath"
	"strings"
)

// buildOSV scans the source tree's dependency manifests. osv-scanner exits 1 when
// it finds vulnerabilities, so okExit={1} keeps such a run completed.
// NOTE: verify the subcommand against the installed osv-scanner version; v1 uses
// `osv-scanner --format json -r <dir>`, v2 uses `osv-scanner scan ...`.
func buildOSV(req Request, cfg Config) commandSpec {
	src := strings.TrimSpace(req.Target)
	if src == "" {
		return commandSpec{notApp: "osv-scanner requires a source path", timeout: cfg.OsvTimeout}
	}
	artifact := filepath.Join(req.ScanDir, "scanner-output", "osv", "results.json")
	args := []string{"--format", "json", "--output", artifact, "-r", src}
	return commandSpec{path: cfg.OsvPath, args: args, artifact: artifact, timeout: cfg.OsvTimeout, okExit: map[int]bool{1: true}}
}
