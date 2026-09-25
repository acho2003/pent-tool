package scanner

import (
	"path/filepath"
	"strconv"
	"strings"
)

// buildTestssl runs testssl.sh against a web host and writes a flat JSON array
// of results. It is a light, web-track, host-scope scanner. The artifact path
// is fresh per (scope) because each host scope gets its own ScanDir, so
// testssl's refuse-to-overwrite behavior never triggers on a first run; on
// resume the terminal run is reused and testssl is not re-invoked.
func buildTestssl(req Request, cfg Config) commandSpec {
	target := strings.TrimSpace(req.Target)
	if target == "" || strings.HasPrefix(target, "artifact://") {
		return commandSpec{notApp: "testssl requires a host or URL target", timeout: cfg.TestsslTimeout}
	}
	artifact := filepath.Join(req.ScanDir, "scanner-output", "testssl", "results.json")
	args := []string{
		"--quiet",      // no banner
		"--color", "0", // no ANSI in logs
		"--warnings", "batch", // never prompt
		"--connect-timeout", strconv.Itoa(15),
		"--openssl-timeout", strconv.Itoa(15),
		"--jsonfile", artifact,
		target, // must remain the final arg
	}
	return commandSpec{path: cfg.TestsslPath, args: args, artifact: artifact, timeout: cfg.TestsslTimeout}
}
