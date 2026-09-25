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
	return commandSpec{path: cfg.TestsslPath, args: args, artifact: artifact, timeout: cfg.TestsslTimeout, classify: testsslConnectFailure}
}

// testsslConnectFailure recognizes testssl's own "cannot reach the TLS port"
// output. testssl only assesses TLS, so a host it cannot connect to on the
// scanned port has nothing for it to test — a not_applicable with a plain
// reason, rather than a bare non-zero exit code, tells the operator why. This
// covers both an HTTP-only host and a target that blocked the scan; the reason
// names both so a blocked HTTPS host is still worth investigating.
func testsslConnectFailure(_ int, output string) (string, string, bool) {
	low := strings.ToLower(output)
	for _, marker := range []string{
		"unable to open a socket",
		"can't connect",
		"cannot connect",
		"tcp connect problem",
		"connection refused",
	} {
		if strings.Contains(low, marker) {
			return "not_applicable", "no reachable TLS service on the target — testssl could not connect on the scanned port (the host may serve only HTTP, or may have blocked the scan)", true
		}
	}
	return "", "", false
}
