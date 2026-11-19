package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// defaultSemgrepConfigs are the registry rulesets the generic source scan runs.
// p/default is the broad baseline; the rest add TypeScript/Node.js, the OWASP
// Top Ten, JWT, secret and Dockerfile coverage that matches the NestJS/Next.js
// stack. They are resolved from the Semgrep registry at scan time (like the
// original p/default), so the source target's host needs registry access; an
// air-gapped run should override the list with local rule paths (see
// semgrepConfigs). Each entry becomes a separate --config flag.
var defaultSemgrepConfigs = []string{
	"p/default",
	"p/typescript",
	"p/nodejs",
	"p/owasp-top-ten",
	"p/jwt",
	"p/secrets",
	"p/docker",
}

// semgrepConfigs returns the rulesets to run. XALGORIX_SEMGREP_CONFIGS, a
// comma-separated list, replaces the default set when set (for example to pin a
// subset, add a team ruleset, or point at bundled local rule files for an
// offline run). An empty or whitespace-only value falls back to the default.
func semgrepConfigs() []string {
	raw := strings.TrimSpace(os.Getenv("XALGORIX_SEMGREP_CONFIGS"))
	if raw == "" {
		return defaultSemgrepConfigs
	}
	var configs []string
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			configs = append(configs, part)
		}
	}
	if len(configs) == 0 {
		return defaultSemgrepConfigs
	}
	return configs
}

// buildSemgrep uses explicit registry rulesets: auto configuration refuses to
// run when the runtime's metrics policy disables telemetry.
func buildSemgrep(req Request, cfg Config) commandSpec {
	src := strings.TrimSpace(req.Target)
	if src == "" {
		return commandSpec{notApp: "semgrep requires a source path", timeout: cfg.SemgrepTimeout}
	}
	artifact := filepath.Join(req.ScanDir, "scanner-output", "semgrep", "results.json")
	args := []string{"scan"}
	for _, config := range semgrepConfigs() {
		args = append(args, "--config", config)
	}
	args = append(args, "--metrics", "off", "--json", "--output", artifact, "--quiet", src)
	return commandSpec{path: cfg.SemgrepPath, args: args, artifact: artifact, timeout: cfg.SemgrepTimeout, classify: semgrepFailure}
}

func semgrepFailure(exitCode int, output string) (string, string, bool) {
	text := strings.ToLower(output)
	if strings.Contains(text, "cannot create auto config when metrics are off") {
		return "failed", "Semgrep auto configuration is incompatible with disabled metrics; use an explicit ruleset", true
	}
	if strings.Contains(text, "failed to download") || strings.Contains(text, "invalid configuration") || strings.Contains(text, "no valid configuration") {
		return "failed", "Semgrep could not load a configured ruleset (registry access or a bad XALGORIX_SEMGREP_CONFIGS entry); see scanner stderr", true
	}
	return "failed", fmt.Sprintf("Semgrep exited with code %d; see scanner stderr for details", exitCode), true
}
