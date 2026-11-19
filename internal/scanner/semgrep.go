package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// semgrepPacks are the rulesets the generic source scan runs: the broad
// p/default baseline plus TypeScript/Node.js, OWASP Top Ten, JWT, secret and
// Dockerfile coverage for the NestJS/Next.js stack.
var semgrepPacks = []string{
	"default",
	"typescript",
	"nodejs",
	"owasp-top-ten",
	"jwt",
	"secrets",
	"docker",
}

// bundledSemgrepRulesDir holds the pack YAMLs baked into the runtime image at
// build time (one <pack>.yaml per entry in semgrepPacks). When present, the
// scan uses these local files and needs no registry access. A var so tests can
// point it at a fixture.
var bundledSemgrepRulesDir = "/usr/local/share/xalgorix/semgrep-rules"

// registrySemgrepConfigs are the p/<name> registry aliases, used when the
// bundle is absent (developer machines, non-image runs). These resolve from the
// Semgrep registry at scan time, so that path needs network.
func registrySemgrepConfigs() []string {
	out := make([]string, 0, len(semgrepPacks))
	for _, pack := range semgrepPacks {
		out = append(out, "p/"+pack)
	}
	return out
}

// bundledSemgrepConfigs returns the local pack files present in
// bundledSemgrepRulesDir, or nil when none are bundled.
func bundledSemgrepConfigs() []string {
	var out []string
	for _, pack := range semgrepPacks {
		path := filepath.Join(bundledSemgrepRulesDir, pack+".yaml")
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			out = append(out, path)
		}
	}
	return out
}

// semgrepConfigs returns the rulesets to run, in priority order:
//  1. XALGORIX_SEMGREP_CONFIGS (comma-separated) if set — an explicit override.
//  2. the offline bundle baked into the image, if present (no registry access).
//  3. the p/<name> registry aliases (fetched at scan time) as a fallback.
func semgrepConfigs() []string {
	if raw := strings.TrimSpace(os.Getenv("XALGORIX_SEMGREP_CONFIGS")); raw != "" {
		var configs []string
		for _, part := range strings.Split(raw, ",") {
			if part = strings.TrimSpace(part); part != "" {
				configs = append(configs, part)
			}
		}
		if len(configs) > 0 {
			return configs
		}
	}
	if bundled := bundledSemgrepConfigs(); len(bundled) > 0 {
		return bundled
	}
	return registrySemgrepConfigs()
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
