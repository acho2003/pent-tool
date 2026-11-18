package scanner

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// subfinderRunner collects candidates. Its output never becomes a scan target
// without a new accepted scope; the caller receives names as evidence only.
type subfinderRunner struct{}

func (subfinderRunner) Name() string { return "subfinder" }
func (subfinderRunner) Descriptor() Descriptor {
	return Descriptor{Name: "subfinder", Summary: "Passive subdomain candidates", Phase: PhaseRecon, Tracks: []Track{TrackWeb}, Weight: WeightLight, Applies: appliesToHost}
}
func (subfinderRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(req.Target)), ".")
	if domain == "" || strings.ContainsAny(domain, "/\\:@ ") || net.ParseIP(domain) != nil {
		return executeSpec(ctx, "subfinder", req, cfg, commandSpec{notApp: "subfinder requires a domain name", timeout: cfg.SubfinderTimeout}, emit)
	}
	artifact := filepath.Join(req.ScanDir, "scanner-output", "subfinder", "candidates.jsonl")
	spec := commandSpec{path: cfg.SubfinderPath, artifact: artifact, timeout: cfg.SubfinderTimeout,
		args: []string{"-d", domain, "-silent", "-json", "-rl", "2", "-duc", "-o", artifact}}
	if providers, cleanup := subfinderProviderConfig(); providers != "" {
		defer cleanup()
		spec.args = append(spec.args, "-pc", providers)
	}
	run := executeSpec(ctx, "subfinder", req, cfg, spec, emit)
	if run.Status != "completed" {
		return run
	}
	for _, host := range parseSubfinderHosts(artifact) {
		host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
		if host == domain || strings.HasSuffix(host, "."+domain) {
			run.CandidateHosts = append(run.CandidateHosts, host)
		}
	}
	run.CandidateHosts = dedupHosts(run.CandidateHosts)
	return run
}

// subfinderProviderConfig writes the optional passive-source API keys found in
// the environment to a temporary Subfinder provider file, outside the scan
// directory so the keys never become a retained artifact. It returns "" when
// no key is set, which leaves Subfinder on its keyless sources.
func subfinderProviderConfig() (path string, cleanup func()) {
	var b strings.Builder
	for _, source := range [][2]string{{"securitytrails", "SECURITYTRAILS_API_KEY"}, {"chaos", "CHAOS_API_KEY"}, {"virustotal", "VIRUSTOTAL_API_KEY"}, {"shodan", "SHODAN_API_KEY"}, {"github", "GITHUB_TOKEN"}} {
		if key := strings.TrimSpace(os.Getenv(source[1])); key != "" {
			fmt.Fprintf(&b, "%s: [%q]\n", source[0], key)
		}
	}
	if b.Len() == 0 {
		return "", nil
	}
	dir, err := os.MkdirTemp("", "subfinder-providers-")
	if err != nil {
		return "", nil
	}
	path = filepath.Join(dir, "provider-config.yaml")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", nil
	}
	return path, func() { _ = os.RemoveAll(dir) }
}
