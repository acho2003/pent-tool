package scanner

import (
	"context"
	"net"
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
