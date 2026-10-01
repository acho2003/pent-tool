package scanner

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// nmapAssessmentRunner is the assessment adapter for nmap: service and version
// detection against an approved network target (IP, CIDR, host, or domain).
// The legacy recon path has its own nmap invocation; this runner is what the
// typed assessment planner dispatches. Results are parsed by parseNmap.
type nmapAssessmentRunner struct{}

func (nmapAssessmentRunner) Name() string { return "nmap" }
func (nmapAssessmentRunner) Descriptor() Descriptor {
	return Descriptor{Name: "nmap", Summary: "Service and version detection on an approved network target", Phase: PhaseRecon, Weight: WeightLight, Applies: appliesToHost}
}
func (r nmapAssessmentRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	return executeSpec(ctx, r.Name(), req, cfg, buildNmap(req, cfg), emit)
}

func buildNmap(req Request, cfg Config) commandSpec {
	if strings.TrimSpace(cfg.NmapPath) == "" {
		return commandSpec{notApp: "nmap executable is not configured", timeout: cfg.NmapTimeout}
	}
	target := strings.TrimSpace(req.Target)
	host, ok := nmapTargetSpec(target)
	if !ok {
		return commandSpec{notApp: "nmap requires one IP address, CIDR range, hostname, or domain without a scheme, port, or path", timeout: cfg.NmapTimeout}
	}
	artifact := filepath.Join(req.ScanDir, "scanner-output", "nmap", "nmap.xml")
	// -sT uses TCP connect scanning without raw sockets; -sV detects
	// service/version on open ports and -oX writes the parsed XML.
	// "--" stops option parsing so a target can never be read as a flag.
	return commandSpec{
		path:     cfg.NmapPath,
		args:     []string{"-sT", "-sV", "-oX", artifact, "--", host},
		artifact: artifact,
		timeout:  cfg.NmapTimeout,
		prepare:  func() error { return os.MkdirAll(filepath.Dir(artifact), 0o700) },
	}
}

// nmapTargetSpec validates an assessment target for nmap and returns the exact
// argument to scan. It accepts an IP, a canonical CIDR, or a hostname/domain,
// and rejects anything carrying a scheme, port, path, or shell metacharacters.
func nmapTargetSpec(target string) (string, bool) {
	if addr, err := netip.ParseAddr(target); err == nil {
		return addr.String(), true
	}
	if prefix, err := netip.ParsePrefix(target); err == nil && prefix == prefix.Masked() {
		return prefix.String(), true
	}
	if strings.ContainsAny(target, " \t\r\n/@\\?#:") || !validNmapHostname(target) {
		return "", false
	}
	return target, true
}

func validNmapHostname(host string) bool {
	if host == "" || len(host) > 253 || strings.HasPrefix(host, "-") || strings.Contains(host, "..") {
		return false
	}
	for _, r := range host {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' {
			continue
		}
		return false
	}
	return true
}
