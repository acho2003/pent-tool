package scanner

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Largest network one nmap job may cover: 256 IPv4 addresses or 256 IPv6 addresses.
const (
	nmapMinIPv4PrefixBits = 24
	nmapMinIPv6PrefixBits = 120
	nmapMaxRate           = "100"
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
	if prefix, err := netip.ParsePrefix(host); err == nil {
		minimum := nmapMinIPv4PrefixBits
		if prefix.Addr().Is6() {
			minimum = nmapMinIPv6PrefixBits
		}
		if prefix.Bits() < minimum {
			return commandSpec{notApp: fmt.Sprintf("nmap is limited to networks of at most 256 addresses (/%d for IPv4, /%d for IPv6); %s is larger", nmapMinIPv4PrefixBits, nmapMinIPv6PrefixBits, host), timeout: cfg.NmapTimeout}
		}
	}
	if cfg.ScopeGuard != nil {
		if blocked, reason := cfg.ScopeGuard(guardURL(host), nmapGuardAddresses(host)); blocked {
			return commandSpec{notApp: reason, timeout: cfg.NmapTimeout}
		}
	}
	artifact := filepath.Join(req.ScanDir, "scanner-output", "nmap", "nmap.xml")
	// -sT uses TCP connect scanning without raw sockets; -sV detects
	// service/version on open ports and -oX writes the parsed XML. -n skips
	// reverse DNS and --max-rate bounds the probe rate.
	// "--" stops option parsing so a target can never be read as a flag.
	return commandSpec{
		path:     cfg.NmapPath,
		args:     []string{"-sT", "-sV", "-n", "--max-rate", nmapMaxRate, "-oX", artifact, "--", host},
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

// nmapGuardAddresses returns the addresses the scope guard should judge for an
// nmap target: the address itself, a network's base address, or what a hostname
// resolves to right now (bounded, best effort; nmap resolves it again itself).
func nmapGuardAddresses(host string) []string {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []string{addr.String()}
	}
	if prefix, err := netip.ParsePrefix(host); err == nil {
		return []string{prefix.Addr().String()}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil
	}
	return addresses
}
