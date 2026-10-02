package scanner

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

// DNSResolution is evidence only. A resolved address never becomes an
// authorized destination or expands the accepted application scope.
type DNSResolution struct {
	Host     string   `json:"host"`
	A        []string `json:"a,omitempty"`
	AAAA     []string `json:"aaaa,omitempty"`
	CNAME    []string `json:"cname,omitempty"`
	Wildcard bool     `json:"wildcard,omitempty"`
}

type dnsxRunner struct{}

func (dnsxRunner) Name() string { return "dnsx" }
func (dnsxRunner) Descriptor() Descriptor {
	return Descriptor{Name: "dnsx", Summary: "Resolve approved hostnames without expanding scope", Phase: PhaseRecon, Tracks: []Track{TrackWeb}, Weight: WeightLight, Applies: appliesToHost}
}

func (dnsxRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	host := strings.TrimSuffix(strings.ToLower(hostFromTarget(req.Target)), ".")
	if net.ParseIP(host) != nil || host == "" || strings.ContainsAny(host, "/\\@ ") {
		return executeSpec(ctx, "dnsx", req, cfg, commandSpec{notApp: "DNSX requires an approved DNS hostname, not an IP literal", timeout: cfg.DNSXTimeout}, emit)
	}
	if req.AppScope != nil {
		allowed := false
		for _, origin := range req.AppScope.Origins() {
			if strings.EqualFold(origin.Host, host) {
				allowed = true
				break
			}
		}
		if !allowed {
			return executeSpec(ctx, "dnsx", req, cfg, commandSpec{notApp: "DNSX host is outside approved origins", timeout: cfg.DNSXTimeout}, emit)
		}
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return executeSpec(ctx, "dnsx", req, cfg, commandSpec{notApp: "cannot create DNS wildcard probe", timeout: cfg.DNSXTimeout}, emit)
	}
	wildcardHost := "xalgorix-" + hex.EncodeToString(nonce[:]) + "." + host
	for range 2 {
		if err := cfg.Budget.Wait(ctx); err != nil {
			return executeSpec(ctx, "dnsx", req, cfg, commandSpec{notApp: "assessment budget exhausted before DNS validation: " + err.Error(), timeout: cfg.DNSXTimeout}, emit)
		}
	}
	base := filepath.Join(req.ScanDir, "scanner-output", "dnsx")
	input := filepath.Join(base, "hosts.txt")
	artifact := filepath.Join(base, "results.jsonl")
	spec := commandSpec{path: cfg.DNSXPath, timeout: cfg.DNSXTimeout, artifact: artifact,
		args: []string{"-l", input, "-a", "-aaaa", "-cname", "-json", "-omit-raw", "-silent", "-retry", "1", "-rl", "2", "-duc", "-o", artifact},
		prepare: func() error {
			if err := os.MkdirAll(base, 0o700); err != nil {
				return err
			}
			return os.WriteFile(input, []byte(host+"\n"+wildcardHost+"\n"), 0o600)
		},
	}
	run := executeSpec(ctx, "dnsx", req, cfg, spec, emit)
	if run.Status != "completed" {
		return run
	}
	resolution, err := parseDNSX(artifact, host, wildcardHost)
	if err != nil {
		run.Status, run.Reason = "failed", fmt.Sprintf("parse DNSX evidence: %v", err)
		return run
	}
	run.DNSResolution = &resolution
	if len(resolution.A) == 0 && len(resolution.AAAA) == 0 && len(resolution.CNAME) == 0 {
		run.Status, run.Reason = "failed", "DNSX returned no resolution evidence for the approved hostname"
		return run
	}
	if cfg.ScopeGuard != nil {
		var origins []assessment.ApprovedOrigin
		if req.AppScope != nil {
			origins = req.AppScope.Origins()
		}
		if len(origins) == 0 {
			origins = []assessment.ApprovedOrigin{{Scheme: "https", Host: host, Port: 443}}
		}
		for _, origin := range origins {
			if !strings.EqualFold(origin.Host, host) {
				continue
			}
			u := origin.Origin()
			if parsed, err := url.Parse(u); err == nil {
				parsed.Path = "/"
				u = parsed.String()
			}
			if blocked, reason := cfg.ScopeGuard(u, append(slices.Clone(resolution.A), resolution.AAAA...)); blocked {
				run.Status, run.Reason = "failed", "DNS address failed execution-time scope guard: "+reason
				return run
			}
		}
	}
	return run
}

func parseDNSX(path, host, wildcardHost string) (DNSResolution, error) {
	f, err := os.Open(path)
	if err != nil {
		return DNSResolution{}, err
	}
	defer f.Close()
	result := DNSResolution{Host: host}
	var wildcardIPs []string
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64<<10), 2<<20)
	for s.Scan() {
		var row struct {
			Host  string   `json:"host"`
			A     []string `json:"a"`
			AAAA  []string `json:"aaaa"`
			CNAME []string `json:"cname"`
		}
		if err := json.Unmarshal(s.Bytes(), &row); err != nil {
			return DNSResolution{}, err
		}
		switch strings.TrimSuffix(strings.ToLower(row.Host), ".") {
		case host:
			result.A = append(result.A, validDNSIPs(row.A)...)
			result.AAAA = append(result.AAAA, validDNSIPs(row.AAAA)...)
			result.CNAME = append(result.CNAME, row.CNAME...)
		case wildcardHost:
			wildcardIPs = append(wildcardIPs, validDNSIPs(row.A)...)
			wildcardIPs = append(wildcardIPs, validDNSIPs(row.AAAA)...)
		}
	}
	if err := s.Err(); err != nil {
		return DNSResolution{}, err
	}
	result.A = dedupHosts(result.A)
	result.AAAA = dedupHosts(result.AAAA)
	result.CNAME = dedupHosts(result.CNAME)
	result.Wildcard = len(wildcardIPs) > 0
	return result, nil
}

func validDNSIPs(values []string) []string {
	var out []string
	for _, value := range values {
		if ip := net.ParseIP(value); ip != nil {
			out = append(out, ip.String())
		}
	}
	return out
}
