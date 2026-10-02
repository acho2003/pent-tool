package scanner

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// amassRunner uses passive enumeration only. Names are evidence, not scope.
type amassRunner struct{}

func (amassRunner) Name() string { return "amass" }
func (amassRunner) Descriptor() Descriptor {
	return Descriptor{Name: "amass", Summary: "Optional passive subdomain candidates", Phase: PhaseRecon, Tracks: []Track{TrackWeb}, Weight: WeightLight, Applies: appliesToHost}
}
func (amassRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(req.Target)), ".")
	if domain == "" || strings.ContainsAny(domain, "/\\:@ *") || net.ParseIP(domain) != nil {
		return executeSpec(ctx, "amass", req, cfg, commandSpec{notApp: "Amass requires a domain name", timeout: cfg.AmassTimeout}, emit)
	}
	base := filepath.Join(req.ScanDir, "scanner-output", "amass")
	artifact := filepath.Join(base, "candidates.txt")
	spec := commandSpec{path: cfg.AmassPath, artifact: artifact, timeout: cfg.AmassTimeout,
		args:    []string{"enum", "-passive", "-d", domain, "-o", artifact},
		env:     []string{"XDG_CONFIG_HOME=" + filepath.Join(base, "config")},
		prepare: func() error { return os.MkdirAll(base, 0o700) },
	}
	run := executeSpec(ctx, "amass", req, cfg, spec, emit)
	if run.Status != "completed" {
		return run
	}
	f, err := os.Open(artifact)
	if err != nil {
		run.Status, run.Reason = "failed", "Amass output is missing"
		return run
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64<<10), 1<<20)
	for s.Scan() {
		host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s.Text())), ".")
		if host == domain || strings.HasSuffix(host, "."+domain) {
			run.CandidateHosts = append(run.CandidateHosts, host)
		}
	}
	if err := s.Err(); err != nil {
		run.Status, run.Reason = "failed", "Amass output could not be read: "+err.Error()
		return run
	}
	run.CandidateHosts = dedupHosts(run.CandidateHosts)
	return run
}
