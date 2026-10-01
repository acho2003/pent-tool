package scanner

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

const masscanPorts = "22,80,443,445,3389,8080,8443"

var masscanGate = make(chan struct{}, 1)

type masscanRunner struct{}

func (masscanRunner) Name() string { return "masscan" }
func (masscanRunner) Descriptor() Descriptor {
	return Descriptor{Name: "masscan", Summary: "Bounded common-port SYN discovery", Phase: PhaseRecon, Weight: WeightLight, Applies: appliesToHost}
}
func (r masscanRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	if reason := MasscanCapabilityReason(); reason != "" {
		return executeSpec(ctx, r.Name(), req, cfg, commandSpec{prepare: func() error { return errors.New(reason) }}, emit)
	}
	release, err := acquireMasscan(ctx, cfg.MasscanPath)
	if err != nil {
		return cancelledRun("masscan", req.Scope, req, err, emit)
	}
	defer release()
	return executeSpec(ctx, r.Name(), req, cfg, buildMasscan(req, cfg), emit)
}

func acquireMasscan(ctx context.Context, binary string) (func(), error) {
	_ = binary // One process-wide lease prevents aggregate packet rates multiplying.
	select {
	case masscanGate <- struct{}{}:
		return func() { <-masscanGate }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func buildMasscan(req Request, cfg Config) commandSpec {
	if strings.TrimSpace(cfg.MasscanPath) == "" {
		return commandSpec{notApp: "Masscan executable is not configured", timeout: cfg.MasscanTimeout}
	}
	target := strings.TrimSpace(req.Target)
	var addr netip.Addr
	var prefix netip.Prefix
	if parsed, err := netip.ParseAddr(target); err == nil {
		addr = parsed
	} else if parsedPrefix, err := netip.ParsePrefix(target); err == nil {
		if parsedPrefix != parsedPrefix.Masked() {
			return commandSpec{notApp: "Masscan CIDR target must be in canonical network form", timeout: cfg.MasscanTimeout}
		}
		prefix = parsedPrefix.Masked()
		addr = prefix.Addr()
	} else {
		return commandSpec{notApp: "Masscan requires one explicit IPv4 address or bounded IPv4 CIDR", timeout: cfg.MasscanTimeout}
	}
	if !addr.Is4() {
		return commandSpec{notApp: "this Masscan adapter supports IPv4 targets only", timeout: cfg.MasscanTimeout}
	}
	if prefix.IsValid() && prefix.Bits() < 20 {
		return commandSpec{notApp: "Masscan CIDR targets larger than /20 are outside the bounded adapter policy", timeout: cfg.MasscanTimeout}
	}
	rate := cfg.MasscanRate
	if rate <= 0 {
		rate = 100
	}
	if rate > 1000 {
		return commandSpec{notApp: "Masscan packet rate exceeds the adapter maximum of 1000 packets per second", timeout: cfg.MasscanTimeout}
	}
	artifact := filepath.Join(req.ScanDir, "scanner-output", "masscan", "results.json")
	return commandSpec{
		path:     cfg.MasscanPath,
		args:     []string{"-p", masscanPorts, "--rate", fmt.Sprint(rate), "--wait", "3", "-oJ", artifact, target},
		artifact: artifact, timeout: cfg.MasscanTimeout,
		prepare: func() error { return os.MkdirAll(filepath.Dir(artifact), 0o700) },
	}
}
