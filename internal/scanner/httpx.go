package scanner

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// httpxRunner probes only the exact approved origin URLs supplied by the
// accepted plan. -nfs prevents HTTPX from switching schemes; no redirect
// following is enabled. The returned metadata is evidence, not new scope.
type httpxRunner struct{}

func (httpxRunner) Name() string { return "httpx" }
func (httpxRunner) Descriptor() Descriptor {
	return Descriptor{Name: "httpx", Summary: "Approved-origin reachability and technology evidence", Phase: PhaseRecon, Tracks: []Track{TrackWeb}, Weight: WeightLight, Applies: appliesToHost}
}
func (httpxRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	if req.AppScope == nil {
		return executeSpec(ctx, "httpx", req, cfg, commandSpec{notApp: "typed HTTPX requires an approved application scope", timeout: cfg.HttpxTimeout}, emit)
	}
	var seeds []string
	for _, origin := range req.AppScope.Origins() {
		seed := origin.Origin() + origin.PathPrefix
		if allowed, _ := req.AppScope.Allows(seed); !allowed {
			continue
		}
		if excluded, _ := req.AppScope.Excluded("GET", seed); excluded {
			continue
		}
		if cfg.ScopeGuard != nil {
			if blocked, reason := cfg.ScopeGuard(seed, nil); blocked {
				return executeSpec(ctx, "httpx", req, cfg, commandSpec{notApp: "approved origin failed execution-time scope guard: " + reason, timeout: cfg.HttpxTimeout}, emit)
			}
		}
		seeds = append(seeds, seed)
	}
	seeds = dedupHosts(seeds)
	if len(seeds) == 0 {
		return executeSpec(ctx, "httpx", req, cfg, commandSpec{notApp: "no approved non-excluded origin for reachability probe", timeout: cfg.HttpxTimeout}, emit)
	}
	for range seeds {
		if err := cfg.Budget.Wait(ctx); err != nil {
			return executeSpec(ctx, "httpx", req, cfg, commandSpec{notApp: "assessment budget exhausted before reachability probe: " + err.Error(), timeout: cfg.HttpxTimeout}, emit)
		}
	}
	base := filepath.Join(req.ScanDir, "scanner-output", "httpx")
	input := filepath.Join(base, "origins.txt")
	artifact := filepath.Join(base, "results.jsonl")
	rate := max(1, cfg.RateRPS)
	spec := commandSpec{path: cfg.HttpxPath, artifact: artifact, timeout: cfg.HttpxTimeout,
		args: []string{"-l", input, "-nfs", "-json", "-silent", "-status-code", "-content-type", "-title", "-tech-detect", "-location", "-rl", fmt.Sprint(rate), "-t", "1", "-retries", "0", "-duc", "-o", artifact},
		prepare: func() error {
			if err := os.MkdirAll(base, 0o700); err != nil {
				return err
			}
			return os.WriteFile(input, []byte(strings.Join(seeds, "\n")+"\n"), 0o600)
		},
	}
	run := executeSpec(ctx, "httpx", req, cfg, spec, emit)
	if run.Status != "completed" {
		return run
	}
	for _, observation := range parseHttpxLive(artifact) {
		if allowed, _ := req.AppScope.Allows(observation.URL); !allowed {
			continue
		}
		if excluded, _ := req.AppScope.Excluded("GET", observation.URL); excluded {
			continue
		}
		if observation.RedirectURL != "" {
			redirect, err := url.Parse(observation.RedirectURL)
			if err != nil || redirect.User != nil {
				observation.RedirectURL = ""
			} else {
				redirect.RawQuery, redirect.Fragment = "", ""
				observation.RedirectURL = redirect.String()
			}
		}
		run.HTTPObservations = append(run.HTTPObservations, observation)
	}
	return run
}
