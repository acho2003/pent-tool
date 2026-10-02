package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// HistoricalCandidate is archive evidence. Query values are deliberately
// discarded; an archived URL is never an executable request sample.
type HistoricalCandidate struct {
	URL       string   `json:"url"`
	QueryKeys []string `json:"query_keys,omitempty"`
	Provider  string   `json:"provider"`
	State     string   `json:"state"`
	Status    int      `json:"status,omitempty"`
	Reason    string   `json:"reason,omitempty"`
}

type historicalRunner struct{ provider string }

func (r historicalRunner) Name() string { return r.provider }
func (r historicalRunner) Descriptor() Descriptor {
	return Descriptor{Name: r.provider, Summary: "Historical URL candidates with scoped public revalidation", Phase: PhaseRecon, Tracks: []Track{TrackWeb}, Weight: WeightLight, Applies: appliesToHost}
}

type cappedHistoricalOutput struct {
	bytes.Buffer
	limit int
}

func (w *cappedHistoricalOutput) Write(p []byte) (int, error) {
	if w.Len()+len(p) > w.limit {
		return 0, fmt.Errorf("historical provider output exceeded %d bytes", w.limit)
	}
	return w.Buffer.Write(p)
}

func (r historicalRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	run := Run{Scanner: r.provider, Target: req.Target, Scope: req.Scope, Status: "running", StartedAt: now}
	fail := func(reason string) Run { run.Status, run.Reason = "failed", reason; return finalizeRun(run) }
	if req.AppScope == nil || len(req.AppScope.Origins()) == 0 {
		return fail("historical discovery requires approved origins")
	}
	if r.provider != "gau" && r.provider != "waybackurls" {
		return fail("unsupported history provider")
	}
	domain := hostFromTarget(req.Target)
	if domain == "" || net.ParseIP(domain) != nil {
		return fail("historical discovery requires a DNS hostname")
	}
	path, timeout := cfg.GauPath, cfg.GauTimeout
	if r.provider == "waybackurls" {
		path, timeout = cfg.WaybackurlsPath, cfg.WaybackurlsTimeout
	}
	if _, err := exec.LookPath(path); err != nil {
		return fail("historical provider binary unavailable")
	}
	providerCtx, cancel := withOptionalTimeout(ctx, timeout)
	defer cancel()
	var args []string
	if r.provider == "gau" {
		args = []string{"--threads", "1", "--timeout", "10", "--retries", "0", domain}
	}
	cmd := exec.CommandContext(providerCtx, path, args...)
	if r.provider == "waybackurls" {
		cmd.Stdin = strings.NewReader(domain + "\n")
	}
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	stdout, stderr := &cappedHistoricalOutput{limit: 8 << 20}, &cappedHistoricalOutput{limit: 64 << 10}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if emit != nil {
		emit(Event{Type: "scanner_started", Scanner: r.provider, Run: run})
	}
	if err := cmd.Run(); err != nil {
		return fail("historical provider failed: " + err.Error())
	}
	base := filepath.Join(req.ScanDir, "scanner-output", r.provider)
	if err := os.MkdirAll(base, 0o700); err != nil {
		return fail(err.Error())
	}
	artifact := filepath.Join(base, "candidates.jsonl")
	f, err := os.OpenFile(artifact, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fail(err.Error())
	}
	run.ArtifactPath = artifact
	seen := map[string]bool{}
	scan := bufio.NewScanner(bytes.NewReader(stdout.Bytes()))
	scan.Buffer(make([]byte, 64<<10), 1<<20)
	for scan.Scan() {
		if len(run.HistoricalCandidates) >= 500 {
			break
		}
		candidate := historicalCandidate(strings.TrimSpace(scan.Text()), r.provider, req)
		if candidate.URL == "" || seen[candidate.URL] {
			continue
		}
		seen[candidate.URL] = true
		if candidate.State == EndpointStateHistoricalUnverified {
			candidate = revalidateHistorical(providerCtx, candidate, req, cfg)
		}
		run.HistoricalCandidates = append(run.HistoricalCandidates, candidate)
		if err := json.NewEncoder(f).Encode(candidate); err != nil {
			_ = f.Close()
			return fail(err.Error())
		}
	}
	if err := scan.Err(); err != nil {
		_ = f.Close()
		return fail(err.Error())
	}
	if err := f.Close(); err != nil {
		return fail(err.Error())
	}
	run.Status = "completed"
	run = finalizeRun(run)
	if emit != nil {
		emit(Event{Type: "scanner_completed", Scanner: r.provider, Run: run})
	}
	return run
}

func historicalCandidate(raw, provider string, req Request) HistoricalCandidate {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return HistoricalCandidate{}
	}
	keys := make([]string, 0, len(u.Query()))
	for key := range u.Query() {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	u.RawQuery, u.Fragment = "", ""
	redacted := u.String()
	c := HistoricalCandidate{URL: redacted, QueryKeys: keys, Provider: provider, State: EndpointStateHistoricalUnverified}
	if ok, reason := req.AppScope.Allows(redacted); !ok {
		c.State, c.Reason = EndpointStateOutOfScope, reason
		return c
	}
	if excluded, reason := req.AppScope.Excluded("HEAD", redacted); excluded {
		c.State, c.Reason = EndpointStateExcluded, reason
		return c
	}
	if excluded, reason := req.AppScope.Excluded("GET", redacted); excluded {
		c.State, c.Reason = EndpointStateExcluded, reason
		return c
	}
	if len(keys) > 0 {
		c.Reason = "archived query values were removed; supply an executable sample before testing"
	}
	return c
}

func revalidateHistorical(ctx context.Context, candidate HistoricalCandidate, req Request, cfg Config) HistoricalCandidate {
	if err := cfg.Budget.Wait(ctx); err != nil {
		candidate.Reason = err.Error()
		return candidate
	}
	transport := &http.Transport{MaxConnsPerHost: 1, DisableKeepAlives: true}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		resolved := make([]string, 0, len(ips))
		for _, ip := range ips {
			resolved = append(resolved, ip.IP.String())
		}
		if cfg.ScopeGuard != nil {
			if blocked, reason := cfg.ScopeGuard(candidate.URL, resolved); blocked {
				return nil, fmt.Errorf("scope guard: %s", reason)
			}
		}
		if len(resolved) == 0 {
			return nil, fmt.Errorf("no DNS addresses")
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(resolved[0], port))
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodHead, candidate.URL, nil)
	if err != nil {
		candidate.Reason = err.Error()
		return candidate
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		candidate.Reason = "revalidation failed: " + err.Error()
		return candidate
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	_ = resp.Body.Close()
	candidate.Status = resp.StatusCode
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		if len(candidate.QueryKeys) == 0 {
			candidate.State, candidate.Reason = EndpointStateInScope, "public HEAD revalidation succeeded"
		}
	} else {
		candidate.State, candidate.Reason = EndpointStateUnreachable, "archived URL did not respond successfully to HEAD"
	}
	return candidate
}
