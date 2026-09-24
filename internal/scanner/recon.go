package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func reconScopeKey(target string) string { return "recon:" + target }

// hostFromTarget extracts the bare host from a URL, host:port, or host.
func hostFromTarget(target string) string {
	t := strings.TrimSpace(target)
	if strings.Contains(t, "://") {
		if u, err := url.Parse(t); err == nil && u.Host != "" {
			t = u.Host
		}
	}
	if h, _, err := net.SplitHostPort(t); err == nil {
		return h
	}
	return t
}

// isBareHostInput reports whether the target is an IP, host:port, or URL —
// i.e. not an apex/subdomain name that subfinder should enumerate.
func isBareHostInput(target string) bool {
	t := strings.TrimSpace(target)
	if strings.Contains(t, "://") {
		return true
	}
	host := hostFromTarget(t)
	if net.ParseIP(host) != nil {
		return true
	}
	// host:port form (a port after the host) is a bare host input.
	if _, _, err := net.SplitHostPort(t); err == nil {
		return true
	}
	return false
}

func candidateHosts(target string) []string {
	h := hostFromTarget(target)
	if h == "" {
		return nil
	}
	return []string{h}
}

// httpxResult is one live-host record parsed from httpx JSONL output.
type httpxResult struct {
	URL, Host, Port, Scheme string
	TLS                     bool
}

// parseSubfinderHosts reads subfinder JSONL output ({"host":"..."} per line)
// and collects the discovered hostnames. Blank or malformed lines are skipped.
func parseSubfinderHosts(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64<<10), 8<<20)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		var v struct {
			Host string `json:"host"`
		}
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			continue
		}
		if h := strings.TrimSpace(v.Host); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// parseHttpxLive reads httpx JSONL output and collects one httpxResult per
// non-empty, well-formed line. Blank or malformed lines are skipped.
func parseHttpxLive(path string) []httpxResult {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []httpxResult
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64<<10), 8<<20)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		var v struct {
			URL    string      `json:"url"`
			Host   string      `json:"host"`
			Port   json.Number `json:"port"` // real httpx emits an int; older/mock output a string
			Scheme string      `json:"scheme"`
		}
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			continue
		}
		// httpx does not emit a reliable top-level tls bool (only a tls object
		// under -tls-grab); scheme is the dependable https signal.
		out = append(out, httpxResult{URL: v.URL, Host: v.Host, Port: v.Port.String(), Scheme: v.Scheme, TLS: v.Scheme == "https"})
	}
	return out
}

// dedupHosts returns the input hosts trimmed and deduplicated, in stable order.
func dedupHosts(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, h := range in {
		h = strings.TrimSpace(h)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

// sanitizeHost turns a hostname into a safe filename component for per-host
// nmap artifacts (IPv6 literals carry colons; some hosts carry slashes).
func sanitizeHost(host string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', ':', ' ':
			return '_'
		default:
			return r
		}
	}, host)
}

// runRecon runs the recon phase: optional subfinder enumeration, httpx liveness
// probing, then per-host nmap service detection. It returns one Scope per live
// host (carrying LiveURLs, TLS, and OpenPorts evidence) plus every recon Run,
// each stamped with the recon scope key and a terminal status. Missing tools
// degrade gracefully: a reachable bare host still yields at least one scope.
func runRecon(ctx context.Context, req Request, cfg Config, emit EmitFunc) (scopes []Scope, runs []Run) {
	scopeKey := reconScopeKey(req.Target)
	seeds := candidateHosts(req.Target)

	// Step 1: subfinder subdomain enumeration (skipped for bare-host input).
	if !isBareHostInput(req.Target) {
		host := hostFromTarget(req.Target)
		artifact := filepath.Join(req.ScanDir, "scanner-output", "subfinder", "subfinder.jsonl")
		spec := commandSpec{
			path:     cfg.SubfinderPath,
			args:     []string{"-d", host, "-silent", "-json", "-o", artifact},
			artifact: artifact,
			timeout:  cfg.SubfinderTimeout,
		}
		run := executeSpec(ctx, "subfinder", req, cfg, spec, emit)
		run.Scope = scopeKey
		runs = append(runs, run)
		if run.Status == "completed" {
			seeds = append(seeds, parseSubfinderHosts(artifact)...)
		}
	}
	seeds = dedupHosts(seeds)

	// Step 2: httpx liveness probing over the seed hosts.
	inputPath := filepath.Join(req.ScanDir, "scanner-output", "httpx", "seeds.txt")
	httpxArtifact := filepath.Join(req.ScanDir, "scanner-output", "httpx", "httpx.jsonl")
	httpxSpec := commandSpec{
		path:     cfg.HttpxPath,
		args:     []string{"-silent", "-json", "-l", inputPath, "-o", httpxArtifact},
		artifact: httpxArtifact,
		timeout:  cfg.HttpxTimeout,
		prepare: func() error {
			if err := os.MkdirAll(filepath.Dir(inputPath), 0o700); err != nil {
				return err
			}
			return os.WriteFile(inputPath, []byte(strings.Join(seeds, "\n")+"\n"), 0o600)
		},
	}
	httpxRun := executeSpec(ctx, "httpx", req, cfg, httpxSpec, emit)
	httpxRun.Scope = scopeKey
	live := parseHttpxLive(httpxArtifact)
	if len(live) == 0 {
		// Fallback: httpx is missing or nothing responded — treat each seed as a
		// live host so a reachable host is not silently dropped from the scan.
		for _, h := range seeds {
			live = append(live, httpxResult{Host: h})
		}
		httpxRun.Reason = strings.TrimSpace(httpxRun.Reason + " httpx returned no live hosts; falling back to candidate seeds")
	}
	runs = append(runs, httpxRun)

	// Group httpx results by host so each live host produces exactly one scope
	// (httpx can report a host once per scheme/port).
	order := make([]string, 0, len(live))
	byHost := make(map[string][]httpxResult, len(live))
	for _, r := range live {
		h := strings.TrimSpace(r.Host)
		if h == "" {
			continue
		}
		if _, ok := byHost[h]; !ok {
			order = append(order, h)
		}
		byHost[h] = append(byHost[h], r)
	}

	// Steps 3 & 4: per live host, run nmap and assemble the host scope.
	for _, host := range order {
		s := HostScope(host)
		for _, r := range byHost[host] {
			if r.URL != "" {
				s.Evidence.LiveURLs = append(s.Evidence.LiveURLs, r.URL)
			}
			if r.TLS {
				s.Evidence.TLS = true
			}
		}

		artifact := filepath.Join(req.ScanDir, "scanner-output", "nmap", sanitizeHost(host)+".xml")
		nmapSpec := commandSpec{
			path:     cfg.NmapPath,
			args:     []string{"-sV", "-oX", artifact, host},
			artifact: artifact,
			timeout:  cfg.NmapTimeout,
		}
		nmapRun := executeSpec(ctx, "nmap", req, cfg, nmapSpec, emit)
		nmapRun.Scope = scopeKey
		nmapRun.ArtifactPath = artifact
		runs = append(runs, nmapRun)
		if nmapRun.Status == "completed" {
			if findings, err := parseNmap(artifact); err == nil {
				for _, f := range findings {
					n, _ := strconv.Atoi(f.Endpoint)
					s.Evidence.OpenPorts = append(s.Evidence.OpenPorts, Port{
						Number:   n,
						Protocol: "tcp",
						Service:  f.Title,
						Product:  f.Evidence,
					})
				}
			}
		}
		scopes = append(scopes, s)
	}
	return scopes, runs
}
