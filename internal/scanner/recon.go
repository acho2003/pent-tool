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

		// Nest each host's nmap output under scanner-output/nmap/<host> so the
		// per-host stdout/stderr/XML files never collide: executeSpec derives log
		// paths from the scanner name alone, and a shared log would break the
		// sealed per-run checksum once a second host appends to it.
		subdir := sanitizeHost(host)
		artifact := filepath.Join(req.ScanDir, "scanner-output", "nmap", subdir, "nmap.xml")
		nmapSpec := commandSpec{
			path:         cfg.NmapPath,
			args:         []string{"-sV", "-oX", artifact, host},
			artifact:     artifact,
			timeout:      cfg.NmapTimeout,
			outputSubdir: subdir,
		}
		nmapRun := executeSpec(ctx, "nmap", req, cfg, nmapSpec, emit)
		nmapRun.Scope = scopeKey
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
	// Persist the complete discovered scope set so a resume interrupted mid-scan
	// can re-fan out over every discovered host — including hosts that recon found
	// but that have no terminal scan run yet — without re-invoking the recon tools.
	saveReconScopes(req.ScanDir, scopes)
	return scopes, runs
}

// reconScopesPath is the artifact holding the discovered scope set for resume.
func reconScopesPath(scanDir string) string {
	return filepath.Join(scanDir, "scanner-output", "recon-scopes.json")
}

// saveReconScopes writes the discovered scope set (including per-host Evidence,
// which round-trips since all Scope fields are exported) for lossless resume. A
// write failure is non-fatal: recon still returns its in-memory scopes.
func saveReconScopes(scanDir string, scopes []Scope) {
	path := reconScopesPath(scanDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	data, err := json.MarshalIndent(scopes, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o600)
}

// loadReconScopes reads the persisted discovered scope set. It returns
// (scopes, true) only when the file exists and decodes to at least one scope.
func loadReconScopes(scanDir string) ([]Scope, bool) {
	data, err := os.ReadFile(reconScopesPath(scanDir))
	if err != nil {
		return nil, false
	}
	var scopes []Scope
	if err := json.Unmarshal(data, &scopes); err != nil || len(scopes) == 0 {
		return nil, false
	}
	return scopes, true
}

// subfinderRunner is a descriptor stub for subfinder within the recon phase.
type subfinderRunner struct{}

func (subfinderRunner) Name() string { return "subfinder" }

func (subfinderRunner) Descriptor() Descriptor {
	return Descriptor{Name: "subfinder", Phase: PhaseRecon, Weight: WeightLight}
}

func (subfinderRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	return notApplicableRun("subfinder", req, cfg, "recon runs via the recon phase", emit)
}

// httpxRunner is a descriptor stub for httpx within the recon phase.
type httpxRunner struct{}

func (httpxRunner) Name() string { return "httpx" }

func (httpxRunner) Descriptor() Descriptor {
	return Descriptor{Name: "httpx", Phase: PhaseRecon, Weight: WeightLight}
}

func (httpxRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	return notApplicableRun("httpx", req, cfg, "recon runs via the recon phase", emit)
}

// nmapRunner is a descriptor stub for nmap within the recon phase.
type nmapRunner struct{}

func (nmapRunner) Name() string { return "nmap" }

func (nmapRunner) Descriptor() Descriptor {
	return Descriptor{Name: "nmap", Phase: PhaseRecon, Weight: WeightLight}
}

func (nmapRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	return notApplicableRun("nmap", req, cfg, "recon runs via the recon phase", emit)
}
