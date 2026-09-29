package scanner

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// katanaAvailable reports whether the katana binary is runnable, so recon can
// skip the crawl cleanly (rather than record a failed run) on a host that has no
// katana installed. An absolute/relative path is stat-checked; a bare name is
// resolved on PATH.
func katanaAvailable(cfg Config) bool {
	p := strings.TrimSpace(cfg.KatanaPath)
	if p == "" {
		return false
	}
	if strings.ContainsRune(p, os.PathSeparator) {
		info, err := os.Stat(p)
		return err == nil && !info.IsDir()
	}
	_, err := exec.LookPath(p)
	return err == nil
}

// Katana is the web-discovery stage: it crawls one live web host (headless, so
// JS-rendered links and XHR/API endpoints are found) and writes structured
// JSONL. The parser turns it into the normalized attack-surface inventory used
// by the deterministic dispatcher.
//
// The crawl is deliberately bounded and non-destructive: fixed depth, a rate
// limit, a wall-clock timeout, and field-scope pinned to the target's FQDN so it
// never wanders off the approved host. It only requests pages (GET-style
// crawling); it submits nothing.

const katanaDefaultDepth = 5

// katanaArtifactPath is where the crawl writes its JSONL request records.
// It is nested per host so concurrent per-host crawls never share (and corrupt)
// one another's output file.
func katanaArtifactPath(scanDir, host string) string {
	sub := sanitizeHost(host)
	if sub == "" {
		sub = "host"
	}
	return filepath.Join(scanDir, "scanner-output", "katana", sub, "results.jsonl")
}

// buildKatana constructs the bounded, in-scope crawl command for req.Target.
func buildKatana(req Request, cfg Config) commandSpec {
	target := strings.TrimSpace(req.Target)
	if strings.HasPrefix(target, "artifact://") || target == "" {
		return commandSpec{notApp: "Katana requires a live HTTP(S) web host", timeout: cfg.KatanaTimeout}
	}
	if !isHTTPish(target) {
		return commandSpec{notApp: "Katana requires an HTTP(S) URL or host", timeout: cfg.KatanaTimeout}
	}

	host := hostFromTarget(target)
	artifact := katanaArtifactPath(req.ScanDir, host)
	// -jc  : crawl JS files for endpoints; -xhr extracts runtime XHR/fetch calls;
	// -fx extracts forms; -kf all crawls known files (robots.txt, sitemap.xml).
	// -fs fqdn : field-scope the crawl to the target's FQDN (stay on host).
	// -d   : bounded depth. -c concurrency. -rl rate limit. -silent quiet output.
	// -headless -no-sandbox : render JS/XHR so SPA and API routes are discovered.
	// JSONL preserves request method, provenance, response metadata and forms.
	// Raw request/response bytes and response bodies are omitted to keep the
	// inventory bounded and avoid duplicating credentials/content on disk.
	args := []string{
		"-u", target,
		"-d", strconv.Itoa(katanaDefaultDepth),
		"-fs", "fqdn",
		"-jc",
		"-xhr",
		"-fx",
		"-kf", "all",
		"-c", "10",
		"-silent",
		"-headless", "-no-sandbox",
		"-jsonl",
		"-or",
		"-ob",
		"-o", artifact,
	}
	// Headless JS crawling needs a real Chromium. katana's bundled go-rod
	// otherwise tries to DOWNLOAD one (which fails in an offline/arm64 container),
	// so a JS app like an SPA yields zero endpoints. Point katana at the image's
	// installed browser explicitly. Without a configured path, katana falls back
	// to its own resolution.
	if p := strings.TrimSpace(cfg.KatanaChromePath); p != "" {
		args = append(args, "-system-chrome", "-scp", p)
	}
	if cfg.RateRPS > 0 {
		args = append(args, "-rl", strconv.Itoa(cfg.RateRPS))
	}
	// Carry operator scan headers and per-scan auth so authenticated areas are
	// crawled with the same identity the scanners will use.
	for _, h := range cfg.ScanHeaders {
		if strings.TrimSpace(h) != "" {
			args = append(args, "-H", strings.TrimSpace(h))
		}
	}
	for _, h := range strings.Split(req.TargetAuth, "\n") {
		if strings.TrimSpace(h) != "" {
			args = append(args, "-H", strings.TrimSpace(h))
		}
	}

	return commandSpec{path: cfg.KatanaPath, args: args, artifact: artifact, timeout: cfg.KatanaTimeout, outputSubdir: sanitizeHost(host)}
}

// hostIsWeb reports whether a discovered host presents a web surface worth
// crawling: httpx found a live URL, TLS is present, or a common web port is
// open. A bare host with only non-web ports is skipped.
func hostIsWeb(ev HostEvidence) bool {
	if len(ev.LiveURLs) > 0 || ev.TLS {
		return true
	}
	for _, p := range ev.OpenPorts {
		switch p.Number {
		case 80, 443, 8080, 8443, 8000, 8888:
			return true
		}
	}
	return false
}

// primaryWebURL picks the URL katana should crawl for a host: the first live URL
// httpx reported, else an https:// (when TLS was seen) or http:// URL built from
// the host.
func primaryWebURL(host string, ev HostEvidence) string {
	if len(ev.LiveURLs) > 0 {
		return ev.LiveURLs[0]
	}
	if ev.TLS {
		return "https://" + host
	}
	return "http://" + host
}

// parseKatanaEndpoints is the compatibility view used by older callers/tests.
// New execution paths parse the same JSONL into AttackSurface first.
func parseKatanaEndpoints(artifact string) []string {
	f, err := os.Open(artifact)
	if err != nil {
		return nil
	}
	defer f.Close()

	seen := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(f)
	// Katana lines are single URLs; a generous buffer avoids truncation on long
	// query strings.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		candidate := line
		if strings.HasPrefix(line, "{") {
			var row map[string]any
			if json.Unmarshal([]byte(line), &row) != nil {
				continue
			}
			request, _ := row["request"].(map[string]any)
			candidate = firstStringValue(request, "endpoint", "url")
			if candidate == "" {
				candidate = firstStringValue(row, "endpoint", "url")
			}
		}
		if !isHTTPish(candidate) || seen[candidate] {
			continue
		}
		seen[candidate] = true
		out = append(out, candidate)
	}
	return out
}

// isHTTPish reports whether v looks like an http(s) URL or a bare host that the
// crawler/scanners will treat as one.
func isHTTPish(v string) bool {
	lv := strings.ToLower(strings.TrimSpace(v))
	if strings.HasPrefix(lv, "http://") || strings.HasPrefix(lv, "https://") {
		return true
	}
	// bare host or host:port with no scheme and no path traversal characters
	return lv != "" && !strings.ContainsAny(lv, " \t") && strings.Contains(lv, ".")
}
