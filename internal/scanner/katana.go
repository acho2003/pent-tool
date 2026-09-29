package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Katana is the web-discovery stage: it crawls one live web host (headless, so
// JS-rendered links and XHR/API endpoints are found) and writes the discovered
// in-scope URLs to a shared artifact. Later web stages (nuclei today;
// dalfox/wapiti next) consume that endpoint list via Request.WebEndpoints so the
// crawl actually drives coverage instead of every tool re-crawling from the
// single seed URL.
//
// The crawl is deliberately bounded and non-destructive: fixed depth, a rate
// limit, a wall-clock timeout, and field-scope pinned to the target's FQDN so it
// never wanders off the approved host. It only requests pages (GET-style
// crawling); it submits nothing.

const katanaDefaultDepth = 3

// katanaArtifactPath is where the crawl writes its newline-delimited URL list.
func katanaArtifactPath(scanDir string) string {
	return filepath.Join(scanDir, "scanner-output", "katana", "endpoints.txt")
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

	artifact := katanaArtifactPath(req.ScanDir)
	// -jc  : crawl JS files for endpoints; -kf robotstxt,sitemapxml known files.
	// -fs fqdn : field-scope the crawl to the target's FQDN (stay on host).
	// -d   : bounded depth. -c concurrency. -rl rate limit. -silent quiet output.
	// -headless -no-sandbox : render JS/XHR so SPA and API routes are discovered.
	// -f url : emit only the URL field, one per line, for a clean endpoint list.
	args := []string{
		"-u", target,
		"-d", strconv.Itoa(katanaDefaultDepth),
		"-fs", "fqdn",
		"-jc",
		"-kf", "robotstxt,sitemapxml",
		"-c", "10",
		"-silent",
		"-headless", "-no-sandbox",
		"-f", "url",
		"-o", artifact,
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

	return commandSpec{path: cfg.KatanaPath, args: args, artifact: artifact, timeout: cfg.KatanaTimeout}
}

// parseKatanaEndpoints reads the crawl artifact into a deduplicated, ordered URL
// slice. Blank lines and obvious non-URL noise are skipped. A missing or
// unreadable artifact yields no endpoints (the caller degrades to the seed URL).
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
		if line == "" || !isHTTPish(line) || seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
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
