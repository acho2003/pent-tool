package scanner

import (
	"bufio"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
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

// katanaMaxConcurrency is the fetcher ceiling; below it concurrency follows
// RateRPS so in-flight requests never outnumber the per-second budget.
const katanaMaxConcurrency = 10

// katanaRequestTimeout is the per-request timeout in seconds (-timeout) and
// katanaRetries the per-request retry count (-retry): one retry absorbs a
// transient error without multiplying load on a struggling target.
const (
	katanaRequestTimeout = 10
	katanaRetries        = 1
)

// katanaFlushGrace is how much of the process timeout is reserved after the
// crawl-duration limit (-ct), so katana stops on its own and flushes its JSONL
// rather than being killed mid-write.
const katanaFlushGrace = 30 * time.Second

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
	if req.AppScope != nil && len(req.AppScope.Origins()) == 0 {
		return commandSpec{notApp: "Katana has no approved origin for this target", timeout: cfg.KatanaTimeout}
	}
	crawlDuration, timeout, ok := katanaDurations(cfg)
	if !ok {
		return commandSpec{notApp: "assessment time budget exhausted before the crawl", timeout: cfg.KatanaTimeout}
	}

	host := hostFromTarget(target)
	artifact := katanaArtifactPath(req.ScanDir, host)
	// -jc  : crawl JS files for endpoints; -xhr extracts runtime XHR/fetch calls;
	// -fx extracts forms; -kf all crawls known files (robots.txt, sitemap.xml).
	// Legacy crawls use -fs fqdn; typed crawls use their approved-origin regexes
	// so an explicitly approved API host can also be discovered.
	// -d   : bounded depth. -c concurrency. -rl rate limit. -silent quiet output.
	// -retry/-timeout bound each request; -duc never phones home for updates.
	// -headless -no-sandbox : render JS/XHR so SPA and API routes are discovered.
	// JSONL preserves request method, provenance, response metadata and forms.
	// Raw request/response bytes and response bodies are omitted to keep the
	// inventory bounded and avoid duplicating credentials/content on disk.
	args := []string{
		"-u", target,
		"-d", strconv.Itoa(katanaDefaultDepth),
		"-jc",
		"-xhr",
		"-fx",
		"-kf", "all",
		"-c", strconv.Itoa(katanaConcurrency(cfg.RateRPS)),
		"-retry", strconv.Itoa(katanaRetries),
		"-timeout", strconv.Itoa(katanaRequestTimeout),
		"-duc",
		"-silent",
		"-jsonl",
		"-or",
		"-ob",
		"-o", artifact,
	}
	if crawlDuration > 0 {
		args = append(args, "-ct", strconv.FormatInt(int64(crawlDuration/time.Second), 10)+"s")
	}
	if req.AppScope == nil {
		args = append(args, "-fs", "fqdn")
	}
	// A typed assessment pins the crawl to its approved origins (scheme, host,
	// port and path prefix, not just the FQDN) and fences off every exclusion,
	// so katana never GETs a logout/delete/purchase/admin route and kills the
	// verified session. The Go-side scope gate on the parsed inventory remains
	// authoritative. -ns disables only katana's implicit DNS/registrable-domain
	// check; its -cs/-cos URL checks still apply (v1.7.0 scope.Manager.Validate).
	if req.AppScope != nil {
		args = append(args, "-ns")
		for _, re := range katanaScopeRegexes(*req.AppScope) {
			args = append(args, "-cs", re)
		}
		for _, re := range katanaExclusionRegexes(*req.AppScope) {
			args = append(args, "-cos", re)
		}
	}
	// katana's headless engine silently drops every -H header (verified on
	// v1.7.0: neither Cookie nor custom headers reach the server), so an
	// authenticated crawl would run logged out while claiming to be logged in.
	// With a session attached, use the standard engine, which sends headers on
	// every crawl request; -jc still mines JS bundles for SPA routes.
	if strings.TrimSpace(req.TargetAuth) == "" {
		args = append(args, "-headless", "-no-sandbox")
		// Headless JS crawling needs a real Chromium. katana's bundled go-rod
		// otherwise tries to DOWNLOAD one (which fails in an offline/arm64
		// container), so a JS app like an SPA yields zero endpoints. Point katana
		// at the image's installed browser explicitly. Without a configured path,
		// katana falls back to its own resolution.
		if p := strings.TrimSpace(cfg.KatanaChromePath); p != "" {
			args = append(args, "-system-chrome", "-scp", p)
		}
	}
	if cfg.RateRPS > 0 {
		args = append(args, "-rl", strconv.Itoa(cfg.RateRPS))
	}
	// Carry operator scan headers and per-scan auth so authenticated areas are
	// crawled with the same identity the scanners will use.
	var headers []string
	for _, h := range cfg.ScanHeaders {
		if strings.TrimSpace(h) != "" {
			headers = append(headers, strings.TrimSpace(h))
		}
	}
	for _, h := range strings.Split(req.TargetAuth, "\n") {
		if strings.TrimSpace(h) != "" {
			headers = append(headers, strings.TrimSpace(h))
		}
	}
	for _, h := range headers {
		args = append(args, "-H", h)
	}
	// net/http strips only Authorization/Cookie on a cross-domain redirect, so
	// a custom API-key header would follow a redirect off the approved origin.
	// With any header attached, katana (-dr, verified on v1.7.0) records the 3xx
	// response instead of following it; MergeKatanaRedirectTargets adds the
	// Location targets to the inventory through the same scope gate.
	if len(headers) > 0 {
		args = append(args, "-dr")
	}

	return commandSpec{path: cfg.KatanaPath, args: args, artifact: artifact, timeout: timeout, outputSubdir: sanitizeHost(host)}
}

// katanaConcurrency bounds the fetcher count so in-flight requests never exceed
// the per-second rate: min(10, max(1, RateRPS)). No configured rate keeps the
// legacy concurrency of 10 (there is no rate to stay under).
func katanaConcurrency(rateRPS int) int {
	if rateRPS <= 0 {
		return katanaMaxConcurrency
	}
	return min(katanaMaxConcurrency, max(1, rateRPS))
}

// katanaDurations returns the crawl-duration limit (-ct, 0 = none) and the
// process timeout. Both are capped by the time left in the assessment budget;
// -ct leaves katanaFlushGrace before the process timeout when there is room.
// ok is false when the budget's deadline has already passed.
func katanaDurations(cfg Config) (crawl, timeout time.Duration, ok bool) {
	timeout = cfg.KatanaTimeout
	if _, hasDeadline := cfg.Budget.Deadline(); hasDeadline {
		remaining := cfg.Budget.Remaining().Truncate(time.Second)
		if remaining <= 0 {
			return 0, 0, false
		}
		if timeout <= 0 || remaining < timeout {
			timeout = remaining
		}
	}
	if timeout <= 0 {
		return 0, timeout, true
	}
	crawl = timeout
	if timeout > 2*katanaFlushGrace {
		crawl = timeout - katanaFlushGrace
	}
	return crawl, timeout, true
}

// katanaScopeRegexes returns one -cs regex per approved origin. katana matches
// them against the full URL it is about to request, so each is anchored on
// scheme, host and port (the default port may be explicit or omitted) and on
// the path prefix at a segment boundary; the query and fragment are free.
func katanaScopeRegexes(scope assessment.AppScope) []string {
	var out []string
	for _, o := range scope.Origins() {
		out = append(out, katanaRegexArg(`^`+katanaOriginPattern(o)+katanaPathPrefixPattern(o.PathPrefix)+`(?:[/?#].*)?$`))
	}
	return out
}

// katanaExclusionRegexes returns one -cos regex per exclusion, reusing
// Exclusion.PathRegex for the path translation. An origin-bound exclusion
// fences only that origin; every other one fences the path on any origin.
// Method-bound exclusions are included too: katana cannot match on method and
// a headless page's scripts may issue any method, so fencing the route is the
// fail-closed choice.
func katanaExclusionRegexes(scope assessment.AppScope) []string {
	var out []string
	for _, e := range scope.Exclusions() {
		origin := `(?i:https?)://[^/?#]+`
		if strings.TrimSpace(e.Origin) != "" {
			o, err := assessment.ParseApprovedOrigin("", e.Origin)
			if err != nil {
				continue
			}
			origin = katanaOriginPattern(o)
		}
		path := strings.TrimSuffix(strings.TrimPrefix(e.PathRegex(), `(?i)^`), `(?:/.*)?$`)
		out = append(out, katanaRegexArg(`^`+origin+`(?i:`+path+`)(?:[/?#].*)?$`))
	}
	return out
}

// katanaOriginPattern is the regex for o's scheme://host[:port], scheme and
// host case-insensitive. The default port matches with or without ":port".
func katanaOriginPattern(o assessment.ApprovedOrigin) string {
	host := o.Host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := `:` + strconv.Itoa(o.Port)
	if (o.Scheme == "https" && o.Port == 443) || (o.Scheme == "http" && o.Port == 80) {
		port = `(?:` + port + `)?`
	}
	return `(?i:` + regexp.QuoteMeta(o.Scheme) + `://` + regexp.QuoteMeta(host) + `)` + port
}

// katanaPathPrefixPattern is the regex for an origin's path prefix as it
// appears in a request URL (escaped form); "/" constrains nothing.
func katanaPathPrefixPattern(prefix string) string {
	prefix = strings.TrimSuffix(prefix, "/")
	if prefix == "" {
		return ""
	}
	return regexp.QuoteMeta((&url.URL{Path: prefix}).EscapedPath())
}

// katanaRegexArg makes a regex safe to pass as one -cs/-cos value. katana
// parses those flags with goflags' comma-separated slice options, which would
// split a regex at every literal comma; \x2c matches the same character.
func katanaRegexArg(re string) string {
	return strings.ReplaceAll(re, ",", `\x2c`)
}

// MergeKatanaRedirectTargets adds the Location target of every 3xx response in
// katana's JSONL artifact to surface and returns how many rows it merged. With
// redirects disabled (-dr) katana records the redirect but never follows it,
// so its target would otherwise vanish. Targets go through the same gate as
// crawled rows: with a typed scope a cross-origin target is kept as an
// out_of_scope candidate (visible, never dispatched) and an in-scope one is
// stamped like any endpoint; without one, targets off the surface's host are
// dropped as in ParseKatanaAttackSurface. Missing or unreadable artifacts and
// malformed rows are skipped.
func MergeKatanaRedirectTargets(surface *AttackSurface, artifact string, appScope *assessment.AppScope, observedWithAuth bool) int {
	if surface == nil {
		return 0
	}
	f, err := os.Open(artifact)
	if err != nil {
		return 0
	}
	defer f.Close()
	byID := make(map[string]int, len(surface.Endpoints))
	for i := range surface.Endpoints {
		byID[surface.Endpoints[i].ID] = i
	}
	targetHost := hostFromTarget(surface.Target)
	artifactName := filepath.Base(artifact)
	added := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var raw map[string]any
		if json.Unmarshal([]byte(line), &raw) != nil {
			continue
		}
		request, _ := raw["request"].(map[string]any)
		response, _ := raw["response"].(map[string]any)
		if status := intValue(response["status_code"]); status < 300 || status > 399 {
			continue
		}
		location := strings.TrimSpace(headerValue(response["headers"], "location"))
		endpoint := firstStringValue(request, "endpoint", "url")
		if location == "" || endpoint == "" {
			continue
		}
		base, baseErr := url.Parse(endpoint)
		ref, refErr := url.Parse(location)
		if baseErr != nil || refErr != nil {
			continue
		}
		rawURL := base.ResolveReference(ref).String()
		allowed, reason := inSurfaceScope(rawURL, targetHost, appScope)
		if !allowed && appScope == nil {
			continue
		}
		timestamp := firstStringValue(raw, "timestamp")
		ep, ok := normalizeAttackSurfaceEndpoint(rawURL, "GET", "redirect", timestamp, 0, "", endpointParameters(rawURL), false, observedWithAuth)
		if !ok {
			continue
		}
		ep.Provenance = []EndpointProvenance{{Tool: "katana", Source: "redirect", Artifact: artifactName, ObservedAt: timestamp, Authenticated: observedWithAuth}}
		if appScope != nil {
			stampEndpointState(&ep, *appScope, allowed, "redirect target: "+reason)
		}
		mergeSurfaceEndpoint(surface, byID, ep)
		added++
	}
	return added
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
