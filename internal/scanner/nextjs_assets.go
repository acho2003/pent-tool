package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// nextjsAssetsCatalogVersion is part of the plan fingerprint. Bump it when the
// detection rules or request bounds change.
const nextjsAssetsCatalogVersion = "nextjs-assets-v4"

const (
	nextjsMaxScripts      = 40
	nextjsPageReadLimit   = 512 << 10
	nextjsScriptReadLimit = 2 << 20
	// A source-map probe reads only enough to confirm the structure; the map
	// content itself is never retained.
	nextjsMapProbeLimit = 4 << 10

	// Build-manifest routes are confirmed with one anonymous GET each, up to
	// this many; the rest stay unverified inventory entries.
	nextjsMaxRouteChecks = 100
	nextjsMaxRoutes      = 500

	// LimitationScriptLimit: more in-scope scripts existed than the adapter examines.
	LimitationScriptLimit = "script_limit"
	// LimitationAnonymousAssets: assets are fetched without credentials, so
	// bundles served only to signed-in users are not examined.
	LimitationAnonymousAssets = "anonymous_assets_only"
	// LimitationVersionUnknown: Next.js was detected but its version was not,
	// so no advisory could be matched.
	LimitationVersionUnknown = "version_unknown"
	// LimitationRouteCheckLimit: more manifest routes existed than were confirmed.
	LimitationRouteCheckLimit = "route_check_limit"
)

var (
	nextjsVersionPattern   = regexp.MustCompile(`window\.next\s*=\s*\{\s*version\s*:\s*"(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)"`)
	nextjsBuildIDPattern   = regexp.MustCompile(`"buildId"\s*:\s*"([A-Za-z0-9_-]{1,64})"`)
	nextjsManifestPattern  = regexp.MustCompile(`/_next/static/([A-Za-z0-9_-]{1,64})/_(?:build|ssg)Manifest\.js$`)
	nextjsSourceMapPattern = regexp.MustCompile(`(?m)^[ \t]*//[#@][ \t]*sourceMappingURL=([^\s'"]+)[ \t]*$`)
	nextjsSortedPages      = regexp.MustCompile(`sortedPages\s*:\s*\[((?:\s*"[^"]*"\s*,?)*)\]`)
	nextjsManifestRouteKey = regexp.MustCompile(`"(/[^"\s]{0,512})"\s*:\s*\[`)
	nextjsQuoted           = regexp.MustCompile(`"([^"\s]{1,512})"`)
	// Route names that suggest a GET may change state are recorded, not requested.
	nextjsUnsafeRouteName = regexp.MustCompile(`(?i)(^|[/_.-])(log-?out|sign-?out|delete|remove|destroy|unsubscribe|deactivate|revoke)([/_.-]|$)`)
)

// nextjsAssetsRunner examines the JavaScript a Next.js application already
// serves: it fingerprints the framework version and build, and checks whether
// production source maps are publicly retrievable. It sends only GET requests
// to in-scope URLs, never follows redirects and never forwards credentials.
type nextjsAssetsRunner struct{}

func (nextjsAssetsRunner) Name() string { return "nextjs-assets" }
func (nextjsAssetsRunner) Descriptor() Descriptor {
	return Descriptor{Name: "nextjs-assets", Summary: "Read-only Next.js fingerprint and source-map exposure checks", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightLight}
}

type nextjsFetch struct {
	status int
	header http.Header
	body   []byte
}

func (nextjsAssetsRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	run := Run{Scanner: "nextjs-assets", Target: req.Target, Scope: req.Scope, Status: "running", StartedAt: now, Variant: nextjsAssetsCatalogVersion}
	finish := func(status, reason string) Run {
		run.Status, run.Reason, run.FinishedAt = status, reason, time.Now().UTC().Format(time.RFC3339Nano)
		return finalizeRun(run)
	}
	if !req.TypedAssessment || req.AppScope == nil {
		return finish("failed", "Next.js asset checks require a typed assessment scope")
	}
	base, err := url.Parse(strings.TrimSpace(req.Target))
	if err != nil || base.Host == "" || base.User != nil || (base.Scheme != "http" && base.Scheme != "https") {
		return finish("failed", "target must be an absolute HTTP(S) URL without credentials")
	}
	if emit != nil {
		emit(Event{Type: "scanner_started", Scanner: run.Scanner, Run: run})
	}
	dir := filepath.Join(req.ScanDir, "scanner-output", "nextjs-assets")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return finish("failed", "create artifact directory: "+err.Error())
	}
	artifact := filepath.Join(dir, "findings.jsonl")
	file, err := os.OpenFile(artifact, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return finish("failed", "create artifact: "+err.Error())
	}
	defer file.Close()
	eventsPath := filepath.Join(dir, "coverage-events.jsonl")
	events, err := os.OpenFile(eventsPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return finish("failed", "create discovery evidence: "+err.Error())
	}
	defer events.Close()
	run.CoverageEventsPath = eventsPath
	record := func(raw, kind, reason string, status int) bool {
		event := CoverageEvent{Scanner: "nextjs-assets", AttemptID: req.AttemptID, Method: http.MethodGet, URL: SafeTelemetryURL(raw), Phase: "discovery", Kind: kind, At: time.Now().UTC().Format(time.RFC3339Nano), Reason: reason, ResponseCode: status}
		if err := json.NewEncoder(events).Encode(event); err != nil {
			run.GapKind, run.Reason = GapInterruptedWrite, "write discovery evidence failed"
			return false
		}
		return true
	}
	run.ArtifactPath = artifact
	run.Limitations = append(run.Limitations, RunLimitation{Kind: LimitationAnonymousAssets, Reason: "assets are requested without credentials; bundles served only to signed-in users are not examined"})

	limits := nextjsLimits(req)
	attempted, completed := 0, 0
	totalBytes := int64(0)
	requestFailures := 0
	var lastErr string
	var stopped bool
	fetch := func(rawURL string, limit int64) (nextjsFetch, bool) {
		if stopped {
			return nextjsFetch{}, false
		}
		if !nextjsAllows(req, rawURL) || nextjsExcluded(req, rawURL) || browserRequestAllowed(req, Config{}, http.MethodGet, rawURL) != nil {
			return nextjsFetch{}, false
		}

		if attempted >= limits.MaxRequests || totalBytes >= limits.MaxResponseBytes {
			stopped = true
			run.GapKind, run.Reason = GapBudgetExhausted, "Next.js request or response-byte budget exhausted"
			return nextjsFetch{}, false
		}
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Host == "" || parsed.User != nil {
			return nextjsFetch{}, false
		}
		endpoint, normalized := normalizeAttackSurfaceEndpoint(rawURL, http.MethodGet, "nextjs-assets", "", 0, "", endpointParameters(rawURL), false, false)
		if !normalized {
			return nextjsFetch{}, false
		}
		if len(cfg.Budget.ReserveEndpoints([]string{endpoint.ID})) == 0 {
			stopped = true
			run.GapKind, run.Reason = GapBudgetExhausted, "assessment endpoint budget stopped Next.js discovery"
			return nextjsFetch{}, false
		}
		if err := cfg.Budget.Wait(ctx); err != nil {
			stopped = true
			if ctx.Err() != nil {
				run.GapKind, run.Reason = GapCancelled, "checks cancelled before completion"
			} else {
				run.GapKind, run.Reason = GapBudgetExhausted, "assessment request budget stopped remaining checks: "+err.Error()
			}
			return nextjsFetch{}, false
		}

		client, err := guardedOriginClient(ctx, cfg, rawURL)
		if err != nil {
			attempted++
			lastErr = err.Error()
			requestFailures++
			return nextjsFetch{}, false
		}

		request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nextjsFetch{}, false
		}
		attempted++
		if !record(rawURL, "submitted", "", 0) {
			stopped = true
			return nextjsFetch{}, false
		}
		resp, err := client.Do(request)
		if err != nil {
			lastErr = safeAPIError(err)
			requestFailures++
			if !record(rawURL, "failed", "request failed", 0) {
				stopped = true
			}
			return nextjsFetch{}, false
		}
		defer resp.Body.Close()
		readLimit := min(limit+1, limits.MaxResponseBytes-totalBytes+1)
		body, err := io.ReadAll(io.LimitReader(resp.Body, readLimit))
		if err != nil {
			lastErr = "response read failed: " + err.Error()
			requestFailures++
			if !record(rawURL, "failed", "response read failed", resp.StatusCode) {
				stopped = true
			}
			return nextjsFetch{}, false
		}

		totalBytes += int64(len(body))
		if totalBytes > limits.MaxResponseBytes {
			stopped = true
			run.GapKind, run.Reason = GapBudgetExhausted, "Next.js response-byte budget exhausted"
			if !record(rawURL, "failed", "response-byte budget exhausted", resp.StatusCode) {
				run.GapKind = GapInterruptedWrite
			}
			return nextjsFetch{}, false
		}
		if int64(len(body)) > limit {
			body = body[:limit]
			if limit > 0 && !hasNextjsLimitation(run, "nextjs_response_limit") {
				run.Limitations = append(run.Limitations, RunLimitation{Kind: "nextjs_response_limit", Reason: "one or more responses exceeded their parsing limit"})
			}
		}
		completed++
		if !record(rawURL, "observed", "discovery response; not active security testing", resp.StatusCode) {
			stopped = true
			return nextjsFetch{}, false
		}
		return nextjsFetch{status: resp.StatusCode, header: resp.Header, body: body}, true
	}

	var version, buildID string
	var signals []string
	addSignal := func(signal string) {
		if !slices.Contains(signals, signal) {
			signals = append(signals, signal)
		}
	}
	var findings []Finding
	exposedKeys := map[string]bool{}
	inspectExposure := func(raw string, body []byte) {
		if req.Profile != ProfileNextjsDeep || exposedKeys[raw] {
			return
		}
		if finding := nextjsPrivateKeyFinding(req, raw, body, eventsPath); finding != nil {
			findings = append(findings, *finding)
			exposedKeys[raw] = true
		}
	}
	scripts := nextjsInventoryScripts(req)
	page := *base
	page.Fragment = ""
	landing, landingOK := fetch(page.String(), nextjsPageReadLimit)
	if res, ok := landing, landingOK; ok {
		if res.status == http.StatusOK {
			inspectExposure(page.String(), res.body)
		}
		if strings.Contains(strings.ToLower(res.header.Get("X-Powered-By")), "next.js") {
			addSignal("X-Powered-By header")
		}
		html := string(res.body)
		if strings.Contains(html, "__NEXT_DATA__") {
			addSignal("__NEXT_DATA__ page data")
		}
		if strings.Contains(html, "self.__next_f") {
			addSignal("App Router flight data")
		}
		if m := nextjsBuildIDPattern.FindStringSubmatch(html); m != nil {
			buildID = m[1]
		}
		refs := nextjsHTMLReferences(&page, res.body)
		scripts = append(scripts, refs.Scripts...)
	}
	if req.Profile == ProfileNextjsDeep && (len(signals) > 0 || len(scripts) > 0) {
		queue := []string{page.String()}
		seenPages := map[string]bool{page.String(): true}
		seenCandidates := map[string]bool{}
		recordCandidate := func(raw, source string) {
			if seenCandidates[raw] || len(seenCandidates) >= nextjsMaxRoutes {
				return
			}
			seenCandidates[raw] = true
			run.HistoricalCandidates = append(run.HistoricalCandidates, nextjsURLCandidate(req, raw, source))
		}
		// Reuse the landing response, then crawl only explicit harmless page links.
		for i := 0; i < len(queue) && i < limits.MaxPages && !stopped; i++ {
			current, _ := url.Parse(queue[i])
			res, ok := landing, landingOK
			if i != 0 {
				res, ok = fetch(current.String(), nextjsPageReadLimit)
			}
			if !ok || res.status != http.StatusOK {
				continue
			}
			for j := range run.HistoricalCandidates {
				if run.HistoricalCandidates[j].URL == current.String() {
					run.HistoricalCandidates[j].Status = res.status
					run.HistoricalCandidates[j].State = EndpointStateInScope
					run.HistoricalCandidates[j].Reason = "page discovery GET completed; not an active security check"
				}
			}
			inspectExposure(current.String(), res.body)
			refs := nextjsHTMLReferences(current, res.body)
			scripts = append(scripts, refs.Scripts...)
			for _, raw := range refs.Links {
				recordCandidate(raw, "html_link")
				if !seenPages[raw] && len(queue) < nextjsMaxRoutes && nextjsPageEligible(req, cfg, raw) {
					seenPages[raw] = true
					queue = append(queue, raw)
				}
			}
			for _, match := range nextjsAPIReference.FindAllSubmatch(res.body, nextjsMaxRoutes) {
				if u, err := current.Parse(string(match[1])); err == nil {
					recordCandidate(u.String(), "inline_api_reference")
				}
			}
		}
		if len(queue) > limits.MaxPages {
			run.Limitations = append(run.Limitations, RunLimitation{Kind: "nextjs_page_limit", Reason: fmt.Sprintf("page discovery reached its %d-page limit", limits.MaxPages)})
		}
	}

	scripts = nextjsInScopeScripts(req, scripts)
	if len(scripts) > limits.MaxScripts {
		run.Limitations = append(run.Limitations, RunLimitation{Kind: LimitationScriptLimit, Reason: fmt.Sprintf("examined %d of %d in-scope scripts", limits.MaxScripts, len(scripts))})
		scripts = scripts[:limits.MaxScripts]
	}

	var routes []string
	var routeBase *url.URL
	probedMaps := map[string]bool{}
	for scriptIndex := 0; scriptIndex < len(scripts); scriptIndex++ {
		script := scripts[scriptIndex]
		if stopped {
			break
		}
		scriptURL, _ := url.Parse(script)
		if strings.Contains(scriptURL.Path, "/_next/static/") {
			addSignal("/_next/static/ assets")
		}
		if m := nextjsManifestPattern.FindStringSubmatch(scriptURL.Path); m != nil && buildID == "" {
			buildID = m[1]
		}
		res, ok := fetch(script, nextjsScriptReadLimit)
		if !ok || res.status != http.StatusOK {
			continue
		}
		inspectExposure(script, res.body)
		if strings.HasSuffix(scriptURL.Path, "/_buildManifest.js") && routes == nil {
			routes = nextjsManifestRoutes(res.body)
			// Manifest routes are relative to the application's base path.
			base := *scriptURL
			base.Path, base.RawPath, base.RawQuery = scriptURL.Path[:strings.Index(scriptURL.Path, "/_next/")], "", ""
			routeBase = &base
		}
		if req.Profile == ProfileNextjsDeep {
			for _, match := range nextjsAssetReference.FindAllSubmatch(res.body, nextjsMaxRoutes) {
				child, err := scriptURL.Parse(string(match[1]))
				if err != nil {
					continue
				}
				child.Fragment = ""
				if nextjsAllows(req, child.String()) && !nextjsExcluded(req, child.String()) && !slices.Contains(scripts, child.String()) {
					if len(scripts) < limits.MaxScripts {
						scripts = append(scripts, child.String())
					} else if !hasNextjsLimitation(run, LimitationScriptLimit) {
						run.Limitations = append(run.Limitations, RunLimitation{Kind: LimitationScriptLimit, Reason: "additional referenced chunks exceeded the script limit"})
					}
				}
			}
			for _, match := range nextjsAPIReference.FindAllSubmatch(res.body, nextjsMaxRoutes) {
				if u, err := base.Parse(string(match[1])); err == nil && len(run.HistoricalCandidates) < nextjsMaxRoutes {
					candidate := nextjsURLCandidate(req, u.String(), "javascript_api_reference")
					if !slices.ContainsFunc(run.HistoricalCandidates, func(c HistoricalCandidate) bool { return c.URL == candidate.URL }) {
						run.HistoricalCandidates = append(run.HistoricalCandidates, candidate)
					}
				}
			}
		}

		if m := nextjsVersionPattern.FindSubmatch(res.body); m != nil && version == "" {
			version = string(m[1])
		}
		ref := firstNonEmptyKube(res.header.Get("SourceMap"), res.header.Get("X-SourceMap"))
		if ref == "" {
			if m := nextjsSourceMapPattern.FindAllSubmatch(res.body, nextjsMaxRoutes); len(m) > 0 {
				ref = string(m[len(m)-1][1])
			}
		}
		if ref == "" && req.Profile == ProfileNextjsDeep {
			adjacent := *scriptURL
			adjacent.Path += ".map"
			adjacent.RawPath = ""
			ref = adjacent.String()
		}
		if ref == "" || strings.HasPrefix(strings.ToLower(ref), "data:") {
			continue
		}
		mapURL, err := scriptURL.Parse(ref)
		if err != nil {
			continue
		}
		mapURL.Fragment = ""
		if probedMaps[mapURL.String()] {
			continue
		}
		probedMaps[mapURL.String()] = true
		probe, ok := fetch(mapURL.String(), nextjsMapProbeLimit)
		if !ok || probe.status != http.StatusOK || !looksLikeSourceMap(probe.body) {
			continue
		}
		inspectExposure(mapURL.String(), probe.body)
		findings = append(findings, Finding{
			SourceID: nextjsSourceID("nextjs-source-map", mapURL.String()), Scanner: "nextjs-assets", RuleID: "nextjs-source-map",
			Title: "Public JavaScript source map", Severity: "low", Target: req.Target, Endpoint: sanitizeKubeURL(mapURL.String()), Method: http.MethodGet,
			Description: "A production source map is publicly retrievable. It can disclose original source code, internal file paths and comments.",
			Evidence:    fmt.Sprintf("HTTP %d; associated script %s; source map structure confirmed from the first %d bytes; content not retained", probe.status, sanitizeKubeURL(script), nextjsMapProbeLimit),
			Remediation: "Do not deploy source maps publicly (Next.js: productionBrowserSourceMaps false), or restrict them to authorized users.",
			CWE:         "CWE-540", Confidence: "confirmed", EvidenceRef: eventsPath,
		})
	}
	if routeBase != nil {
		checked, unconfirmed := 0, 0
		for _, route := range routes {
			candidate := nextjsRouteCandidate(req, routeBase, route)
			if candidate.URL == "" {
				continue
			}
			if candidate.State == EndpointStateInScope {
				if checked >= limits.MaxRouteChecks || stopped {
					unconfirmed++
					candidate.State, candidate.Reason = EndpointStateHistoricalUnverified, "referenced by the Next.js build manifest; not confirmed (route check limit or budget)"
				} else if res, ok := fetch(candidate.URL, 0); ok {
					checked++
					candidate.Status = res.status
					candidate.Reason = fmt.Sprintf("referenced by the Next.js build manifest; anonymous GET answered HTTP %d", res.status)
				} else {
					checked++
					candidate.State, candidate.Reason = EndpointStateHistoricalUnverified, "referenced by the Next.js build manifest; confirmation request did not complete"
				}
			}
			run.HistoricalCandidates = append(run.HistoricalCandidates, candidate)
		}
		if unconfirmed > 0 {
			run.Limitations = append(run.Limitations, RunLimitation{Kind: LimitationRouteCheckLimit, Reason: fmt.Sprintf("confirmed %d manifest routes; %d more are recorded unverified", checked, unconfirmed)})
		}
	}
	if len(signals) > 0 {
		detail := "version not determined from served assets"
		if version != "" {
			detail = "version " + version
		}
		if buildID != "" {
			detail += "; build ID " + buildID
		}
		fingerprint := Finding{
			SourceID: nextjsSourceID("nextjs-fingerprint", base.Scheme+"://"+base.Host), Scanner: "nextjs-assets", RuleID: "nextjs-fingerprint",
			Title: "Next.js application detected", Severity: "info", Target: req.Target, Endpoint: sanitizeKubeURL(page.String()), Method: http.MethodGet,
			Description: "The application is built with Next.js. Check the version against current Next.js security advisories.",
			Evidence:    "signals: " + strings.Join(signals, ", ") + "; " + detail,
			Package:     "next", PackageVersion: version, Confidence: "firm",
		}
		if version != "" {
			fingerprint.Confidence = "confirmed"
		}
		findings = append([]Finding{fingerprint}, findings...)
		if version != "" {
			advisories, err := nextjsAdvisoryFindings(req, base, page.String(), version)
			if err != nil {
				return finish("failed", "load Next.js advisory snapshot: "+err.Error())
			}
			findings = append(findings, advisories...)
		} else {
			run.Limitations = append(run.Limitations, RunLimitation{Kind: LimitationVersionUnknown, Reason: "the served assets did not reveal the Next.js version, so advisories were not matched"})
		}
	}
	if requestFailures > 0 {
		run.Limitations = append(run.Limitations, RunLimitation{Kind: "nextjs_request_failed", Reason: fmt.Sprintf("%d discovery requests failed or were refused by the execution guard", requestFailures)})
	}
	if err := events.Sync(); err != nil {
		return finish("failed", "persist discovery evidence: "+err.Error())
	}
	enc := json.NewEncoder(file)
	for _, finding := range findings {
		if err := enc.Encode(finding); err != nil {
			return finish("failed", "write artifact: "+err.Error())
		}
	}
	switch {
	case run.GapKind != "":
		return finish("failed", run.Reason)
	case completed == 0:
		run.GapKind = GapRequestFailed
		return finish("failed", fmt.Sprintf("no request completed (%d attempted; %s)", attempted, firstNonEmptyKube(lastErr, "all requests were refused or failed")))
	case len(signals) == 0:
		return finish("completed", fmt.Sprintf("no Next.js signals in %d responses", completed))
	}
	return finish("completed", fmt.Sprintf("completed %d bounded read-only requests over %d scripts; %d source maps probed; %d manifest routes recorded; %d findings", completed, len(scripts), len(probedMaps), len(run.HistoricalCandidates), len(findings)))
}

// nextjsInventoryScripts returns the script URLs the crawl already recorded.
// Static resources are discovery-only in the inventory, so they are read here
// rather than through the scanner dispatch list.
func nextjsInventoryScripts(req Request) []string {
	if req.Inventory == nil {
		return nil
	}
	var out []string
	for _, endpoint := range req.Inventory.Endpoints {
		if endpoint.Method != "" && endpoint.Method != http.MethodGet {
			continue
		}
		if ext := strings.ToLower(path.Ext(endpoint.Path)); ext == ".js" || ext == ".mjs" {
			out = append(out, endpoint.URL)
		}
	}
	return out
}

// nextjsInScopeScripts deduplicates and orders scripts, dropping any that the
// approved scope does not allow. Next.js manifests sort first so the build ID is
// read even when the script limit applies.
func nextjsInScopeScripts(req Request, scripts []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, script := range scripts {
		if seen[script] {
			continue
		}
		seen[script] = true
		if ok, _ := req.AppScope.Allows(script); ok {
			out = append(out, script)
		}
	}
	rank := func(raw string) int {
		switch {
		case strings.Contains(raw, "Manifest.js"):
			return 0
		case strings.Contains(raw, "/_next/static/chunks/main") || strings.Contains(raw, "/_next/static/chunks/webpack"):
			return 1
		case strings.Contains(raw, "/_next/static/"):
			return 2
		}
		return 3
	}
	slices.SortStableFunc(out, func(a, b string) int {
		if ra, rb := rank(a), rank(b); ra != rb {
			return ra - rb
		}
		return strings.Compare(a, b)
	})
	return out
}

// nextjsAdvisoryFindings reports each advisory in the embedded snapshot whose
// affected range contains the detected version. A match is a version match,
// not a tested exploit: applicability depends on the features and hosting the
// advisory describes.
func nextjsAdvisoryFindings(req Request, base *url.URL, endpoint, version string) ([]Finding, error) {
	snapshot, err := loadNextjsAdvisories()
	if err != nil {
		return nil, err
	}
	var out []Finding
	for _, match := range matchNextjsAdvisories(snapshot, version) {
		advisory := match.Advisory
		remediation := "Upgrade next to a patched release; see " + advisory.URL
		if match.Range.Patched != "" {
			remediation = "Upgrade next to " + match.Range.Patched + " or later; see " + advisory.URL
		}
		cwe := ""
		if len(advisory.CWEs) > 0 {
			cwe = advisory.CWEs[0]
		}
		out = append(out, Finding{
			SourceID: nextjsSourceID("nextjs-advisory", advisory.GHSAID+"\x00"+base.Scheme+"://"+base.Host), Scanner: "nextjs-assets", RuleID: advisory.GHSAID,
			Title: "Next.js " + version + ": " + advisory.Summary, Severity: advisory.Severity, Target: req.Target, Endpoint: sanitizeKubeURL(endpoint), Method: http.MethodGet,
			Description: advisory.Summary + ". The served Next.js version is in the advisory's affected range. Whether it is exploitable depends on the features and hosting described in the advisory; it was not tested.",
			Evidence:    fmt.Sprintf("detected version %s from the served client runtime; affected range %s; %s (snapshot %s)", version, match.Range.Range, advisory.GHSAID, snapshot.Retrieved),
			Remediation: remediation, CVE: advisory.CVEID, CWE: cwe, Package: "next", PackageVersion: version, Confidence: "version_match",
		})
	}
	return out, nil
}

// nextjsManifestRoutes reads the Pages Router route list from a build
// manifest: sortedPages when present, otherwise the manifest's route keys.
// Internal pages (/_app, /_error, ...) are dropped.
func nextjsManifestRoutes(body []byte) []string {
	var raw []string
	if m := nextjsSortedPages.FindSubmatch(body); m != nil {
		for _, q := range nextjsQuoted.FindAllSubmatch(m[1], -1) {
			raw = append(raw, string(q[1]))
		}
	} else {
		for _, k := range nextjsManifestRouteKey.FindAllSubmatch(body, nextjsMaxRoutes) {
			raw = append(raw, string(k[1]))
		}
	}
	seen := map[string]bool{}
	routes := []string{}
	for _, route := range raw {
		if !strings.HasPrefix(route, "/") || strings.HasPrefix(route, "/_") || seen[route] {
			continue
		}
		seen[route] = true
		routes = append(routes, route)
		if len(routes) >= nextjsMaxRoutes {
			break
		}
	}
	return routes
}

// nextjsRouteCandidate places one manifest route in the inventory model. Only
// a static, in-scope, non-excluded route with a harmless name is eligible for
// a confirmation request; every other route is recorded with its reason.
func nextjsRouteCandidate(req Request, base *url.URL, route string) HistoricalCandidate {
	u := *base
	u.Path = strings.TrimSuffix(base.Path, "/") + route
	u.RawPath = ""
	c := HistoricalCandidate{URL: u.String(), Provider: "nextjs-assets", Source: "build_manifest", State: EndpointStateInScope}
	switch {
	case strings.Contains(route, "["):
		c.State, c.Reason = EndpointStateUnmaterialized, "dynamic Next.js route segment needs a supplied value"
	case !nextjsAllows(req, c.URL):
		_, reason := req.AppScope.Allows(c.URL)
		c.State, c.Reason = EndpointStateOutOfScope, reason
	case nextjsExcluded(req, c.URL):
		_, reason := req.AppScope.Excluded(http.MethodGet, c.URL)
		c.State, c.Reason = EndpointStateExcluded, reason
	case nextjsUnsafeRouteName.MatchString(route):
		c.State, c.Reason = EndpointStateHistoricalUnverified, "not requested: the route name suggests a GET may change state"
	}
	return c
}

func nextjsAllows(req Request, rawURL string) bool {
	ok, _ := req.AppScope.Allows(rawURL)
	return ok
}

func nextjsExcluded(req Request, rawURL string) bool {
	excluded, _ := req.AppScope.Excluded(http.MethodGet, rawURL)
	return excluded
}

// looksLikeSourceMap confirms a source-map document from its opening bytes:
// a JSON object carrying the version and a sources or mappings member.
func looksLikeSourceMap(body []byte) bool {
	text := bytes.TrimSpace(bytes.TrimPrefix(body, []byte(")]}'")))
	decoder := json.NewDecoder(bytes.NewReader(text))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	version, structure := false, false
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return false
		}
		key, ok := token.(string)
		if !ok {
			return false
		}
		value, err := decoder.Token()
		if err != nil {
			return false
		}
		switch key {
		case "version":
			version = value == float64(3)
		case "sources":
			structure = value == json.Delim('[')
		case "mappings":
			_, structure = value.(string)
		}
		if version && structure {
			return true
		}
		// Skip a compound value before looking for the next top-level member.
		if delimiter, ok := value.(json.Delim); ok && (delimiter == '[' || delimiter == '{') {
			depth := 1
			for depth > 0 {
				next, err := decoder.Token()
				if err != nil {
					return false
				}
				if d, ok := next.(json.Delim); ok {
					switch d {
					case '[', '{':
						depth++
					case ']', '}':
						depth--
					}
				}
			}
		}
	}
	return false
}

func nextjsSourceID(ruleID, key string) string {
	hash := sha256.Sum256([]byte(ruleID + "\x00" + key))
	return ruleID + ":" + hex.EncodeToString(hash[:8])
}

func parseNextjsAssets(path string) ([]Finding, error) {
	return parseKubeExposure(path)
}

var _ Runner = nextjsAssetsRunner{}

func hasNextjsLimitation(run Run, kind string) bool {
	for _, limitation := range run.Limitations {
		if limitation.Kind == kind {
			return true
		}
	}
	return false
}
