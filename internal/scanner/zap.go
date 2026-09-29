package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// zapDomXSSPluginID is ZAP's DOM XSS active scan rule (from the "domxss"
// add-on). It is disabled per scan because it launches headless Firefox, which
// OOM-kills the daemon on a memory-constrained host.
const zapDomXSSPluginID = "40026"

var zapLeases = struct {
	sync.Mutex
	byService map[string]chan struct{}
}{byService: make(map[string]chan struct{})}

var zapServiceState = struct {
	sync.RWMutex
	quarantined map[string]string
}{quarantined: make(map[string]string)}

// acquireZAPServiceLease serializes access to a configured daemon across every
// pipeline instance in this process. ZAP replacer rules and its Sites tree are
// daemon-global state, so a per-Pipeline worker semaphore is insufficient.
func acquireZAPServiceLease(ctx context.Context, serviceURL string) (func(), error) {
	key := strings.TrimRight(strings.TrimSpace(serviceURL), "/")
	zapLeases.Lock()
	lease := zapLeases.byService[key]
	if lease == nil {
		lease = make(chan struct{}, 1)
		zapLeases.byService[key] = lease
	}
	zapLeases.Unlock()
	select {
	case lease <- struct{}{}:
		return func() { <-lease }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func ZAPServiceQuarantined(serviceURL string) bool {
	key := strings.TrimRight(strings.TrimSpace(serviceURL), "/")
	zapServiceState.RLock()
	defer zapServiceState.RUnlock()
	return zapServiceState.quarantined[key] != ""
}

func quarantineZAPService(serviceURL, reason string) {
	key := strings.TrimRight(strings.TrimSpace(serviceURL), "/")
	zapServiceState.Lock()
	zapServiceState.quarantined[key] = reason
	zapServiceState.Unlock()
}

func applicationContextRegex(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" {
		return "", fmt.Errorf("invalid application URL for ZAP context")
	}
	host := u.Hostname()
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	authority := host
	if port != "" {
		authority = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	origin := regexp.QuoteMeta(strings.ToLower(u.Scheme) + "://" + strings.ToLower(authority))
	path := strings.TrimSuffix(u.EscapedPath(), "/")
	pathRule := `(?:/.*)?`
	if path != "" {
		pathRule = regexp.QuoteMeta(path) + `(?:/.*)?`
	}
	return "^" + origin + pathRule + `(?:\?.*)?$`, nil
}

type zapRunner struct{}

func (zapRunner) Name() string { return "zap" }

func (zapRunner) Descriptor() Descriptor {
	return Descriptor{Name: "zap", Summary: "Spider and active scan of each HTTP/HTTPS host", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightHeavy, Applies: appliesToHost}
}

func (zapRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	target, ok := normalizedWebTarget(req.Target)
	if !ok {
		return notApplicableRun("zap", req, cfg, "ZAP requires an HTTP or HTTPS target", emit)
	}
	if strings.TrimSpace(cfg.ZAPURL) == "" {
		return failedServiceRun("zap", req, "ZAP service URL is not configured", emit)
	}
	if req.TypedAssessment && !cfg.ZAPDedicated {
		return failedServiceRun("zap", req, "typed assessments require XALGORIX_ZAP_DEDICATED=true for a dedicated managed ZAP daemon", emit)
	}
	if req.TypedAssessment && strings.TrimSpace(req.TargetAuth) != "" && req.AuthRefresh == nil {
		return failedServiceRun("zap", req, "authenticated assessment requires an active session verifier", emit)
	}
	release, err := acquireZAPServiceLease(ctx, cfg.ZAPURL)
	if err != nil {
		run := cancelledRun("zap", req.Scope, req, err, emit)
		return run
	}
	defer release()
	if ZAPServiceQuarantined(cfg.ZAPURL) {
		return failedServiceRun("zap", req, "ZAP daemon is quarantined after a cleanup failure; restart the managed daemon and Xalgorix before retrying", emit)
	}
	base := filepath.Join(req.ScanDir, "scanner-output", "zap")
	_ = os.MkdirAll(base, 0o700)
	run := Run{Scanner: "zap", Target: req.Target, Scope: req.Scope, Status: "running", StartedAt: time.Now().Format(time.RFC3339Nano), ExitCode: -1, StdoutPath: filepath.Join(base, "stdout.log"), StderrPath: filepath.Join(base, "stderr.log"), ArtifactPath: filepath.Join(base, "results.json")}
	logFile, _ := os.OpenFile(run.StdoutPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if logFile != nil {
		defer logFile.Close()
	}
	seq := int64(0)
	secrets := secretValues(req, cfg)
	logLine := func(s string) {
		clean := redact(s, secrets)
		data := []byte(clean + "\n")
		if logFile != nil {
			data = appendCappedFile(logFile, data, cfg.MaxOutputBytes, &run.Truncated)
		}
		if len(data) == 0 {
			return
		}
		seq++
		if emit != nil {
			emit(Event{Type: "scanner_output", Scanner: "zap", Stream: "stdout", Sequence: seq, Output: string(data)})
		}
	}
	if emit != nil {
		emit(Event{Type: "scanner_started", Scanner: "zap", Run: run})
	}
	zapTimeout := cfg.ZAPTimeout
	if req.Profile == ProfileThorough {
		zapTimeout = 0
	} else if cfg.WebBudget > 0 && cfg.WebBudget < zapTimeout {
		zapTimeout = cfg.WebBudget
	}
	cctx, cancel := withOptionalTimeout(ctx, zapTimeout)
	defer cancel()
	client := &http.Client{}
	// Every exchange with ZAP is a plain HTTP API call: the daemon is reached
	// over cfg.ZAPURL and nothing is handed to it through the filesystem, so a
	// ZAP running in another container (or on another host) needs no shared
	// volume, matching uid, or readable scan directory.
	fetch := func(path string, q url.Values, timeout time.Duration) ([]byte, error) {
		rctx, rcancel := context.WithTimeout(cctx, timeout)
		defer rcancel()
		q.Set("apikey", cfg.ZAPAPIKey)
		endpoint := strings.TrimRight(cfg.ZAPURL, "/") + path + "?" + q.Encode()
		hreq, err := http.NewRequestWithContext(rctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(hreq)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 512<<20))
		if err != nil {
			return nil, err
		}
		if resp.StatusCode/100 != 2 {
			return nil, fmt.Errorf("ZAP API %s: %s", resp.Status, strings.TrimSpace(string(body)))
		}
		return body, nil
	}
	call := func(path string, q url.Values) (map[string]any, error) {
		body, err := fetch(path, q, 60*time.Second)
		if err != nil {
			return nil, err
		}
		var out map[string]any
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, err
		}
		return out, nil
	}
	if _, err := call("/JSON/core/view/version/", url.Values{}); err != nil {
		return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
	}
	contextName, contextID, scopeRegex := "", "", ""
	if req.TypedAssessment {
		var err error
		scopeRegex, err = applicationContextRegex(target)
		if err != nil {
			return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
		}
		contextName = "xalgorix-" + stableJobPath(req.Scope+"\x00"+target)
		if _, err := call("/JSON/core/action/newSession/", url.Values{}); err != nil {
			return finishServiceFailure(run, fmt.Errorf("create fresh ZAP session: %w", err), secrets, cfg.MaxOutputBytes, emit)
		}
		defer func() {
			if err := zapPost(cfg, "/JSON/core/action/newSession/", url.Values{}); err != nil {
				quarantineZAPService(cfg.ZAPURL, "reset ZAP session: "+err.Error())
				logLine("ZAP cleanup failed; daemon quarantined: " + err.Error())
			}
		}()
		created, err := call("/JSON/context/action/newContext/", url.Values{"contextName": {contextName}})
		if err != nil {
			return finishServiceFailure(run, fmt.Errorf("create target context: %w", err), secrets, cfg.MaxOutputBytes, emit)
		}
		defer func() {
			if err := zapPost(cfg, "/JSON/context/action/removeContext/", url.Values{"contextName": {contextName}}); err != nil {
				quarantineZAPService(cfg.ZAPURL, "remove target context: "+err.Error())
				logLine("ZAP cleanup failed; daemon quarantined: " + err.Error())
			}
		}()
		contextID = valueString(created, "contextId")
		if contextID == "" || contextID == "<nil>" {
			return finishServiceFailure(run, errors.New("ZAP did not return a context ID"), secrets, cfg.MaxOutputBytes, emit)
		}
		if _, err := call("/JSON/context/action/includeInContext/", url.Values{"contextName": {contextName}, "regex": {scopeRegex}}); err != nil {
			return finishServiceFailure(run, fmt.Errorf("scope ZAP context to the submitted application: %w", err), secrets, cfg.MaxOutputBytes, emit)
		}
		if _, err := call("/JSON/context/action/setContextInScope/", url.Values{"contextName": {contextName}, "booleanInScope": {"true"}}); err != nil {
			return finishServiceFailure(run, fmt.Errorf("enable target context scope: %w", err), secrets, cfg.MaxOutputBytes, emit)
		}
	}
	// Apply configured scan and per-target authentication headers through
	// deterministic ZAP replacer rules before crawling. No model interprets
	// authentication material.
	var headers []string
	if !req.TypedAssessment {
		headers = append(headers, cfg.ScanHeaders...)
	}
	headers = append(headers, strings.Split(req.TargetAuth, "\n")...)
	var rules []string
	// ZAP replacer rules live in the daemon, not in the scan: leaving them
	// behind would replay this target's credentials onto the next one.
	defer func() {
		// Detached from cctx on purpose: the rules must come off even when the
		// scan was cancelled or timed out.
		for _, description := range rules {
			if err := zapRemoveRule(cfg, description); err != nil && req.TypedAssessment {
				quarantineZAPService(cfg.ZAPURL, "remove target authentication rule: "+err.Error())
				logLine("ZAP cleanup failed; daemon quarantined: " + err.Error())
			}
		}
	}()
	for i, raw := range headers {
		name, value, ok := strings.Cut(strings.TrimSpace(raw), ":")
		if !ok || strings.TrimSpace(name) == "" || strings.TrimSpace(value) == "" {
			continue
		}
		description := fmt.Sprintf("xalgorix-%s-%d", filepath.Base(req.ScanDir), i)
		rules = append(rules, description)
		params := url.Values{
			"description": {description},
			"enabled":     {"true"}, "matchType": {"REQ_HEADER"}, "matchRegex": {"false"},
			"matchString": {strings.TrimSpace(name)}, "replacement": {strings.TrimSpace(value)},
		}
		if req.TypedAssessment {
			params.Set("url", scopeRegex)
		}
		_, err := zapPostResponse(cctx, cfg, "/JSON/replacer/action/addRule/", params)
		if err != nil {
			return finishServiceFailure(run, fmt.Errorf("configure ZAP header %s: %w", strings.TrimSpace(name), err), secrets, cfg.MaxOutputBytes, emit)
		}
	}
	// Check authentication at stage boundaries and while waiting on long ZAP
	// jobs. A refreshed cookie replaces its scoped daemon rule in this lease.
	authMonitor := &zapAuthMonitor{current: headers, refresh: req.AuthRefresh, interval: time.Minute}
	checkAuth := func() error {
		initialCheck := authMonitor.next.IsZero()
		verificationDue := req.AuthRefresh != nil && (initialCheck || !time.Now().Before(authMonitor.next))
		err := authMonitor.check(cctx, func(next []string) error {
			for i, raw := range next {
				if i >= len(headers) || raw == headers[i] {
					continue
				}
				name, value, ok := strings.Cut(raw, ":")
				if !ok || i >= len(rules) || !strings.EqualFold(strings.TrimSpace(name), strings.TrimSpace(strings.SplitN(headers[i], ":", 2)[0])) {
					return errors.New("authenticated session renewal returned invalid headers")
				}
				if err := zapRemoveRule(cfg, rules[i]); err != nil {
					return errors.New("authenticated session header could not be replaced")
				}
				params := url.Values{"description": {rules[i]}, "enabled": {"true"}, "matchType": {"REQ_HEADER"}, "matchRegex": {"false"}, "matchString": {strings.TrimSpace(name)}, "replacement": {strings.TrimSpace(value)}, "url": {scopeRegex}}
				if _, err := zapPostResponse(cctx, cfg, "/JSON/replacer/action/addRule/", params); err != nil {
					return errors.New("authenticated session header could not be installed")
				}
				secrets = append(secrets, strings.TrimSpace(value))
			}
			headers = append([]string(nil), next...)
			if req.AuthKind == "form login" {
				logLine("Authentication: form session renewed after re-login")
			} else {
				logLine("Authentication: scoped credential refreshed")
			}
			return nil
		})
		if err != nil {
			if req.AuthRefresh != nil {
				logLine("Authentication error: session verification failed; authenticated ZAP scan stopped")
			}
			return err
		}
		if verificationDue {
			if initialCheck {
				method := "HTTP headers"
				if req.AuthKind == "form login" {
					method = "form login"
				}
				logLine("Authentication verified: " + method + " session active for scoped ZAP scan")
			} else {
				logLine("Authentication reverified: scoped session still active")
			}
		}
		return nil
	}
	if err := checkAuth(); err != nil {
		return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
	}

	// Best-effort: seed the target into ZAP's Sites tree before crawling, so a
	// site the spider can't harvest links from (a JS app, or one with no crawlable
	// anchors) still gets a node for the active scan. accessUrl is not fatal: it
	// fails on targets ZAP's classic fetcher can't handle (e.g. HTTP/2-only sites)
	// that the spider may still reach, so a failure here is logged and the scan
	// continues rather than aborting a reachable target.
	followRedirects := "true"
	if req.TypedAssessment {
		followRedirects = "false"
	}
	maxChildren := cfg.WebMaxEndpoints
	if maxChildren <= 0 {
		maxChildren = DefaultWebProfile(ProfileGentle).MaxEndpoints
	}
	if _, err := call("/JSON/core/action/accessUrl/", url.Values{"url": {target}, "followRedirects": {followRedirects}}); err != nil {
		logLine("ZAP could not pre-seed the target (continuing to spider): " + err.Error())
	} else {
		logLine("ZAP seeded target into scan tree: " + target)
	}
	if req.TypedAssessment && len(req.APIEndpoints) > 0 {
		seeded := 0
		for _, endpoint := range req.APIEndpoints {
			if err := checkAuth(); err != nil {
				return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
			}
			result := APIEndpointResult{Method: endpoint.Method, Path: endpoint.Path}
			if !endpoint.Eligible || !endpoint.Resolved {
				result.Status, result.Reason = "skipped", endpoint.Reason
				if result.Reason == "" {
					result.Reason = "operation needs values or explicit approval"
				}
				run.APIEndpointResults = append(run.APIEndpointResults, result)
				continue
			}
			if seeded >= maxChildren {
				result.Status, result.Reason = "skipped", "web endpoint budget exhausted before this operation was seeded"
				run.APIEndpointResults = append(run.APIEndpointResults, result)
				continue
			}
			operationURL, urlErr := apiEndpointURL(target, endpoint)
			if urlErr != nil {
				result.Status, result.Reason = "skipped", urlErr.Error()
				run.APIEndpointResults = append(run.APIEndpointResults, result)
				continue
			}
			if _, seedErr := call("/JSON/core/action/accessUrl/", url.Values{"url": {operationURL}, "followRedirects": {"false"}}); seedErr != nil {
				result.Status, result.Reason = "failed", "ZAP could not seed this operation into the scoped scan tree"
			} else {
				result.Status = "seeded"
				seeded++
			}
			run.APIEndpointResults = append(run.APIEndpointResults, result)
		}
	}

	// Fixed pipeline: spider the target, drain the passive scanner, then active
	// scan what was discovered. The stages and their parameters are constant —
	// nothing about them is model-generated.
	spiderParams := url.Values{"url": {target}, "recurse": {"true"}, "maxChildren": {strconv.Itoa(maxChildren)}}
	if req.TypedAssessment {
		spiderParams.Set("contextName", contextName)
	}
	if err := checkAuth(); err != nil {
		return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
	}
	spider, err := call("/JSON/spider/action/scan/", spiderParams)
	if err != nil {
		return finishServiceFailure(run, fmt.Errorf("start ZAP spider: %w", err), secrets, cfg.MaxOutputBytes, emit)
	}
	spiderID := valueString(spider, "scan")
	if spiderID == "" || spiderID == "<nil>" {
		return finishServiceFailure(run, fmt.Errorf("ZAP did not return a spider scan id"), secrets, cfg.MaxOutputBytes, emit)
	}
	logLine("ZAP spider started: " + spiderID)
	if err := zapWaitScanChecked(cctx, call, "/JSON/spider/view/status/", spiderID, "spider", logLine, checkAuth); err != nil {
		zapStopScan(cfg, "/JSON/spider/action/stop/", spiderID)
		return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
	}
	logLine("ZAP passive scan: waiting for spider traffic to be analyzed")
	if err := zapWaitPassiveChecked(cctx, call, logLine, checkAuth); err != nil {
		return finishServiceFailure(run, fmt.Errorf("ZAP passive scan after spider: %w", err), secrets, cfg.MaxOutputBytes, emit)
	}
	logLine("ZAP passive scan complete after spider")
	// Typed jobs restore daemon-global scan rule state after execution. Legacy
	// jobs retain the historical DOM XSS mitigation behavior.
	if req.TypedAssessment {
		state, err := call("/JSON/ascan/view/scanners/", url.Values{"ids": {zapDomXSSPluginID}})
		if err != nil {
			return finishServiceFailure(run, fmt.Errorf("read ZAP DOM XSS rule state: %w", err), secrets, cfg.MaxOutputBytes, emit)
		}
		wasEnabled, found := zapScannerEnabled(state, zapDomXSSPluginID)
		if !found {
			return finishServiceFailure(run, errors.New("ZAP did not report the DOM XSS rule state; refusing to change daemon-global policy"), secrets, cfg.MaxOutputBytes, emit)
		}
		if wasEnabled {
			defer func() {
				if err := zapPost(cfg, "/JSON/ascan/action/enableScanners/", url.Values{"ids": {zapDomXSSPluginID}}); err != nil {
					quarantineZAPService(cfg.ZAPURL, "restore DOM XSS rule: "+err.Error())
					logLine("ZAP cleanup failed; daemon quarantined: " + err.Error())
				}
			}()
		}
	}
	// Disable the DOM XSS active scan rule (plugin 40026). It drives headless
	// Firefox through Selenium, whose memory lands on top of the JVM heap and
	// exceeds ZAP's container limit mid-scan; the browser child is OOM-killed and
	// the daemon comes down (surfacing as "connection refused" on the next poll).
	// Reflected and persistent XSS over HTTP stay covered by the other XSS rules.
	// Best-effort: a ZAP build without the DOM XSS add-on has nothing to disable,
	// so a failure here is logged, not fatal.
	if _, err := call("/JSON/ascan/action/disableScanners/", url.Values{"ids": {zapDomXSSPluginID}}); err != nil {
		logLine("could not disable ZAP DOM XSS scan rule: " + err.Error())
	} else {
		logLine("ZAP DOM XSS scan rule disabled (avoids headless-browser OOM)")
	}
	activeParams := url.Values{"url": {target}, "recurse": {"true"}, "inScopeOnly": {"false"}}
	if req.TypedAssessment {
		activeParams.Set("contextId", contextID)
		activeParams.Set("inScopeOnly", "true")
	}
	if err := checkAuth(); err != nil {
		return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
	}
	active, err := call("/JSON/ascan/action/scan/", activeParams)
	if err != nil {
		// The active scan runs over the Sites tree. An empty tree (the spider
		// found nothing reachable and the pre-seed did not land) surfaces as
		// this ZAP error; translate it into a plain explanation instead of the
		// raw API string.
		if strings.Contains(err.Error(), "url_not_found") || strings.Contains(err.Error(), "URL Not Found in the Scan Tree") {
			return finishServiceFailure(run, fmt.Errorf("ZAP found no reachable pages to scan on %s — the spider returned nothing (the target may block automated crawling, require JavaScript rendering, or speak only HTTP/2, which ZAP's crawler does not fetch)", target), secrets, cfg.MaxOutputBytes, emit)
		}
		return finishServiceFailure(run, fmt.Errorf("start ZAP active scan: %w", err), secrets, cfg.MaxOutputBytes, emit)
	}
	activeID := valueString(active, "scan")
	if activeID == "" || activeID == "<nil>" {
		return finishServiceFailure(run, fmt.Errorf("ZAP did not return an active scan id"), secrets, cfg.MaxOutputBytes, emit)
	}
	logLine("ZAP active scan started: " + activeID)
	if err := zapWaitScanChecked(cctx, call, "/JSON/ascan/view/status/", activeID, "active scan", logLine, checkAuth); err != nil {
		zapStopScan(cfg, "/JSON/ascan/action/stop/", activeID)
		return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
	}
	logLine("ZAP passive scan: waiting for active-scan traffic to be analyzed")
	if err := zapWaitPassiveChecked(cctx, call, logLine, checkAuth); err != nil {
		return finishServiceFailure(run, fmt.Errorf("ZAP passive scan after active scan: %w", err), secrets, cfg.MaxOutputBytes, emit)
	}
	logLine("ZAP passive scan complete after active scan")
	// Scope the export to this target. The ZAP daemon is long-lived and shared
	// by every scan, so a session-wide report would fold alerts raised against
	// previously scanned hosts into this scan's artifact.
	if err := checkAuth(); err != nil {
		return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
	}
	report, err := fetch("/JSON/core/view/alerts/", url.Values{"baseurl": {target}}, 10*time.Minute)
	if err != nil {
		return finishServiceFailure(run, fmt.Errorf("export ZAP alerts: %w", err), secrets, cfg.MaxOutputBytes, emit)
	}
	if err := os.WriteFile(run.ArtifactPath, report, 0o600); err != nil {
		return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
	}
	logLine(fmt.Sprintf("ZAP alerts exported for %s (%d bytes)", target, len(report)))
	if err := redactArtifact(run.ArtifactPath, secrets); err != nil {
		return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
	}
	if truncateArtifact(run.ArtifactPath, cfg.MaxOutputBytes) {
		run.Truncated = true
		run.Reason = fmt.Sprintf("artifact truncated at configured %d-byte limit", cfg.MaxOutputBytes)
	}
	run.Status, run.ExitCode, run.FinishedAt = "completed", 0, time.Now().Format(time.RFC3339Nano)
	run = finalizeRun(run)
	if emit != nil {
		emit(Event{Type: "scanner_completed", Scanner: "zap", Run: run})
	}
	return run
}

func zapScannerEnabled(response map[string]any, id string) (bool, bool) {
	items, ok := response["scanners"].([]any)
	if !ok {
		return false, false
	}
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok || valueString(entry, "id") != id {
			continue
		}
		state := strings.ToLower(valueString(entry, "enabled"))
		if state == "true" || state == "1" {
			return true, true
		}
		if state == "false" || state == "0" {
			return false, true
		}
		return false, false
	}
	return false, false
}

type zapCallFunc func(string, url.Values) (map[string]any, error)

type zapAuthMonitor struct {
	current  []string
	refresh  func(context.Context, []string) ([]string, error)
	interval time.Duration
	next     time.Time
}

func (m *zapAuthMonitor) check(ctx context.Context, replace func([]string) error) error {
	if m.refresh == nil || (!m.next.IsZero() && time.Now().Before(m.next)) {
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	next, err := m.refresh(ctx, append([]string(nil), m.current...))
	if err != nil || len(next) != len(m.current) {
		return errors.New("authenticated session expired or verification failed")
	}
	if !slices.Equal(next, m.current) {
		if err := replace(next); err != nil {
			return err
		}
		m.current = append([]string(nil), next...)
	}
	m.next = time.Now().Add(m.interval)
	return nil
}

// zapWaitScan polls a spider or active-scan job until ZAP reports 100%.
func zapWaitScan(ctx context.Context, call zapCallFunc, statusPath, scanID, label string, log func(string)) error {
	return zapWaitScanChecked(ctx, call, statusPath, scanID, label, log, nil)
}

func zapWaitScanChecked(ctx context.Context, call zapCallFunc, statusPath, scanID, label string, log func(string), check func() error) error {
	last := ""
	for {
		if check != nil {
			if err := check(); err != nil {
				return err
			}
		}
		resp, err := call(statusPath, url.Values{"scanId": {scanID}})
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("poll ZAP %s: %w", label, err)
		}
		status := valueString(resp, "status")
		if status != last {
			log("ZAP " + label + " progress: " + status + "%")
			last = status
		}
		if status == "100" {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// zapWaitPassive drains the passive scan queue so alerts raised against
// already-crawled messages are in the report. Failure to inspect the queue
// means passive coverage cannot be confirmed.
func zapWaitPassive(ctx context.Context, call zapCallFunc, log func(string)) error {
	return zapWaitPassiveChecked(ctx, call, log, nil)
}

func zapWaitPassiveChecked(ctx context.Context, call zapCallFunc, log func(string), check func() error) error {
	for {
		if check != nil {
			if err := check(); err != nil {
				return err
			}
		}
		resp, err := call("/JSON/pscan/view/recordsToScan/", url.Values{})
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("query ZAP passive scan queue: %w", err)
		}
		remaining := valueString(resp, "recordsToScan")
		count, err := strconv.Atoi(remaining)
		if err != nil || count < 0 {
			return fmt.Errorf("invalid ZAP passive scan queue count %q", remaining)
		}
		if count == 0 {
			return nil
		}
		log("ZAP passive scan queue: " + remaining + " record(s)")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func zapRemoveRule(cfg Config, description string) error {
	return zapPost(cfg, "/JSON/replacer/action/removeRule/", url.Values{"description": {description}})
}

func zapStopScan(cfg Config, path, scanID string) {
	_ = zapPost(cfg, path, url.Values{"scanId": {scanID}})
}

// zapPost issues a best-effort ZAP API call on its own short-lived context, for
// teardown that has to outlive a cancelled scan.
func zapPost(cfg Config, path string, q url.Values) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	q.Set("apikey", cfg.ZAPAPIKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(cfg.ZAPURL, "/")+path+"?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("ZAP API %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var response map[string]any
	if json.Unmarshal(body, &response) == nil {
		if code := valueString(response, "code"); code != "" && code != "<nil>" {
			return fmt.Errorf("ZAP API %s: %s", code, valueString(response, "message"))
		}
	}
	return nil
}

// zapPostResponse sends action parameters in a form body. Authentication
// replacer rules contain credentials, so they must not appear in the URL/query
// where reverse proxies commonly record them. ZAP accepts its API key header.
func zapPostResponse(parent context.Context, cfg Config, path string, body url.Values) (map[string]any, error) {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(cfg.ZAPURL, "/")+path, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cfg.ZAPAPIKey != "" {
		req.Header.Set("X-ZAP-API-Key", cfg.ZAPAPIKey)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("ZAP API %s", resp.Status)
	}
	var result map[string]any
	if json.Unmarshal(data, &result) == nil {
		if code := valueString(result, "code"); code != "" && code != "<nil>" {
			return nil, fmt.Errorf("ZAP API %s: %s", code, valueString(result, "message"))
		}
	}
	return result, nil
}

func valueString(m map[string]any, key string) string {
	v := m[key]
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.Itoa(int(x))
	default:
		return fmt.Sprint(x)
	}
}
func notApplicableRun(name string, req Request, cfg Config, reason string, emit EmitFunc) Run {
	return executeSpec(context.Background(), name, req, cfg, commandSpec{notApp: reason}, emit)
}
func failedServiceRun(name string, req Request, reason string, emit EmitFunc) Run {
	base := filepath.Join(req.ScanDir, "scanner-output", name)
	_ = os.MkdirAll(base, 0o700)
	now := time.Now().Format(time.RFC3339Nano)
	r := Run{Scanner: name, Target: req.Target, Scope: req.Scope, Status: "failed", Reason: reason, StartedAt: now, FinishedAt: now, ExitCode: -1, StdoutPath: filepath.Join(base, "stdout.log"), StderrPath: filepath.Join(base, "stderr.log")}
	_ = os.WriteFile(r.StdoutPath, nil, 0o600)
	_ = os.WriteFile(r.StderrPath, []byte(reason+"\n"), 0o600)
	r = finalizeRun(r)
	if emit != nil {
		emit(Event{Type: "scanner_failed", Scanner: name, Run: r, Output: reason})
	}
	return r
}
func finishServiceFailure(run Run, err error, secrets []string, limit int64, emit EmitFunc) Run {
	run.Status = "failed"
	if errors.Is(err, context.Canceled) {
		run.Status = "cancelled"
	}
	run.Reason = redact(err.Error(), secrets)
	run.FinishedAt = time.Now().Format(time.RFC3339Nano)
	data := []byte(run.Reason + "\n")
	if limit > 0 && int64(len(data)) > limit {
		data = data[:limit]
		run.Truncated = true
	}
	_ = appendFile(run.StderrPath, data)
	run = finalizeRun(run)
	if emit != nil {
		emit(Event{Type: "scanner_failed", Scanner: run.Scanner, Run: run, Output: run.Reason})
	}
	return run
}
