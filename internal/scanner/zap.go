package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

	"github.com/xalgord/xalgorix/v4/internal/assessment"
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

// applicationContextRegex is the ZAP context (and replacer) regex for the
// application at rawURL: its origin and path boundary. The origin is normalized
// by assessment.ParseApprovedOrigin, the same normalizer AppScope uses, and a
// default port matches whether or not ZAP's URL spells it out
// (https://a/x and https://a:443/x are the same request target).
func applicationContextRegex(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" {
		return "", fmt.Errorf("invalid application URL for ZAP context")
	}
	origin, err := assessment.ParseApprovedOrigin("", rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid application URL for ZAP context")
	}
	pathRule := `(?:/.*)?`
	if prefix := strings.TrimSuffix(origin.PathPrefix, "/"); prefix != "" {
		pathRule = regexp.QuoteMeta((&url.URL{Path: prefix}).EscapedPath()) + `(?:/.*)?`
	}
	return "^" + zapOriginPattern(origin) + pathRule + `(?:\?.*)?$`, nil
}

// zapOriginPattern matches a normalized origin in a ZAP URL, with the default
// port optional.
func zapOriginPattern(o assessment.ApprovedOrigin) string {
	host := o.Host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	pattern := regexp.QuoteMeta(o.Scheme + "://" + host)
	port := o.Port
	if port == 0 {
		port = zapDefaultPort(o.Scheme)
	}
	if port == zapDefaultPort(o.Scheme) {
		return pattern + "(?::" + strconv.Itoa(port) + ")?"
	}
	return pattern + regexp.QuoteMeta(":"+strconv.Itoa(port))
}

func zapDefaultPort(scheme string) int {
	if scheme == "http" {
		return 80
	}
	return 443
}

// zapExclusionRegexes translates scope exclusions into full-URL ZAP regexes,
// reusing Exclusion.PathRegex for the path. ZAP cannot exclude by method, so a
// method-bound exclusion is applied to every method (fail closed); the second
// result reports whether that happened. An exclusion bound to a target with no
// origin in this scope applies to nothing here and is skipped.
func zapExclusionRegexes(scope *assessment.AppScope) ([]string, bool) {
	if scope == nil {
		return nil, false
	}
	var out []string
	widened := false
	for _, e := range scope.Exclusions() {
		var origins []string
		switch {
		case e.Origin != "":
			o, err := assessment.ParseApprovedOrigin("", e.Origin)
			if err != nil {
				continue
			}
			origins = append(origins, zapOriginPattern(o))
		case e.TargetID != "":
			for _, o := range scope.Origins() {
				if o.TargetID == e.TargetID {
					origins = append(origins, zapOriginPattern(o))
				}
			}
			if len(origins) == 0 {
				continue
			}
		default:
			origins = append(origins, `https?://[^/?#]+`)
		}
		path := strings.TrimSuffix(strings.TrimPrefix(e.PathRegex(), "(?i)^"), "$")
		pattern := `(?i)^(?:` + strings.Join(origins, "|") + `)` + path + `(?:[?#].*)?$`
		if !slices.Contains(out, pattern) {
			out = append(out, pattern)
		}
		if e.Method != "" {
			widened = true
		}
	}
	return out, widened
}

// zapRateOptions converts the single configured request rate into ZAP's
// active-scan options: one thread per host with a delay between its requests,
// rounded up so the daemon never exceeds rps.
func zapRateOptions(rps int) (delayMS, threadsPerHost int) {
	if rps <= 0 {
		return 0, 0
	}
	return (1000 + rps - 1) / rps, 1
}

// zapAuthInterval is how often a long ZAP job re-verifies its session.
var zapAuthInterval = time.Minute

// errZAPSessionLost marks a failed session verification, as opposed to a
// daemon error while installing renewed headers.
var errZAPSessionLost = errors.New("authenticated session expired or verification failed")

type zapRunner struct{}

func (zapRunner) Name() string { return "zap" }

func (zapRunner) Descriptor() Descriptor {
	return Descriptor{Name: "zap", Summary: "Spider and active scan of each HTTP/HTTPS host", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightHeavy, Applies: appliesToHost}
}

func (zapRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) (final Run) {
	if req.StructuredDispatch && len(req.EndpointTargets) == 0 && len(req.InputRequests) == 0 {
		return notApplicableRun("zap", req, cfg, "ZAP has no dispatcher-approved API, parameter, form, or sensitive endpoint to test", emit)
	}
	if req.ZAPDiscoveryOnly && (!expandedWorkflowRequest(req) || !req.TypedAssessment || req.AppScope == nil) {
		return failedServiceRun("zap", req, "supplemental discovery requires the approved unified workflow scope", emit)
	}
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
	if req.TypedAssessment && (strings.TrimSpace(req.TargetAuth) != "" || strings.EqualFold(req.AuthKind, "form login")) && req.AuthRefresh == nil {
		return failedServiceRun("zap", req, "authenticated assessment requires an active session verifier", emit)
	}
	// A typed job carries its approved scope; ZAP never starts on an
	// application outside it.
	if req.TypedAssessment && req.AppScope != nil {
		if ok, reason := req.AppScope.Allows(target); !ok {
			return failedServiceRun("zap", req, "ZAP target is outside the approved application scope: "+reason, emit)
		}
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
	// reportProgress publishes ZAP's own spider/active-scan percentage on the
	// run so the WebUI can show live completion for the current stage.
	reportProgress := func(stage string) func(int) {
		return func(pct int) {
			run.Progress, run.ProgressStage = pct, stage
			if emit != nil {
				emit(Event{Type: "scanner_progress", Scanner: "zap", Run: run})
			}
		}
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
		if code := valueString(out, "code"); code != "" && code != "<nil>" {
			return nil, fmt.Errorf("ZAP API %s", code)
		}
		return out, nil
	}
	if _, err := call("/JSON/core/view/version/", url.Values{}); err != nil {
		return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
	}
	if expandedWorkflowRequest(req) && req.TypedAssessment {
		if err := verifyZAPAddons(call); err != nil {
			return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
		}
	}
	var recording *RecordingGateway
	if expandedWorkflowRequest(req) && req.TypedAssessment {
		recording, err = NewRecordingGateway(cctx, req, cfg, "zap")
		if err != nil {
			return finishServiceFailure(run, fmt.Errorf("ZAP recording gateway unavailable"), secrets, cfg.MaxOutputBytes, emit)
		}
		run.CoverageEventsPath = recording.EventPath
		secrets = append(secrets, recording.password)
		recording.SetPhase("seeding")
		if req.ZAPDiscoveryOnly {
			recording.SetPhase("discovery")
		}
		restore, installErr := configureZAPGateway(cfg, call, recording)
		if installErr != nil {
			recording.Close()
			return finishServiceFailure(run, installErr, secrets, cfg.MaxOutputBytes, emit)
		}
		defer func() {
			if err := restore(); err != nil {
				quarantineZAPService(cfg.ZAPURL, "recording proxy restore failed")
				final.Status, final.Reason = "failed", "ZAP recording proxy cleanup failed"
			}
			if err := recording.Close(); err != nil {
				final.Status, final.Reason = "failed", "ZAP coverage recording failed"
			}
			recording.ApplyOutcome(&final)
			final = finalizeRun(final)
		}()
	}
	exclusionRegexes, widened := zapExclusionRegexes(req.AppScope)
	contextName, contextID, scopeRegex := "", "", ""
	authScopeRegex, _ := applicationContextRegex(target)
	if req.TypedAssessment {
		var err error
		scopeRegex, err = applicationContextRegex(target)
		if expandedWorkflowRequest(req) && req.AppScope != nil {
			scopeRegex, err = zapApprovedContextRegex(*req.AppScope)
		}
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
		for _, regex := range exclusionRegexes {
			if _, err := call("/JSON/context/action/excludeFromContext/", url.Values{"contextName": {contextName}, "regex": {regex}}); err != nil {
				return finishServiceFailure(run, fmt.Errorf("exclude configured routes from the ZAP context: %w", err), secrets, cfg.MaxOutputBytes, emit)
			}
		}
		if _, err := call("/JSON/context/action/setContextInScope/", url.Values{"contextName": {contextName}, "booleanInScope": {"true"}}); err != nil {
			return finishServiceFailure(run, fmt.Errorf("enable target context scope: %w", err), secrets, cfg.MaxOutputBytes, emit)
		}
	}
	// Configured exclusions also bind the spider and the active scan on every
	// path, legacy included. Both lists are daemon-global, so the prior entries
	// are captured and put back afterwards; a scan that cannot install its
	// exclusions does not run.
	if len(exclusionRegexes) > 0 {
		if widened {
			logLine("ZAP cannot exclude by HTTP method; method-specific exclusions are applied to every method")
		}
		for _, list := range []string{"spider", "ascan"} {
			prior, err := call("/JSON/"+list+"/view/excludedFromScan/", url.Values{})
			if err != nil {
				return finishServiceFailure(run, fmt.Errorf("read ZAP %s exclusions: %w", list, err), secrets, cfg.MaxOutputBytes, emit)
			}
			previous, ok := zapStringList(prior, "excludedFromScan")
			if !ok {
				return finishServiceFailure(run, fmt.Errorf("ZAP did not report its %s exclusions; refusing to change daemon-global exclusions", list), secrets, cfg.MaxOutputBytes, emit)
			}
			defer func() {
				err := zapPost(cfg, "/JSON/"+list+"/action/clearExcludedFromScan/", url.Values{})
				for _, regex := range previous {
					if err != nil {
						break
					}
					err = zapPost(cfg, "/JSON/"+list+"/action/excludeFromScan/", url.Values{"regex": {regex}})
				}
				if err != nil {
					quarantineZAPService(cfg.ZAPURL, "restore "+list+" exclusions: "+err.Error())
					logLine("ZAP cleanup failed; daemon quarantined: " + err.Error())
				}
			}()
			for _, regex := range exclusionRegexes {
				if _, err := call("/JSON/"+list+"/action/excludeFromScan/", url.Values{"regex": {regex}}); err != nil {
					return finishServiceFailure(run, fmt.Errorf("apply configured exclusions to ZAP %s: %w", list, err), secrets, cfg.MaxOutputBytes, emit)
				}
			}
		}
		logLine(fmt.Sprintf("ZAP exclusions applied to context, spider and active scan: %d route pattern(s)", len(exclusionRegexes)))
	}
	// The configured request rate becomes ZAP's active-scan delay with one
	// thread per host. These options are daemon-global and restored after the
	// scan. A typed job refuses to run unthrottled; a legacy job logs and keeps
	// its historical behavior.
	if delayMS, threads := zapRateOptions(cfg.RateRPS); delayMS > 0 {
		restore, err := zapApplyRate(cfg, call, delayMS, threads, req.TypedAssessment, logLine)
		if restore != nil {
			defer restore()
		}
		if err != nil {
			if req.TypedAssessment {
				return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
			}
			logLine("could not apply ZAP rate limit (continuing): " + err.Error())
		}
	}
	// Apply configured scan and per-target authentication headers through
	// deterministic ZAP replacer rules before crawling. No model interprets
	// authentication material.
	var headers []string
	if !req.TypedAssessment {
		headers = append(headers, cfg.ScanHeaders...)
	}
	for _, raw := range strings.Split(req.TargetAuth, "\n") {
		if strings.TrimSpace(raw) != "" {
			headers = append(headers, raw)
		}
	}
	if len(headers) == 0 {
		logLine("Authentication: no credentials supplied; running unauthenticated ZAP scan")
	} else if req.AuthRefresh == nil {
		logLine("Authentication: credentials supplied without a session verifier; authenticated state cannot be confirmed")
	}
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
			params.Set("url", authScopeRegex)
		}
		_, err := zapPostResponse(cctx, cfg, "/JSON/replacer/action/addRule/", params)
		if err != nil {
			return finishServiceFailure(run, fmt.Errorf("configure ZAP header %s: %w", strings.TrimSpace(name), err), secrets, cfg.MaxOutputBytes, emit)
		}
	}
	// Check authentication at stage boundaries and while waiting on long ZAP
	// jobs. A refreshed cookie replaces its scoped daemon rule in this lease.
	authMonitor := &zapAuthMonitor{current: headers, refresh: req.AuthRefresh, interval: zapAuthInterval}
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
				params := url.Values{"description": {rules[i]}, "enabled": {"true"}, "matchType": {"REQ_HEADER"}, "matchRegex": {"false"}, "matchString": {strings.TrimSpace(name)}, "replacement": {strings.TrimSpace(value)}, "url": {authScopeRegex}}
				if _, err := zapPostResponse(cctx, cfg, "/JSON/replacer/action/addRule/", params); err != nil {
					return errors.New("authenticated session header could not be installed")
				}
				secrets = append(secrets, strings.TrimSpace(value))
			}
			headers = append([]string(nil), next...)
			if recording != nil {
				recording.UpdateTargetAuth(next)
			}
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
			// Record the session outcome structurally. A session that verified
			// earlier in this run and is now rejected expired mid-scan; one
			// rejected at the first check failed verification.
			if errors.Is(err, errZAPSessionLost) {
				run.AuthState, run.GapKind = assessment.StateExpired, GapAuthExpired
				if initialCheck {
					run.AuthState, run.GapKind = assessment.StateFailed, GapAuthFailed
				}
				run.AuthCheckedAt = time.Now().UTC().Format(time.RFC3339)
			}
			return err
		}
		if verificationDue {
			run.AuthState, run.AuthCheckedAt = assessment.StateVerified, time.Now().UTC().Format(time.RFC3339)
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

	if expandedWorkflowRequest(req) && req.TypedAssessment {
		run.DefinitionImports = zapImportDefinitions(cctx, cfg, req, contextID)
		for _, result := range run.DefinitionImports {
			if result.Status == "failed" {
				run.Completeness = "partial"
			}
		}
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
	// seedRefusal is why a URL must not be seeded: outside a typed job's
	// approved scope, or matching a configured exclusion. Seeding sends a GET.
	seedRefusal := func(method, rawURL string) string {
		if req.AppScope == nil {
			return ""
		}
		if req.TypedAssessment {
			if ok, reason := req.AppScope.Allows(rawURL); !ok {
				return reason
			}
		}
		for _, m := range []string{method} {
			if excluded, reason := req.AppScope.Excluded(m, rawURL); excluded {
				return "excluded: " + reason
			}
		}
		return ""
	}
	seedRequest := func(method, rawURL string) error {
		input := ScannerRequestInput{Method: method, URL: rawURL, Selected: true}
		return zapSeedRequest(cctx, cfg, call, input)
	}
	if req.StructuredDispatch {
		logLine("ZAP target anchor is inventory-only; selected request seeds are authoritative")
	} else if refusal := seedRefusal(http.MethodGet, target); refusal != "" {
		logLine("ZAP did not pre-seed the target: " + refusal)
	} else if _, err := call("/JSON/core/action/accessUrl/", url.Values{"url": {target}, "followRedirects": {followRedirects}}); err != nil {
		logLine("ZAP could not pre-seed the target (continuing to spider): " + err.Error())
	} else {
		logLine("ZAP seeded target into scan tree: " + target)
	}
	if req.TypedAssessment && !req.StructuredDispatch && len(req.APIEndpoints) > 0 {
		seeded := 0
		for _, endpoint := range req.APIEndpoints {
			if err := checkAuth(); err != nil {
				return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
			}
			result := APIEndpointResult{Method: endpoint.Method, Path: endpoint.Path, Origin: endpoint.Origin}
			if !endpoint.Eligible || !endpoint.Resolved || (endpoint.Method != http.MethodGet && endpoint.Method != http.MethodHead && endpoint.Method != http.MethodOptions) {
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
			operationURL := endpoint.RequestURL
			var urlErr error
			if operationURL == "" {
				operationURL, urlErr = apiEndpointURL(target, endpoint)
			}
			if urlErr != nil {
				result.Status, result.Reason = "skipped", urlErr.Error()
				run.APIEndpointResults = append(run.APIEndpointResults, result)
				continue
			}
			if refusal := seedRefusal(endpoint.Method, operationURL); refusal != "" {
				result.Status, result.Reason = "skipped", refusal
				run.APIEndpointResults = append(run.APIEndpointResults, result)
				continue
			}
			if seedErr := seedRequest(endpoint.Method, operationURL); seedErr != nil {
				result.Status, result.Reason = "failed", "ZAP could not seed this operation into the scoped scan tree"
			} else {
				result.Status = "seeded"
				seeded++
			}
			run.APIEndpointResults = append(run.APIEndpointResults, result)
		}
	}

	// Seed katana-discovered URLs into the scan tree so the active scan covers
	// endpoints ZAP's own spider may not reach (JS apps, unlinked routes). These
	// URLs are already FQDN-scoped by the crawl. Bounded by the same web-endpoint
	// budget and best-effort per URL — a seed failure is logged, not fatal.
	inputs := zapSelectedRequests(req)
	seeded := 0
	for _, input := range inputs {
		submission := EndpointSubmission{EndpointID: input.EndpointID, Method: input.Method, URL: SafeTelemetryURL(input.URL), At: time.Now().UTC().Format(time.RFC3339Nano)}
		refusal := seedRefusal(input.Method, input.URL)
		if seeded >= maxChildren {
			refusal = "web request budget exhausted before seeding"
		}
		if !input.Selected {
			refusal = input.Reason
			if refusal == "" {
				refusal = "request was not selected"
			}
		}
		if input.Method != http.MethodGet && input.Method != http.MethodHead && input.Method != http.MethodOptions && !(input.ReadOnly && input.Method == http.MethodPost && input.Body != "" && browserDiscoveryRequestAllowed(req, cfg, input.Method, input.URL, input.ContentType, []byte(input.Body)) == nil) {
			refusal = "state-changing request requires an approved operation and fixture"
		}
		if input.BodyDigest != "" && input.Body == "" {
			refusal = "request body replay data unavailable"
		}
		if refusal != "" {
			submission.Status, submission.Reason = "skipped", refusal
			run.Submissions = append(run.Submissions, submission)
			continue
		}
		if err := checkAuth(); err != nil {
			submission.Status, submission.Reason = "failed", "authentication checkpoint failed before submission"
			run.Submissions = append(run.Submissions, submission)
			for _, pending := range inputs[len(run.Submissions):] {
				run.Submissions = append(run.Submissions, EndpointSubmission{EndpointID: pending.EndpointID, Method: pending.Method, URL: SafeTelemetryURL(pending.URL), Status: "skipped", Reason: "authentication failed before submission", At: time.Now().UTC().Format(time.RFC3339Nano)})
			}
			return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
		}
		if seedErr := zapSeedRequest(cctx, cfg, call, input); seedErr == nil {
			seeded++
			submission.Status = "acknowledged"
		} else {
			submission.Status, submission.Reason = "failed", "ZAP rejected request seeding"
			run.Completeness = "partial"
			logLine("ZAP seed failed for " + SafeTelemetryURL(input.URL))
		}
		run.Submissions = append(run.Submissions, submission)
	}
	if req.StructuredDispatch {
		for _, endpoint := range req.APIEndpoints {
			result := APIEndpointResult{Method: endpoint.Method, Path: endpoint.Path, Origin: endpoint.Origin, Status: "skipped", Reason: "operation was not selected as an exact inventory request"}
			raw := endpoint.RequestURL
			if raw == "" {
				raw, _ = apiEndpointURL(target, endpoint)
			}
			if !endpoint.Resolved || !endpoint.Eligible {
				if endpoint.Reason != "" {
					result.Reason = endpoint.Reason
				}
			} else {
				for i, input := range inputs {
					if input.URL == raw && input.Method == endpoint.Method && i < len(run.Submissions) {
						submission := run.Submissions[i]
						result.Status, result.Reason = submission.Status, submission.Reason
						if submission.Status == "acknowledged" {
							result.Status = "seeded"
						}
						break
					}
				}
			}
			run.APIEndpointResults = append(run.APIEndpointResults, result)
		}
	}
	if seeded > 0 {
		logLine(fmt.Sprintf("ZAP acknowledged %d inventory request submissions", seeded))
	}

	// Legacy scans retain ZAP's crawler. Structured dispatch deliberately does
	// not spider again: doing so would rediscover and submit POST forms that the
	// safe dispatcher marked inventory-only. Its active scan therefore operates
	// on explicitly selected request seeds, without a separate root request.
	if !req.StructuredDispatch || req.ZAPDiscoveryOnly {
		if req.ZAPDiscoveryOnly {
			restoreSpider, err := configureSafeZAPSpider(cfg, call)
			defer func() {
				if restoreSpider != nil {
					if err := restoreSpider(); err != nil {
						quarantineZAPService(cfg.ZAPURL, "restore supplemental spider policy failed")
						final.Status, final.Reason = "failed", "ZAP spider policy cleanup failed"
					}
				}
			}()
			if err != nil {
				return finishServiceFailure(run, fmt.Errorf("configure bounded read-only spider: %w", err), secrets, cfg.MaxOutputBytes, emit)
			}
		}
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
		if err := zapWaitScanChecked(cctx, call, "/JSON/spider/view/status/", spiderID, "spider", logLine, checkAuth, reportProgress("spider")); err != nil {
			zapStopScan(cfg, "/JSON/spider/action/stop/", spiderID)
			return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
		}
		logLine("ZAP passive scan: waiting for spider traffic to be analyzed")
		if err := zapWaitPassiveChecked(cctx, call, logLine, checkAuth); err != nil {
			return finishServiceFailure(run, fmt.Errorf("ZAP passive scan after spider: %w", err), secrets, cfg.MaxOutputBytes, emit)
		}
		logLine("ZAP passive scan complete after spider")
	} else {
		logLine("ZAP spider skipped: structured dispatcher seeded safe endpoints only")
		if err := zapWaitPassiveChecked(cctx, call, logLine, checkAuth); err != nil {
			return finishServiceFailure(run, fmt.Errorf("ZAP passive scan after endpoint seeding: %w", err), secrets, cfg.MaxOutputBytes, emit)
		}
	}
	if req.ZAPDiscoveryOnly {
		if recording == nil {
			return finishServiceFailure(run, errors.New("discovery recording unavailable"), secrets, cfg.MaxOutputBytes, emit)
		}
		if err := recording.Close(); err != nil {
			return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
		}
		if err := saveZAPDiscoveryArtifact(req, &run, cfg); err != nil {
			return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
		}
		return finalizeRun(run)
	}
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
	if recording != nil {
		recording.SetPhase("active_test")
	}
	activeTargets := []string{target}
	if expandedWorkflowRequest(req) && req.AppScope != nil {
		activeTargets = nil
		for _, o := range req.AppScope.Origins() {
			activeTargets = append(activeTargets, o.Origin()+o.PathPrefix)
		}
	}
	for _, activeTarget := range activeTargets {
		activeParams.Set("url", activeTarget)
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
		run.NativeScanIDs = append(run.NativeScanIDs, activeID)
		if activeID == "" || activeID == "<nil>" {
			return finishServiceFailure(run, fmt.Errorf("ZAP did not return an active scan id"), secrets, cfg.MaxOutputBytes, emit)
		}
		logLine("ZAP active scan started: " + activeID)
		if err := zapWaitScanChecked(cctx, call, "/JSON/ascan/view/status/", activeID, "active scan", logLine, checkAuth, reportProgress("active scan")); err != nil {
			zapStopScan(cfg, "/JSON/ascan/action/stop/", activeID)
			return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
		}
		logLine("ZAP passive scan: waiting for active-scan traffic to be analyzed")

	}
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
	exportParams := url.Values{"baseurl": {target}}
	if expandedWorkflowRequest(req) && req.TypedAssessment {
		exportParams = url.Values{}
	}
	report, err := fetch("/JSON/core/view/alerts/", exportParams, 10*time.Minute)
	if err == nil && expandedWorkflowRequest(req) && req.AppScope != nil {
		report, err = filterZAPScopeAlerts(report, *req.AppScope)
	}
	if err != nil {
		return finishServiceFailure(run, fmt.Errorf("export ZAP alerts: %w", err), secrets, cfg.MaxOutputBytes, emit)
	}
	if err := os.WriteFile(run.ArtifactPath, report, 0o600); err != nil {
		return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
	}
	logLine(fmt.Sprintf("ZAP alerts exported for %s (%d bytes)", target, len(report)))
	if err := redactArtifact(run.ArtifactPath, secrets); err != nil {
		invalidateUnsafeArtifact(&run)
		return finishServiceFailure(run, fmt.Errorf("scanner artifact redaction failed; artifact is unavailable"), secrets, cfg.MaxOutputBytes, emit)
	}
	bounded, boundErr := boundWebArtifact(run.ArtifactPath, "zap", cfg.MaxOutputBytes)
	if boundErr != nil {
		run.ExecutionOutcome, run.Outcome = "SUCCESS", "PARSER_FAILED"
		run.ParserOutcome, run.Completeness = "FAILED", "partial"
		return finishServiceFailure(run, fmt.Errorf("retain bounded ZAP artifact: %w", boundErr), secrets, cfg.MaxOutputBytes, emit)
	}
	if bounded {
		run.Truncated = true
		run.Reason = fmt.Sprintf("artifact truncated at configured %d-byte limit", cfg.MaxOutputBytes)
	}
	run.Status, run.ExitCode, run.FinishedAt = "completed", 0, time.Now().Format(time.RFC3339Nano)
	run.Progress, run.ProgressStage = 0, ""
	validateWebResult(&run)
	run = finalizeRun(run)
	if emit != nil {
		emit(Event{Type: "scanner_completed", Scanner: "zap", Run: run})
	}
	return run
}

// zapApplyRate reads ZAP's active-scan delay and threads-per-host, installs
// the configured rate and returns the restore for the prior values. A failed
// restore quarantines a dedicated (typed) daemon, like the DOM XSS restore: the
// next job would inherit this throttle or a half-restored one. A shared legacy
// daemon only logs it. restore is nil when nothing was changed.
func zapApplyRate(cfg Config, call zapCallFunc, delayMS, threads int, quarantine bool, log func(string)) (func(), error) {
	delayView, err := call("/JSON/ascan/view/optionDelayInMs/", url.Values{})
	if err != nil {
		return nil, fmt.Errorf("read ZAP active-scan delay: %w", err)
	}
	threadView, err := call("/JSON/ascan/view/optionThreadPerHost/", url.Values{})
	if err != nil {
		return nil, fmt.Errorf("read ZAP active-scan threads per host: %w", err)
	}
	priorDelay, delayErr := strconv.Atoi(valueString(delayView, "DelayInMs"))
	priorThreads, threadErr := strconv.Atoi(valueString(threadView, "ThreadPerHost"))
	if delayErr != nil || threadErr != nil || priorDelay < 0 || priorThreads < 1 {
		return nil, errors.New("ZAP did not report its active-scan rate options; refusing to change daemon-global options")
	}
	restore := func() {
		err := zapPost(cfg, "/JSON/ascan/action/setOptionDelayInMs/", url.Values{"Integer": {strconv.Itoa(priorDelay)}})
		if err == nil {
			err = zapPost(cfg, "/JSON/ascan/action/setOptionThreadPerHost/", url.Values{"Integer": {strconv.Itoa(priorThreads)}})
		}
		if err != nil && quarantine {
			quarantineZAPService(cfg.ZAPURL, "restore active-scan rate options: "+err.Error())
			log("ZAP cleanup failed; daemon quarantined: " + err.Error())
		} else if err != nil {
			log("could not restore ZAP active-scan rate options: " + err.Error())
		}
	}
	if _, err := call("/JSON/ascan/action/setOptionDelayInMs/", url.Values{"Integer": {strconv.Itoa(delayMS)}}); err != nil {
		return restore, fmt.Errorf("set ZAP active-scan delay: %w", err)
	}
	if _, err := call("/JSON/ascan/action/setOptionThreadPerHost/", url.Values{"Integer": {strconv.Itoa(threads)}}); err != nil {
		return restore, fmt.Errorf("set ZAP active-scan threads per host: %w", err)
	}
	log(fmt.Sprintf("ZAP active-scan rate limited: %d ms delay, %d thread(s) per host (configured %d req/s)", delayMS, threads, cfg.RateRPS))
	return restore, nil
}

// zapStringList reads a JSON string array such as excludedFromScan.
func zapStringList(response map[string]any, key string) ([]string, bool) {
	items, ok := response[key].([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, false
		}
		out = append(out, text)
	}
	return out, true
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
		return errZAPSessionLost
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
	return zapWaitScanChecked(ctx, call, statusPath, scanID, label, log, nil, nil)
}

// progress, when set, receives each new 0–100 value ZAP reports.
func zapWaitScanChecked(ctx context.Context, call zapCallFunc, statusPath, scanID, label string, log func(string), check func() error, progress func(int)) error {
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
			if pct, convErr := strconv.Atoi(status); progress != nil && convErr == nil && pct >= 0 && pct <= 100 {
				progress(pct)
			}
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

func zapApprovedContextRegex(scope assessment.AppScope) (string, error) {
	var parts []string
	for _, o := range scope.Origins() {
		re, err := applicationContextRegex(o.Origin() + o.PathPrefix)
		if err != nil {
			return "", err
		}
		parts = append(parts, "(?:"+re+")")
	}
	if len(parts) == 0 {
		return "", errors.New("no approved ZAP origins")
	}
	return strings.Join(parts, "|"), nil
}
func filterZAPScopeAlerts(data []byte, scope assessment.AppScope) ([]byte, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	var alerts []map[string]any
	if err := json.Unmarshal(root["alerts"], &alerts); err != nil {
		return nil, err
	}
	kept := []map[string]any{}
	for _, alert := range alerts {
		raw := str(alert["url"])
		method := str(alert["method"])
		if method == "" {
			method = "GET"
		}
		if allowed, _ := scope.Allows(raw); !allowed {
			continue
		}
		if excluded, _ := scope.Excluded(method, raw); excluded {
			continue
		}
		kept = append(kept, alert)
	}
	root["alerts"], _ = json.Marshal(kept)
	return json.Marshal(root)
}
