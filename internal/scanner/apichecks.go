package scanner

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const apiCheckOrigin = "https://xalgorix.invalid"

type apiChecksRunner struct{}

func (apiChecksRunner) Name() string { return "apichecks" }
func (apiChecksRunner) Descriptor() Descriptor {
	return Descriptor{Name: "apichecks", Summary: "Low-impact API authentication and CORS checks on eligible operations", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightLight}
}

func (apiChecksRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	run := Run{Scanner: "apichecks", Target: req.Target, Scope: req.Scope, Status: "running", StartedAt: now}
	finish := func(status, reason string) Run {
		run.Status, run.Reason = status, reason
		return finalizeRun(run)
	}
	if !req.TypedAssessment || req.AppScope == nil || len(req.AppScope.Origins()) == 0 {
		return finish("failed", "native API checks require a typed assessment with an approved application scope")
	}
	allowedByDispatcher := map[string]bool{}
	for _, raw := range req.EndpointTargets {
		allowedByDispatcher[raw] = true
	}
	if len(allowedByDispatcher) == 0 {
		run.GapKind = GapEmptyInput
		return finish("skipped", "no materialized API operations passed the request policy")
	}
	apiEndpoints := slices.Clone(req.APIEndpoints)
	knownURLs := map[string]bool{}
	for i := range apiEndpoints {
		endpoint := &apiEndpoints[i]
		if rawURL, err := apiEndpointURL(req.Target, *endpoint); err == nil {
			for _, sample := range req.EndpointTargets {
				if sameAPIPath(rawURL, sample) {
					endpoint.RequestURL = sample
					break
				}
			}
			if endpoint.RequestURL == "" {
				endpoint.RequestURL = rawURL
			}
			knownURLs[endpoint.RequestURL] = true
		}
	}
	for _, rawURL := range req.EndpointTargets {
		if knownURLs[rawURL] {
			continue
		}
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Host == "" {
			continue
		}
		apiEndpoints = append(apiEndpoints, APIEndpoint{RequestURL: rawURL, Method: http.MethodGet, Path: parsed.EscapedPath(), Origin: parsed.Scheme + "://" + parsed.Host, Source: "discovery", Resolved: true, Eligible: true})
		knownURLs[rawURL] = true
	}
	base := filepath.Join(req.ScanDir, "scanner-output", "apichecks")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return finish("failed", "create native API check artifact directory: "+err.Error())
	}
	artifact := filepath.Join(base, "findings.jsonl")
	file, err := os.OpenFile(artifact, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return finish("failed", "create native API check artifact: "+err.Error())
	}
	run.ArtifactPath = artifact
	if emit != nil {
		emit(Event{Type: "scanner_started", Scanner: run.Scanner, Run: run})
	}
	started, failures, skipped := 0, 0, 0
	writeFinding := func(finding Finding) error {
		return json.NewEncoder(file).Encode(finding)
	}
	for _, endpoint := range apiEndpoints {
		result := APIEndpointResult{Method: endpoint.Method, Path: endpoint.Path, Origin: endpoint.Origin}
		if !endpoint.Resolved || !endpoint.Eligible || (endpoint.Method != http.MethodGet && endpoint.Method != http.MethodHead) {
			result.Status, result.Reason = "skipped", endpoint.Reason
			if result.Reason == "" {
				result.Reason = "operation is not materialized for a safe read-only request"
			}
			appendAPICheckResult(&run, result)
			skipped++
			continue
		}
		rawURL := endpoint.RequestURL
		var err error
		if rawURL == "" {
			rawURL, err = apiEndpointURL(req.Target, endpoint)
		}
		if err != nil {
			result.Status, result.Reason = "skipped", err.Error()
			appendAPICheckResult(&run, result)
			skipped++
			continue
		}
		if !allowedByDispatcher[rawURL] {
			result.Status, result.Reason = "skipped", "operation was not approved by the shared scope and endpoint budget gate"
			appendAPICheckResult(&run, result)
			skipped++
			continue
		}
		if allowed, reason := req.AppScope.Allows(rawURL); !allowed {
			result.Status, result.Reason = "skipped", "operation is outside the approved scope: "+reason
			appendAPICheckResult(&run, result)
			skipped++
			continue
		}
		if excluded, reason := req.AppScope.Excluded(endpoint.Method, rawURL); excluded {
			result.Status, result.Reason = "skipped", "operation is excluded: "+reason
			appendAPICheckResult(&run, result)
			skipped++
			continue
		}
		if err := cfg.Budget.Wait(ctx); err != nil {
			result.Status, result.Reason = "skipped", err.Error()
			appendAPICheckResult(&run, result)
			skipped++
			continue
		}
		requestURL, _ := url.Parse(rawURL)
		addresses, resolveErr := resolveAPICheckAddresses(ctx, requestURL.Hostname())
		if resolveErr != nil {
			result.Status, result.Reason = "failed", "could not resolve approved API host"
			appendAPICheckResult(&run, result)
			failures++
			continue
		}
		addressStrings := make([]string, 0, len(addresses))
		for _, address := range addresses {
			addressStrings = append(addressStrings, address.String())
		}
		if cfg.ScopeGuard != nil {
			if blocked, reason := cfg.ScopeGuard(rawURL, addressStrings); blocked {
				result.Status, result.Reason = "skipped", "execution scope guard refused API request: "+reason
				appendAPICheckResult(&run, result)
				skipped++
				continue
			}
		}
		request, err := http.NewRequestWithContext(ctx, endpoint.Method, rawURL, nil)
		if err != nil {
			result.Status, result.Reason = "failed", "construct API request"
			appendAPICheckResult(&run, result)
			failures++
			continue
		}
		request.Header.Set("Origin", apiCheckOrigin)
		response, err := apiCheckClientFor(requestURL, addresses).Do(request)
		if err != nil {
			result.Status, result.Reason = "failed", "API request failed: "+safeAPIError(err)
			appendAPICheckResult(&run, result)
			failures++
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		_ = response.Body.Close()
		result.Status = "checked"
		appendAPICheckResult(&run, result)
		started++
		if len(endpoint.SecuritySchemes) > 0 && response.StatusCode >= 200 && response.StatusCode < 300 {
			finding := newAPICheckFinding(req, endpoint, rawURL, "api-auth-not-enforced", "Declared API authentication was not enforced", "medium", fmt.Sprintf("OpenAPI declares security scheme(s) %s, but an unauthenticated %s request returned HTTP %d.", strings.Join(endpoint.SecuritySchemes, ", "), endpoint.Method, response.StatusCode), "CWE-862")
			if err := writeFinding(finding); err != nil {
				_ = file.Close()
				return finish("failed", "write API check artifact: "+err.Error())
			}
		}
		allowOrigin := strings.TrimSpace(response.Header.Get("Access-Control-Allow-Origin"))
		allowCredentials := strings.EqualFold(strings.TrimSpace(response.Header.Get("Access-Control-Allow-Credentials")), "true")
		if allowCredentials && strings.EqualFold(allowOrigin, apiCheckOrigin) {
			finding := newAPICheckFinding(req, endpoint, rawURL, "api-cors-credentialed-origin", "Cross-origin access allows credentials", "high", "The response allows credentials for a wildcard or arbitrary supplied Origin value.", "CWE-942")
			if err := writeFinding(finding); err != nil {
				_ = file.Close()
				return finish("failed", "write API check artifact: "+err.Error())
			}
		}
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return finish("failed", "sync API check artifact: "+err.Error())
	}
	if err := file.Close(); err != nil {
		return finish("failed", "close API check artifact: "+err.Error())
	}
	if started == 0 && failures == 0 {
		run.GapKind = GapEmptyInput
		return finish("skipped", "no eligible API operations were checked")
	}
	if failures > 0 {
		run.GapKind = GapRequestFailed
		return finish("failed", fmt.Sprintf("native API checks completed with %d failed and %d skipped operation(s)", failures, skipped))
	}
	return finish("completed", "checked API operations without credentials; results are limited to declared-auth and credentialed-CORS checks")
}

func appendAPICheckResult(run *Run, result APIEndpointResult) {
	run.APIEndpointResults = append(run.APIEndpointResults, result)
}

func sameAPIPath(left, right string) bool {
	a, errA := url.Parse(left)
	b, errB := url.Parse(right)
	return errA == nil && errB == nil && strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host) && a.EscapedPath() == b.EscapedPath()
}

func resolveAPICheckAddresses(ctx context.Context, host string) ([]net.IP, error) {
	if address := net.ParseIP(host); address != nil {
		return []net.IP{address}, nil
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(lookupCtx, host)
	if err != nil || len(addresses) == 0 {
		return nil, errors.New("host lookup failed")
	}
	result := make([]net.IP, 0, len(addresses))
	seen := map[string]bool{}
	for _, address := range addresses {
		key := address.IP.String()
		if !seen[key] {
			seen[key] = true
			result = append(result, address.IP)
		}
	}
	return result, nil
}

func apiCheckClientFor(parsed *url.URL, addresses []net.IP) *http.Client {
	host, port := parsed.Hostname(), parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: -1}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		requestHost, requestPort, err := net.SplitHostPort(address)
		if err != nil || !strings.EqualFold(requestHost, host) || requestPort != port {
			return nil, errors.New("request attempted to change the approved API origin")
		}
		var lastErr error
		for _, ip := range addresses {
			connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if dialErr == nil {
				return connection, nil
			}
			lastErr = dialErr
		}
		return nil, lastErr
	}
	return &http.Client{Timeout: 12 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func safeAPIError(err error) string {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err.Error()
	}
	return err.Error()
}

func newAPICheckFinding(req Request, endpoint APIEndpoint, rawURL, ruleID, title, severity, evidence, cwe string) Finding {
	source := strings.Join([]string{ruleID, endpoint.TargetID, endpoint.Method, endpoint.Path, endpoint.Origin}, "\x00")
	hash := sha256.Sum256([]byte(source))
	return Finding{SourceID: ruleID + ":" + hex.EncodeToString(hash[:8]), Scanner: "apichecks", RuleID: ruleID,
		Title: title, Severity: severity, Target: req.Target, Endpoint: rawURL, Method: endpoint.Method,
		Description: evidence, Evidence: evidence, Remediation: "Review the API security policy and verify the expected behavior with the application owner.",
		CWE: cwe, Confidence: "MEDIUM", EvidenceCompleteness: "response_headers_and_status"}
}

func parseAPIChecks(path string) ([]Finding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var findings []Finding
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		var finding Finding
		if err := json.Unmarshal(scanner.Bytes(), &finding); err != nil {
			continue
		}
		if finding.Scanner == "apichecks" && finding.SourceID != "" && finding.Endpoint != "" {
			findings = append(findings, finding)
		}
	}
	return findings, scanner.Err()
}

// Keep compile-time interface coverage close to this adapter.
var _ Runner = apiChecksRunner{}
