package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Passive HTTP security-header check. It is detection only: one read-only GET
// on the approved target root, then inspection of the response headers. No
// payloads, no state change. Findings map to the existing missing_security_header
// class, so ZAP/Nikto results dedupe with these by host.
const securityHeadersCatalogVersion = "security-headers-v1"

// hstsMinMaxAge is six months in seconds; a shorter HSTS lifetime is weak.
const hstsMinMaxAge = 15552000

type securityHeadersRunner struct{}

func (securityHeadersRunner) Name() string { return "security-headers" }
func (securityHeadersRunner) Descriptor() Descriptor {
	return Descriptor{Name: "security-headers", Summary: "Passive check for missing or weak HTTP security response headers", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightLight}
}

func (securityHeadersRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	run := Run{Scanner: "security-headers", Target: req.Target, Scope: req.Scope, Status: "running", StartedAt: now, Variant: securityHeadersCatalogVersion}
	finish := func(status, reason string) Run {
		run.Status, run.Reason, run.FinishedAt = status, reason, time.Now().UTC().Format(time.RFC3339Nano)
		return finalizeRun(run)
	}
	if !req.TypedAssessment || req.AppScope == nil {
		return finish("failed", "security-header checks require a typed URL assessment scope")
	}
	base, err := url.Parse(strings.TrimSpace(req.Target))
	if err != nil || base.Host == "" || base.User != nil || (base.Scheme != "http" && base.Scheme != "https") {
		return finish("failed", "target must be an absolute HTTP(S) URL without credentials")
	}
	raw := base.String()
	if ok, reason := req.AppScope.Allows(raw); !ok {
		return finish("not_applicable", "target root is outside the approved scope: "+reason)
	}
	if excluded, _ := req.AppScope.Excluded(http.MethodGet, raw); excluded {
		return finish("not_applicable", "target root is excluded")
	}
	if emit != nil {
		emit(Event{Type: "scanner_started", Scanner: run.Scanner, Run: run})
	}
	dir := filepath.Join(req.ScanDir, "scanner-output", "security-headers")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return finish("failed", "create artifact directory: "+err.Error())
	}
	artifact := filepath.Join(dir, "findings.jsonl")
	file, err := os.OpenFile(artifact, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return finish("failed", "create artifact: "+err.Error())
	}
	defer file.Close()
	run.ArtifactPath = artifact

	if cfg.Budget != nil {
		if err := cfg.Budget.Wait(ctx); err != nil {
			return finish("failed", "assessment request budget exhausted before the security-header check")
		}
	}
	client, err := guardedOriginClient(ctx, cfg, raw)
	if err != nil {
		return finish("failed", "request refused by scope guard: "+probeRequestError(err))
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	resp, err := client.Do(request)
	if err != nil {
		return finish("failed", "target request failed: "+probeRequestError(err))
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()

	encoder := json.NewEncoder(file)
	findings := securityHeaderFindings(req, raw, base.Scheme == "https", resp.Header)
	for _, finding := range findings {
		if err := encoder.Encode(finding); err != nil {
			return finish("failed", "write finding: "+err.Error())
		}
	}
	if err := file.Sync(); err != nil {
		return finish("failed", "sync artifact: "+err.Error())
	}
	run.ExecutionOutcome, run.ParserOutcome, run.Completeness = "SUCCESS", "SUCCESS", "complete"
	run.Outcome = "SUCCESS_NO_FINDINGS"
	if len(findings) > 0 {
		run.Outcome = "SUCCESS_WITH_FINDINGS"
	}
	return finish("completed", fmt.Sprintf("checked security response headers; %d issue(s) reported", len(findings)))
}

// securityHeaderFindings inspects response headers and returns one finding per
// missing or weak control. Evidence carries only header names and shapes, never
// cookie or token values.
func securityHeaderFindings(req Request, endpoint string, https bool, header http.Header) []Finding {
	safe := SafeTelemetryURL(endpoint)
	var findings []Finding
	add := func(ruleID, title, severity, cwe, description, evidence, remediation string) {
		findings = append(findings, Finding{
			SourceID: nextjsSourceID(ruleID, endpoint), Scanner: "security-headers", RuleID: ruleID,
			Title: title, Severity: severity, Target: req.Target, Endpoint: safe, Method: http.MethodGet,
			Description: description, Evidence: evidence, Remediation: remediation, CWE: cwe, Confidence: "confirmed",
		})
	}
	csp := strings.TrimSpace(header.Get("Content-Security-Policy"))
	lowerCSP := strings.ToLower(csp)

	if https {
		hsts := strings.ToLower(strings.TrimSpace(header.Get("Strict-Transport-Security")))
		switch {
		case hsts == "":
			add("security-header-hsts-missing", "Missing Strict-Transport-Security (HSTS) header", "medium", "CWE-319",
				"The HTTPS response does not set Strict-Transport-Security. Without HSTS a browser can be downgraded to HTTP, enabling interception on the first or a stripped connection.",
				"Response header Strict-Transport-Security is absent.",
				"Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' (add preload once verified).")
		case hstsMaxAge(hsts) < hstsMinMaxAge:
			add("security-header-hsts-weak", "Weak Strict-Transport-Security max-age", "low", "CWE-319",
				"The HSTS max-age is shorter than six months, which narrows the window the policy protects.",
				fmt.Sprintf("Strict-Transport-Security max-age is %d seconds (below %d).", hstsMaxAge(hsts), hstsMinMaxAge),
				"Set max-age to at least 31536000 (one year) and include includeSubDomains.")
		}
	}

	if csp == "" {
		add("security-header-csp-missing", "Missing Content-Security-Policy header", "medium", "CWE-1021",
			"The response sets no Content-Security-Policy. A CSP is the main defence that limits where scripts, styles and frames may load from, reducing the impact of cross-site scripting and clickjacking.",
			"Response header Content-Security-Policy is absent.",
			"Define a Content-Security-Policy that restricts script-src and frame-ancestors; start in report-only mode and tighten it.")
	} else if weak := weakCSPReasons(lowerCSP); len(weak) > 0 {
		add("security-header-csp-weak", "Weak Content-Security-Policy", "low", "CWE-1021",
			"A Content-Security-Policy is present but contains directives that substantially weaken it, so it provides limited protection.",
			"Content-Security-Policy weaknesses: "+strings.Join(weak, ", ")+".",
			"Remove 'unsafe-inline'/'unsafe-eval', avoid '*' sources, and set a restrictive default-src and frame-ancestors.")
	}

	frameOptions := strings.ToLower(strings.TrimSpace(header.Get("X-Frame-Options")))
	frameAncestors := strings.Contains(lowerCSP, "frame-ancestors")
	if frameOptions == "" && !frameAncestors {
		add("security-header-clickjacking", "No clickjacking protection (X-Frame-Options / frame-ancestors)", "medium", "CWE-1021",
			"Neither X-Frame-Options nor a CSP frame-ancestors directive is set, so the page can be framed by any site and is exposed to clickjacking.",
			"Neither X-Frame-Options nor Content-Security-Policy frame-ancestors is present.",
			"Set 'X-Frame-Options: DENY' (or SAMEORIGIN) and a CSP 'frame-ancestors' directive.")
	}

	if !strings.EqualFold(strings.TrimSpace(header.Get("X-Content-Type-Options")), "nosniff") {
		add("security-header-nosniff", "Missing X-Content-Type-Options: nosniff", "low", "CWE-16",
			"X-Content-Type-Options is not set to nosniff, so a browser may MIME-sniff responses and interpret them as an unintended, potentially executable type.",
			"Response header X-Content-Type-Options is absent or not 'nosniff'.",
			"Set 'X-Content-Type-Options: nosniff' on all responses.")
	}

	if strings.TrimSpace(header.Get("Referrer-Policy")) == "" {
		add("security-header-referrer-policy", "Missing Referrer-Policy header", "low", "CWE-200",
			"No Referrer-Policy is set, so full URLs (which may contain tokens or identifiers) can be sent to third-party sites in the Referer header.",
			"Response header Referrer-Policy is absent.",
			"Set a restrictive Referrer-Policy such as 'strict-origin-when-cross-origin' or 'no-referrer'.")
	}

	for _, disclosure := range softwareVersionDisclosures(header) {
		add("security-header-version-disclosure-"+disclosure.id, "Software version disclosed in "+disclosure.name+" header", "info", "CWE-200",
			"The response discloses a specific software name and version in a header. Version banners help an attacker match known vulnerabilities to the stack.",
			fmt.Sprintf("Header %s advertises a version string.", disclosure.name),
			"Remove or generalise version banners in the "+disclosure.name+" header.")
	}
	return findings
}

func hstsMaxAge(value string) int {
	for _, part := range strings.Split(value, ";") {
		part = strings.TrimSpace(part)
		if after, ok := strings.CutPrefix(part, "max-age="); ok {
			if n, err := strconv.Atoi(strings.TrimSpace(after)); err == nil {
				return n
			}
		}
	}
	return -1
}

func weakCSPReasons(lowerCSP string) []string {
	var reasons []string
	if strings.Contains(lowerCSP, "unsafe-inline") {
		reasons = append(reasons, "'unsafe-inline' allows inline scripts/styles")
	}
	if strings.Contains(lowerCSP, "unsafe-eval") {
		reasons = append(reasons, "'unsafe-eval' allows eval()")
	}
	// A bare '*' as a source (not part of a scheme or host wildcard like *.cdn)
	for _, token := range strings.Fields(lowerCSP) {
		token = strings.TrimRight(token, ";")
		if token == "*" {
			reasons = append(reasons, "'*' wildcard source")
			break
		}
	}
	if strings.Contains(lowerCSP, "default-src *") || strings.Contains(lowerCSP, "script-src *") {
		reasons = append(reasons, "wildcard default-src/script-src")
	}
	return dedupeStrings(reasons)
}

type versionDisclosure struct{ id, name string }

// softwareVersionDisclosures returns headers whose value contains a version
// number, which discloses the running software version.
func softwareVersionDisclosures(header http.Header) []versionDisclosure {
	var out []versionDisclosure
	check := func(id, name string) {
		value := strings.TrimSpace(header.Get(name))
		if value != "" && headerHasVersion(value) {
			out = append(out, versionDisclosure{id, name})
		}
	}
	check("server", "Server")
	check("x-powered-by", "X-Powered-By")
	check("x-aspnet-version", "X-AspNet-Version")
	check("x-aspnetmvc-version", "X-AspNetMvc-Version")
	return out
}

// headerHasVersion reports whether a header value carries a dotted version
// number (e.g. "nginx/1.25.3", "PHP/8.2.1"), which is the disclosure.
func headerHasVersion(value string) bool {
	for i := 0; i+2 < len(value); i++ {
		if value[i] >= '0' && value[i] <= '9' {
			if j := strings.IndexByte(value[i:], '.'); j > 0 && i+j+1 < len(value) {
				next := value[i+j+1]
				if next >= '0' && next <= '9' {
					return true
				}
			}
		}
	}
	return false
}

func parseSecurityHeaders(path string) ([]Finding, error) {
	return parseExposureFindings(path)
}

var _ Runner = securityHeadersRunner{}
