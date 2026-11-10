package scanner

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/go-rod/rod/lib/proto"
)

// Detection-only runtime console-leak capture. During the authenticated browser
// crawl the driver already renders in-scope pages; this subscribes to the
// console output those pages emit and scans it for credentials, auth tokens and
// internal URLs. Nothing extra is navigated or submitted — it passively observes
// what the application itself chooses to log. A finding never carries the raw
// value: evidence names the provider, variable or host only.

// Per-page capture bounds so a noisy page cannot exhaust memory.
const (
	consoleMaxMessages     = 300
	consoleMaxBytesPerPage = 256 << 10
)

// consoleJWT matches a JSON Web Token (three base64url segments). A JWT logged
// to the console is very likely a session or access token.
var consoleJWT = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)

// consoleCollector accumulates console text for one page under its own lock, so
// the background event goroutine and the crawl loop can touch it safely.
type consoleCollector struct {
	mu    sync.Mutex
	parts []string
	bytes int
}

// handle is the go-rod event callback for Runtime.consoleAPICalled.
func (c *consoleCollector) handle(e *proto.RuntimeConsoleAPICalled) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.parts) >= consoleMaxMessages || c.bytes >= consoleMaxBytesPerPage {
		return
	}
	for _, arg := range e.Args {
		text := consoleArgText(arg)
		if text == "" {
			continue
		}
		if c.bytes+len(text) > consoleMaxBytesPerPage {
			text = text[:consoleMaxBytesPerPage-c.bytes]
		}
		c.parts = append(c.parts, text)
		c.bytes += len(text)
		if c.bytes >= consoleMaxBytesPerPage || len(c.parts) >= consoleMaxMessages {
			break
		}
	}
}

// joined returns a snapshot of the captured console text.
func (c *consoleCollector) joined() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.parts, "\n")
}

// consoleArgText renders one console argument to searchable text without the
// remote object protocol noise. Primitive values, the engine's string
// description, and object preview properties are all included.
func consoleArgText(arg *proto.RuntimeRemoteObject) string {
	if arg == nil {
		return ""
	}
	var parts []string
	if !arg.Value.Nil() {
		if s := arg.Value.Str(); s != "" {
			parts = append(parts, s)
		} else if raw := arg.Value.String(); raw != "" && raw != "null" {
			parts = append(parts, raw)
		}
	}
	if arg.Description != "" {
		parts = append(parts, arg.Description)
	}
	if arg.UnserializableValue != "" {
		parts = append(parts, string(arg.UnserializableValue))
	}
	if arg.Preview != nil {
		for _, p := range arg.Preview.Properties {
			if p != nil && p.Value != "" {
				parts = append(parts, p.Name+"="+p.Value)
			}
		}
	}
	return strings.Join(parts, " ")
}

// browserConsoleLeakFindings scans captured console text for leaked secrets,
// auth tokens and internal URLs. pageURL is the in-scope page already allowed by
// the crawl policy. Findings use Scanner "browser" and are whitelisted by
// parseBrowserAssetFindings.
func browserConsoleLeakFindings(req Request, pageURL, text, evidenceRef string) []Finding {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	safe := SafeTelemetryURL(pageURL)
	var findings []Finding
	seen := map[string]bool{}
	add := func(ruleID, title, severity, cwe, description, evidence, remediation string) {
		if seen[ruleID] {
			return
		}
		seen[ruleID] = true
		findings = append(findings, Finding{
			SourceID: nextjsSourceID(ruleID, pageURL), Scanner: "browser", RuleID: ruleID,
			Title: title, Severity: severity, Target: req.Target, Endpoint: safe, Method: http.MethodGet,
			Description: description, Evidence: evidence, Remediation: remediation, CWE: cwe, Confidence: "confirmed", EvidenceRef: evidenceRef,
		})
	}
	for _, rule := range nextjsSecretRules {
		if rule.Pattern.MatchString(text) {
			add("browser-console-credential-"+rule.ID, rule.Provider+" credential logged to the browser console", rule.Severity, "CWE-532",
				fmt.Sprintf("The page logged a value matching the %s credential format to the browser console at runtime. Console output is visible to anyone with the page open and is commonly captured by client-side error or telemetry tooling. Ownership and validity were not tested.", rule.Provider),
				fmt.Sprintf("Matched %s format (prefix %q) in console output on %s; the value was not retained.", rule.Provider, rule.Prefix, safe),
				"Remove debug logging of secrets. Never log credentials, tokens or authentication responses to the console; strip such logging from production builds and rotate any exposed credential.")
		}
	}
	if consoleJWT.MatchString(text) {
		add("browser-console-auth-token", "Authentication token logged to the browser console", "medium", "CWE-532",
			"A JSON Web Token (JWT) was logged to the browser console at runtime. If it is a session or access token, anyone able to read the console — or client-side telemetry that captures console output — can reuse it.",
			fmt.Sprintf("A JWT-shaped token was logged to the console on %s; the token was not retained.", safe),
			"Do not log authentication tokens. Remove token logging from production builds and treat any exposed session token as compromised.")
	}
	if names := nextPublicSecretName.FindAllString(text, 20); len(names) > 0 {
		add("browser-console-public-secret-var", "Secret-named NEXT_PUBLIC_ variable logged to the browser console", "medium", "CWE-200",
			"A NEXT_PUBLIC_ variable whose name indicates a secret was logged to the console. The NEXT_PUBLIC_ prefix already makes the value public, and logging it compounds the exposure.",
			fmt.Sprintf("Secret-named NEXT_PUBLIC_ variable(s) %s logged to the console on %s; the value was not retained.", strings.Join(dedupeStrings(names), ", "), safe),
			"Do not store secrets in NEXT_PUBLIC_ variables and do not log them; move secrets server-side and rotate if real.")
	}
	if hosts := nextjsInternalHosts(text); len(hosts) > 0 {
		add("browser-console-internal-url", "Internal URL logged to the browser console", "low", "CWE-200",
			"The page logged an internal or non-routable host to the browser console, disclosing internal infrastructure to anyone viewing the console.",
			fmt.Sprintf("Internal host(s) logged to the console on %s: %s.", safe, strings.Join(hosts, ", ")),
			"Do not log internal URLs or service addresses from client code.")
	}
	return findings
}
