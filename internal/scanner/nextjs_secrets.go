package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// nextDataScript extracts the JSON payload Next.js serializes into the page.
var nextDataScript = regexp.MustCompile(`(?s)<script[^>]+id="__NEXT_DATA__"[^>]*>(.*?)</script>`)

// nextDataSecretKey matches an object key whose name indicates a secret value.
var nextDataSecretKey = regexp.MustCompile(`(?i)(password|passwd|secret|private[_-]?key|api[_-]?secret|access[_-]?token|refresh[_-]?token|client[_-]?secret|auth[_-]?token|session[_-]?secret|connection[_-]?string|db[_-]?pass)`)

// nextjsNextDataFindings inspects the serialized __NEXT_DATA__ payload for
// sensitive data that reached the client: keys named like secrets with real
// values, and leaked server runtime config. Values are never reported — only
// the key paths — so the evidence stays safe to store. This is structural
// detection the body regex scan does not provide.
func nextjsNextDataFindings(req Request, endpoint string, body []byte, evidenceRef string) []Finding {
	match := nextDataScript.FindSubmatch(body)
	if match == nil {
		return nil
	}
	var data any
	if err := json.Unmarshal(match[1], &data); err != nil {
		return nil
	}
	var secretPaths []string
	serverConfig := false
	var walk func(node any, path string, depth int)
	walk = func(node any, path string, depth int) {
		if depth > 12 || len(secretPaths) >= 20 {
			return
		}
		switch value := node.(type) {
		case map[string]any:
			for key, child := range value {
				childPath := key
				if path != "" {
					childPath = path + "." + key
				}
				if key == "serverRuntimeConfig" || key == "runtimeConfig" {
					if inner, ok := child.(map[string]any); ok && len(inner) > 0 {
						serverConfig = true
					}
				}
				if nextDataSecretKey.MatchString(key) && isNonEmptyScalar(child) {
					secretPaths = append(secretPaths, childPath)
				}
				walk(child, childPath, depth+1)
			}
		case []any:
			for i, child := range value {
				if i >= 50 {
					break
				}
				walk(child, path+"[]", depth+1)
			}
		}
	}
	walk(data, "", 0)

	safeEndpoint := SafeTelemetryURL(endpoint)
	var findings []Finding
	if len(secretPaths) > 0 {
		findings = append(findings, Finding{
			SourceID: nextjsSourceID("nextjs-next-data-secret", endpoint), Scanner: "nextjs-assets", RuleID: "nextjs-next-data-secret",
			Title: "Secret-named value serialized into __NEXT_DATA__", Severity: "high", Target: req.Target, Endpoint: safeEndpoint, Method: http.MethodGet,
			Description: "The page's serialized __NEXT_DATA__ (getServerSideProps/getStaticProps output and page props) contains keys named like secrets with non-empty values. Everything in __NEXT_DATA__ is delivered to the browser, so these values are exposed to anyone who views the page source.",
			Evidence:    fmt.Sprintf("Secret-named key path(s) in __NEXT_DATA__ at %s: %s; values were not retained.", safeEndpoint, strings.Join(dedupeStrings(secretPaths), ", ")),
			Remediation: "Do not return secrets from getServerSideProps/getStaticProps or include them in page props. Keep secrets server-side and expose only what the page must render.",
			CWE:         "CWE-200", Confidence: "confirmed", EvidenceRef: evidenceRef,
		})
	}
	if serverConfig {
		findings = append(findings, Finding{
			SourceID: nextjsSourceID("nextjs-server-runtime-config", endpoint), Scanner: "nextjs-assets", RuleID: "nextjs-server-runtime-config",
			Title: "Server runtime config present in client page data", Severity: "medium", Target: req.Target, Endpoint: safeEndpoint, Method: http.MethodGet,
			Description: "serverRuntimeConfig is intended to stay on the server, but a populated runtime-config object appears in the client page data. This can disclose values the application assumed were server-only.",
			Evidence:    fmt.Sprintf("A populated serverRuntimeConfig/runtimeConfig object was serialized into the page data at %s; values were not retained.", safeEndpoint),
			Remediation: "Access serverRuntimeConfig only in server code; never pass it into page props or client components.",
			CWE:         "CWE-200", Confidence: "confirmed", EvidenceRef: evidenceRef,
		})
	}
	return findings
}

// isNonEmptyScalar reports whether v is a non-empty string, a number, or a
// non-false boolean — i.e. a value that is actually present, not null or "".
func isNonEmptyScalar(v any) bool {
	switch value := v.(type) {
	case string:
		return strings.TrimSpace(value) != ""
	case float64:
		return true
	case bool:
		return value
	default:
		return false
	}
}

// Detection-only secret scanning of served client assets. Next.js compiles
// anything prefixed NEXT_PUBLIC_ into the browser bundle, and misconfigured
// builds leak provider keys, internal URLs and serialized server config. The
// bundle bodies are already fetched by nextjs-assets; these functions inspect
// them without any extra request. A finding never carries the secret value:
// the evidence names the provider and the public prefix only, so the findings
// artifact stays safe to store, download and report.

// nextjsSecretRule matches one provider credential whose format makes both the
// type and its secrecy unambiguous. The leading Prefix is a non-secret marker
// (e.g. "AKIA", "ghp_") shown in evidence; the random remainder is never shown.
type nextjsSecretRule struct {
	ID       string
	Provider string
	Severity string
	Prefix   string
	Pattern  *regexp.Regexp
}

// nextjsSecretRules are curated, high-confidence provider credentials. Publicly
// safe values are deliberately excluded: Stripe pk_/publishable keys, Firebase
// web apiKey (AIza... is designed to ship in the client), and bare JWTs.
var nextjsSecretRules = []nextjsSecretRule{
	{"aws-access-key", "AWS access key ID", "high", "AKIA", regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"gcp-api-key", "Google API key", "high", "AIza", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)},
	{"github-pat", "GitHub personal access token", "high", "ghp_", regexp.MustCompile(`\bghp_[0-9A-Za-z]{36}\b`)},
	{"github-fine-grained", "GitHub fine-grained token", "high", "github_pat_", regexp.MustCompile(`\bgithub_pat_[0-9A-Za-z_]{59,}\b`)},
	{"gitlab-pat", "GitLab personal access token", "high", "glpat-", regexp.MustCompile(`\bglpat-[0-9A-Za-z_\-]{20}\b`)},
	{"slack-token", "Slack token", "high", "xox", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,48}\b`)},
	{"stripe-secret", "Stripe secret key", "high", "sk_live_", regexp.MustCompile(`\bsk_live_[0-9A-Za-z]{24,}\b`)},
	{"stripe-restricted", "Stripe restricted key", "high", "rk_live_", regexp.MustCompile(`\brk_live_[0-9A-Za-z]{24,}\b`)},
	{"sendgrid", "SendGrid API key", "high", "SG.", regexp.MustCompile(`\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b`)},
	{"npm-token", "npm access token", "high", "npm_", regexp.MustCompile(`\bnpm_[0-9A-Za-z]{36}\b`)},
	{"openai", "OpenAI API key", "high", "sk-", regexp.MustCompile(`\bsk-(proj-)?[0-9A-Za-z_\-]{20,}T3BlbkFJ[0-9A-Za-z_\-]{20,}\b`)},
	{"twilio", "Twilio API key SID", "medium", "SK", regexp.MustCompile(`\bSK[0-9a-f]{32}\b`)},
	{"square", "Square access token", "high", "sq0atp-", regexp.MustCompile(`\bsq0atp-[0-9A-Za-z_\-]{22}\b`)},
	{"fcm-server-key", "Firebase Cloud Messaging server key", "high", "AAAA", regexp.MustCompile(`\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b`)},
	{"private-key-pem", "Private key (PEM)", "high", "-----BEGIN", regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)},
}

// nextPublicSecretName flags a NEXT_PUBLIC_ variable whose name claims it holds
// a secret. The NEXT_PUBLIC_ prefix means the value is compiled into the public
// bundle, so a secret-named one is a misuse of the prefix.
var nextPublicSecretName = regexp.MustCompile(`NEXT_PUBLIC_[A-Z0-9_]*(SECRET|PRIVATE|PASSWORD|PASSWD|_KEY|APIKEY|API_KEY|TOKEN|CREDENTIAL)[A-Z0-9_]*`)

// nextInternalHost matches a host that should not be reachable from a browser:
// RFC1918 ranges, loopback, and internal TLDs. Finding one in a public bundle
// discloses internal infrastructure.
var nextInternalHost = regexp.MustCompile(`\bhttps?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|localhost|[a-z0-9.\-]+\.(?:internal|local|svc|intranet|corp))(?::\d+)?`)

// nextjsBundleSecretFindings scans one served asset body for provider secrets,
// misused NEXT_PUBLIC_ secret variables, and internal URLs. Results carry the
// provider and a safe prefix, never the secret value. endpoint is already
// scope-checked by the caller.
func nextjsBundleSecretFindings(req Request, endpoint string, body []byte, evidenceRef string) []Finding {
	text := string(body)
	safeEndpoint := SafeTelemetryURL(endpoint)
	var findings []Finding
	seen := map[string]bool{}
	add := func(ruleID, title, severity, cwe, description, evidence, remediation string) {
		key := ruleID + "\x00" + endpoint
		if seen[key] {
			return
		}
		seen[key] = true
		findings = append(findings, Finding{
			SourceID: nextjsSourceID(ruleID, endpoint), Scanner: "nextjs-assets", RuleID: ruleID,
			Title: title, Severity: severity, Target: req.Target, Endpoint: safeEndpoint, Method: http.MethodGet,
			Description: description, Evidence: evidence, Remediation: remediation, CWE: cwe, Confidence: "confirmed", EvidenceRef: evidenceRef,
		})
	}
	for _, rule := range nextjsSecretRules {
		if rule.Pattern.MatchString(text) {
			count := len(rule.Pattern.FindAllStringIndex(text, 50))
			add("nextjs-bundle-secret-"+rule.ID, rule.Provider+" credential in a public client asset", rule.Severity, "CWE-798",
				fmt.Sprintf("A served client asset contains a value matching the %s format. Anything shipped to the browser is public, so a real key here is disclosed to every visitor. Ownership and validity were not tested.", rule.Provider),
				fmt.Sprintf("Matched %s format (prefix %q) %d time(s) in %s; the value was not retained.", rule.Provider, rule.Prefix, count, safeEndpoint),
				"Remove the secret from client code; use a server-only environment variable (no NEXT_PUBLIC_ prefix) reached through an API route or Server Component. Rotate the exposed credential.")
		}
	}
	if names := nextPublicSecretName.FindAllString(text, 20); len(names) > 0 {
		unique := dedupeStrings(names)
		add("nextjs-public-secret-var", "Secret-named NEXT_PUBLIC_ variable compiled into the client bundle", "medium", "CWE-200",
			"A NEXT_PUBLIC_ environment variable whose name indicates a secret is compiled into the browser bundle. The NEXT_PUBLIC_ prefix makes the value public, so a secret stored this way is exposed to every visitor.",
			fmt.Sprintf("Variable name(s) %s found in %s; the value was not retained.", strings.Join(unique, ", "), safeEndpoint),
			"Do not prefix secrets with NEXT_PUBLIC_. Move the value to a server-only variable used in an API route or Server Component, and rotate it if it was a real secret.")
	}
	if hosts := nextjsInternalHosts(text); len(hosts) > 0 {
		add("nextjs-internal-url", "Internal URL disclosed in a public client asset", "low", "CWE-200",
			"A served client asset references an internal or non-routable host. This discloses internal infrastructure (hostnames, ports, service names) to anyone who reads the bundle.",
			fmt.Sprintf("Referenced internal host(s): %s in %s.", strings.Join(hosts, ", "), safeEndpoint),
			"Route internal calls through a server-side API; do not embed internal hostnames or addresses in client code.")
	}
	return findings
}

// nextjsInternalHosts returns the distinct internal hosts referenced in text,
// capped and sorted for stable evidence.
func nextjsInternalHosts(text string) []string {
	matches := nextInternalHost.FindAllString(text, 50)
	hosts := map[string]bool{}
	var out []string
	for _, raw := range matches {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			if !hosts[u.Host] {
				hosts[u.Host] = true
				out = append(out, u.Host)
			}
		}
		if len(out) >= 10 {
			break
		}
	}
	sort.Strings(out)
	return out
}

func dedupeStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	if len(out) > 10 {
		out = out[:10]
	}
	return out
}
