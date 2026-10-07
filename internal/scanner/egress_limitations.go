package scanner

// directEgressReasons describes adapters that run without the recording
// gateway in an expanded assessment. Their scope is enforced only by tool flags
// or by checks made before the tool starts, so a completed run must not be read
// as proof that all of its traffic stayed inside the approved boundary. Adapters
// that do route through the gateway (nuclei, wapiti, dalfox, ZAP) or that
// validate each request natively (apichecks, the Go browser) are not listed.
var directEgressReasons = map[string]string{
	"katana":  "katana is not routed through the recording gateway: only its URL regexes constrain the pages it queues, so requests made by its headless browser itself (for example the origin-root favicon) are not bounded by the approved path prefix, and its traffic is not recorded as coverage events",
	"testssl": "testssl.sh is not routed through the recording gateway: its traffic is not recorded as coverage events or counted against the request budget; it is refused when the approved boundary is below the origin root or excludes it",
	"nikto":   "nikto is not routed through the recording gateway: it requests its own fixed test paths at the origin root, so it is refused for a path-bounded target or when exclusions exist, and its traffic is not recorded as coverage events or counted against the request budget",
	"nmap":    "nmap is not routed through the recording gateway: its probes are rate-capped and limited to networks of at most 256 addresses and the scope guard judges the address it resolves to, but its traffic is not recorded as coverage events",
	"openvas": "OpenVAS network tests run in Greenbone and ignore the web path prefix, request methods and exclusions",
}

// withDirectEgressLimitation records that scanner's scope is not
// gateway-enforced. It is a no-op for adapters with their own enforcement and
// never adds a duplicate.
func withDirectEgressLimitation(limitations []RunLimitation, scanner string) []RunLimitation {
	reason, ok := directEgressReasons[scanner]
	if !ok {
		return limitations
	}
	for _, existing := range limitations {
		if existing.Kind == LimitationScopeNotGatewayEnforced {
			return limitations
		}
	}
	return append(limitations, RunLimitation{Kind: LimitationScopeNotGatewayEnforced, Reason: reason})
}
