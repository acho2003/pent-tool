package assessment

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// AppScope is the request boundary of one application: the approved
// scheme/host/port/path-prefix origins plus the exclusions that apply to them.
// It is the single origin/path matcher for the assessment; scanner-side scope
// fields are filled from it rather than re-implementing the comparison. It
// lives here (not in internal/scanner) because the scanner imports this
// package. The zero value authorizes nothing.
type AppScope struct {
	origins    []ApprovedOrigin
	exclusions []Exclusion
	excludeRe  []*regexp.Regexp
}

// NewAppScope builds a scope from origins and optional exclusions. Origins are
// normalized; an origin that cannot be normalized (bad scheme/host/port) is
// dropped so it never authorizes anything.
func NewAppScope(origins []ApprovedOrigin, exclusions ...Exclusion) AppScope {
	var s AppScope
	for _, o := range origins {
		if n, ok := normalizeOrigin(o); ok && validOrigin(n) == "" {
			s.origins = append(s.origins, n)
		}
	}
	s.origins = sortDedupeOrigins(s.origins)
	for _, e := range sortDedupeExclusions(normalizeExclusions(exclusions)) {
		s.exclusions = append(s.exclusions, e)
		s.excludeRe = append(s.excludeRe, regexp.MustCompile(e.PathRegex()))
	}
	return s
}

// AppScopeForTarget returns the scope of one target: its ApprovedOrigins, or,
// when the config approves none for it, a boundary derived from Target.Value
// so legacy configs still get one. Exclusions that are global or bound to the
// target are included. An unknown or non-web target yields an empty scope.
func AppScopeForTarget(cfg AssessmentConfig, targetID string) AppScope {
	targetID = strings.TrimSpace(targetID)
	var target *Target
	for i := range cfg.Targets {
		if strings.TrimSpace(cfg.Targets[i].ID) == targetID {
			target = &cfg.Targets[i]
			break
		}
	}
	if target == nil {
		return AppScope{}
	}
	var origins []ApprovedOrigin
	for _, o := range cfg.ApprovedOrigins {
		if strings.TrimSpace(o.TargetID) == targetID {
			origins = append(origins, o)
		}
	}
	if len(origins) == 0 {
		origins = derivedOrigins(*target)
	}
	var exclusions []Exclusion
	for _, e := range cfg.Exclusions {
		if id := strings.TrimSpace(e.TargetID); id == "" || id == targetID {
			exclusions = append(exclusions, e)
		}
	}
	return NewAppScope(origins, exclusions...)
}

// derivedOrigins is the legacy boundary of a target without approved origins:
// a URL target is its own origin and path; a domain/IP/host target is that
// host on the default HTTP and HTTPS ports only. Other kinds have no web
// origin.
func derivedOrigins(t Target) []ApprovedOrigin {
	value := strings.TrimSpace(t.Value)
	switch TargetKind(strings.ToUpper(strings.TrimSpace(string(t.Kind)))) {
	case KindURL:
		if o, err := ParseApprovedOrigin(t.ID, value); err == nil {
			return []ApprovedOrigin{o}
		}
	case KindDomain, KindIP, KindHost:
		host, port := value, 0
		if h, p, err := net.SplitHostPort(value); err == nil {
			n, err := strconv.Atoi(p)
			if err != nil {
				return nil
			}
			host, port = h, n
		}
		if host == "" || strings.ContainsAny(host, "/?#@ ") {
			return nil
		}
		return []ApprovedOrigin{
			{TargetID: t.ID, Scheme: "http", Host: host, Port: port, PathPrefix: "/"},
			{TargetID: t.ID, Scheme: "https", Host: host, Port: port, PathPrefix: "/"},
		}
	}
	return nil
}

// ParseApprovedOrigin parses an absolute http(s) URL ("https://host[:port][/path]")
// into a normalized ApprovedOrigin for targetID. Query and fragment are
// ignored; embedded credentials are rejected.
func ParseApprovedOrigin(targetID, raw string) (ApprovedOrigin, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !u.IsAbs() || u.Hostname() == "" || u.User != nil {
		return ApprovedOrigin{}, fmt.Errorf("origin must be an absolute http(s) URL without embedded credentials")
	}
	port := 0
	if p := u.Port(); p != "" {
		if port, err = strconv.Atoi(p); err != nil {
			return ApprovedOrigin{}, fmt.Errorf("origin has an invalid port")
		}
	}
	o, ok := normalizeOrigin(ApprovedOrigin{TargetID: targetID, Scheme: u.Scheme, Host: u.Hostname(), Port: port, PathPrefix: u.Path})
	if !ok {
		return ApprovedOrigin{}, fmt.Errorf("origin must use http or https")
	}
	if reason := validOrigin(o); reason != "" {
		return ApprovedOrigin{}, fmt.Errorf("%s", reason)
	}
	return o, nil
}

// Origin returns the RFC 6454 serialization "scheme://host[:port]", with the
// default port omitted and IPv6 hosts bracketed.
func (o ApprovedOrigin) Origin() string {
	host := o.Host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if o.Port != 0 && o.Port != defaultPort(o.Scheme) {
		host += ":" + strconv.Itoa(o.Port)
	}
	return o.Scheme + "://" + host
}

// String returns the origin followed by its path boundary.
func (o ApprovedOrigin) String() string {
	if o.PathPrefix == "" || o.PathPrefix == "/" {
		return o.Origin() + "/"
	}
	return o.Origin() + o.PathPrefix
}

// Origins returns a copy of the normalized, sorted approved origins.
func (s AppScope) Origins() []ApprovedOrigin {
	return append([]ApprovedOrigin(nil), s.origins...)
}

// Exclusions returns a copy of the normalized, sorted exclusions.
func (s AppScope) Exclusions() []Exclusion {
	return append([]Exclusion(nil), s.exclusions...)
}

// Allows reports whether rawURL is inside an approved origin: same scheme,
// host and port (default ports normalized, IPv6 compared bare) and a path at
// or below the origin's path prefix on a segment boundary, after dot segments
// are resolved. Query and fragment do not matter; embedded credentials are
// refused. The reason explains the decision.
func (s AppScope) Allows(rawURL string) (bool, string) {
	d, reason := parseDestination(rawURL)
	if reason != "" {
		return false, reason
	}
	if len(s.origins) == 0 {
		return false, "no approved origins"
	}
	sameOrigin := false
	for _, o := range s.origins {
		if o.Scheme != d.scheme || o.Host != d.host || o.Port != d.port {
			continue
		}
		sameOrigin = true
		if pathWithin(d.path, o.PathPrefix) {
			return true, "within approved origin " + o.String()
		}
	}
	origin := ApprovedOrigin{Scheme: d.scheme, Host: d.host, Port: d.port}.Origin()
	if sameOrigin {
		return false, fmt.Sprintf("path %q is outside the approved path boundary of %s", d.path, origin)
	}
	return false, fmt.Sprintf("%s is not an approved origin", origin)
}

// Excluded reports whether a request with method to rawURL matches an
// exclusion. An exclusion bound to a TargetID only applies when the URL falls
// inside one of that target's origins in this scope; one bound to an Origin
// only applies to that origin. A URL that cannot be parsed is reported as
// excluded (fail closed).
func (s AppScope) Excluded(method, rawURL string) (bool, string) {
	if len(s.exclusions) == 0 {
		return false, ""
	}
	d, reason := parseDestination(rawURL)
	if reason != "" {
		return true, "cannot check exclusions: " + reason
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	origin := ApprovedOrigin{Scheme: d.scheme, Host: d.host, Port: d.port}.Origin()
	for i, e := range s.exclusions {
		if e.Method != "" && e.Method != method {
			continue
		}
		if e.Origin != "" && e.Origin != origin {
			continue
		}
		if e.TargetID != "" && !s.targetOwns(e.TargetID, d) {
			continue
		}
		if !s.excludeRe[i].MatchString(d.path) {
			continue
		}
		why := e.Reason
		if why == "" {
			why = "matches exclusion " + e.PathPattern
		}
		return true, why
	}
	return false, ""
}

func (s AppScope) targetOwns(targetID string, d destination) bool {
	for _, o := range s.origins {
		if o.TargetID == targetID && o.Scheme == d.scheme && o.Host == d.host && o.Port == d.port && pathWithin(d.path, o.PathPrefix) {
			return true
		}
	}
	return false
}

// PathRegex returns the anchored, case-insensitive Go regular expression for
// PathPattern ("*" matches any run of characters; the pattern also matches
// everything below it). It is the single translation used by Excluded and by
// adapters that take path regexes.
func (e Exclusion) PathRegex() string {
	pattern := strings.TrimSuffix(cleanPath(e.PathPattern), "/")
	parts := strings.Split(pattern, "*")
	for i := range parts {
		parts[i] = regexp.QuoteMeta(parts[i])
	}
	return `(?i)^` + strings.Join(parts, `.*`) + `(?:/.*)?$`
}

type scopeJSON struct {
	Origins    []ApprovedOrigin `json:"origins,omitempty"`
	Exclusions []Exclusion      `json:"exclusions,omitempty"`
}

// MarshalJSON keeps a scope intact when a carrying struct is serialized.
func (s AppScope) MarshalJSON() ([]byte, error) {
	return json.Marshal(scopeJSON{Origins: s.origins, Exclusions: s.exclusions})
}

// UnmarshalJSON rebuilds a scope through NewAppScope so decoded input is
// normalized like any other.
func (s *AppScope) UnmarshalJSON(b []byte) error {
	var v scopeJSON
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*s = NewAppScope(v.Origins, v.Exclusions...)
	return nil
}

type destination struct {
	scheme, host string
	port         int
	path         string
}

// parseDestination normalizes an absolute http(s) URL to the components the
// scope compares. The path is decoded, backslashes are treated as separators
// and dot segments are resolved, so encoded traversal cannot escape a prefix.
func parseDestination(rawURL string) (destination, string) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || !u.IsAbs() || u.Hostname() == "" {
		return destination{}, "not an absolute http(s) URL"
	}
	if u.User != nil {
		return destination{}, "URL embeds credentials"
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return destination{}, fmt.Sprintf("scheme %q is not http or https", u.Scheme)
	}
	port := defaultPort(scheme)
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return destination{}, "URL has an invalid port"
		}
		port = n
	}
	return destination{scheme: scheme, host: canonicalHost(u.Hostname()), port: port, path: cleanPath(u.Path)}, ""
}

func defaultPort(scheme string) int {
	switch scheme {
	case "http":
		return 80
	case "https":
		return 443
	}
	return 0
}

// canonicalHost lower-cases a host, strips IPv6 brackets and a trailing root
// dot, and canonicalizes IP literals.
func canonicalHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	h = strings.TrimSuffix(h, ".")
	if addr, err := netip.ParseAddr(h); err == nil {
		return addr.String()
	}
	return h
}

// cleanPath resolves dot segments in a decoded path; the result is absolute
// and has no trailing slash except for the root.
func cleanPath(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return path.Clean(p)
}

func pathWithin(p, prefix string) bool {
	return prefix == "" || prefix == "/" || p == prefix || strings.HasPrefix(p, prefix+"/")
}

// normalizeOrigin canonicalizes an origin's fields. ok is false when the
// scheme is not http/https (the default port cannot be filled).
func normalizeOrigin(o ApprovedOrigin) (ApprovedOrigin, bool) {
	o.TargetID = strings.TrimSpace(o.TargetID)
	o.Scheme = strings.ToLower(strings.TrimSpace(o.Scheme))
	o.Host = canonicalHost(o.Host)
	prefix := strings.TrimSpace(o.PathPrefix)
	if prefix == "" || !strings.ContainsAny(prefix, "?#") {
		prefix = cleanPath(prefix)
	}
	o.PathPrefix = prefix
	if defaultPort(o.Scheme) == 0 {
		return o, false
	}
	if o.Port == 0 {
		o.Port = defaultPort(o.Scheme)
	}
	return o, true
}

// validOrigin returns why a normalized origin is unusable, or "".
func validOrigin(o ApprovedOrigin) string {
	if defaultPort(o.Scheme) == 0 {
		return fmt.Sprintf("origin scheme %q must be http or https", o.Scheme)
	}
	if o.Host == "" || strings.ContainsAny(o.Host, "/?#@ \t[]%") {
		return fmt.Sprintf("origin host %q must be a bare hostname or IP address", o.Host)
	}
	if strings.Contains(o.Host, ":") {
		if _, err := netip.ParseAddr(o.Host); err != nil {
			return fmt.Sprintf("origin host %q must not include a port", o.Host)
		}
	}
	if o.Port < 1 || o.Port > 65535 {
		return fmt.Sprintf("origin port %d is out of range", o.Port)
	}
	if !strings.HasPrefix(o.PathPrefix, "/") || strings.ContainsAny(o.PathPrefix, "?#") {
		return fmt.Sprintf("origin path_prefix %q must be an absolute path without query or fragment", o.PathPrefix)
	}
	return ""
}

func sortDedupeOrigins(in []ApprovedOrigin) []ApprovedOrigin {
	if len(in) == 0 {
		return nil
	}
	out := append([]ApprovedOrigin(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.TargetID != b.TargetID {
			return a.TargetID < b.TargetID
		}
		if a.Scheme != b.Scheme {
			return a.Scheme < b.Scheme
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.PathPrefix < b.PathPrefix
	})
	dedup := out[:1]
	for _, o := range out[1:] {
		if o != dedup[len(dedup)-1] {
			dedup = append(dedup, o)
		}
	}
	return dedup
}

// normalizeExclusion trims fields, upper-cases the method ("*" means any),
// canonicalizes a parseable Origin and resolves dot segments in the pattern.
func normalizeExclusion(e Exclusion) Exclusion {
	e.TargetID = strings.TrimSpace(e.TargetID)
	e.Method = strings.ToUpper(strings.TrimSpace(e.Method))
	if e.Method == "*" {
		e.Method = ""
	}
	e.Reason = strings.TrimSpace(e.Reason)
	e.Origin = strings.TrimSpace(e.Origin)
	if e.Origin != "" {
		if o, err := ParseApprovedOrigin("", e.Origin); err == nil && o.PathPrefix == "/" {
			e.Origin = o.Origin()
		}
	}
	e.PathPattern = strings.TrimSpace(e.PathPattern)
	if strings.HasPrefix(e.PathPattern, "/") && !strings.ContainsAny(e.PathPattern, "?#") {
		e.PathPattern = cleanPath(e.PathPattern)
	}
	return e
}

func normalizeExclusions(in []Exclusion) []Exclusion {
	var out []Exclusion
	for _, e := range in {
		out = append(out, normalizeExclusion(e))
	}
	return out
}

// sortDedupeExclusions orders exclusions deterministically and drops entries
// that repeat an earlier (TargetID, Origin, Method, PathPattern).
func sortDedupeExclusions(in []Exclusion) []Exclusion {
	if len(in) == 0 {
		return nil
	}
	out := append([]Exclusion(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.TargetID != b.TargetID {
			return a.TargetID < b.TargetID
		}
		if a.Origin != b.Origin {
			return a.Origin < b.Origin
		}
		if a.Method != b.Method {
			return a.Method < b.Method
		}
		if a.PathPattern != b.PathPattern {
			return a.PathPattern < b.PathPattern
		}
		return a.Reason < b.Reason
	})
	dedup := out[:1]
	for _, e := range out[1:] {
		last := dedup[len(dedup)-1]
		if e.TargetID == last.TargetID && e.Origin == last.Origin && e.Method == last.Method && e.PathPattern == last.PathPattern {
			continue
		}
		dedup = append(dedup, e)
	}
	return dedup
}
