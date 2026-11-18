package scanner

import (
	"bytes"
	"context"
	"crypto/hmac"
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
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

// Optional third-party intelligence lookups ("how the internet sees the
// target"). They never send a request to the target: each asks an external
// service about the target's public IP address, domain or locked npm
// dependencies. Every provider is opt-in, and a provider that needs an API key
// is unavailable until that key is set in the environment (Settings).
//
// The target identifier (IP, domain or package name@version) is disclosed to
// the provider. Results are observations reported by that provider; they are
// not verified against the target.
const intelCatalogVersion = "intel-v1"

// GroupIntel is the New-Assessment / Integrations group of these lookups.
const GroupIntel = "threat_intel"

type intelKind int

const (
	intelIP     intelKind = iota // subject: each public IP the target resolves to
	intelDomain                  // subject: the target hostname
	intelDeps                    // subject: the checked-out source directory
)

const (
	intelMaxIPs      = 4
	intelMaxBody     = 8 << 20
	intelMaxFindings = 100
)

// intelBase holds provider API roots; tests point them at a local server.
var intelBase = map[string]string{
	"shodan":       "https://api.shodan.io",
	"censys":       "https://api.platform.censys.io",
	"shadowserver": "https://transform.shadowserver.org/api2",
	"greynoise":    "https://api.greynoise.io",
	"abuseipdb":    "https://api.abuseipdb.com",
	"crtsh":        "https://crt.sh",
	"hibp":         "https://haveibeenpwned.com",
	"github":       "https://api.github.com",
	"dehashed":     "https://api.dehashed.com",
	"cloudflare":   "https://api.cloudflare.com",
	"socket":       "https://api.socket.dev",
	"depsdev":      "https://api.deps.dev",
}

type intelHit struct {
	rule, key, title, severity string
	description, evidence, fix string
	cve, port, pkg, pkgVersion string
	unrated                    bool
}

type intelProvider struct {
	id, name, summary string
	env               []string // every key must be set; empty means no key is needed
	kind              intelKind
	lookup            func(ctx context.Context, c intelClient, subject string) ([]intelHit, error)
}

var intelProviders = []intelProvider{
	{id: "intel-shodan", name: "Shodan", env: []string{"SHODAN_API_KEY"}, kind: intelIP, lookup: shodanLookup,
		summary: "Internet-visible ports, service banners and banner-matched CVEs Shodan has recorded for the target IP"},
	{id: "intel-censys", name: "Censys", env: []string{"CENSYS_API_TOKEN"}, kind: intelIP, lookup: censysLookup,
		summary: "Internet-visible services Censys has recorded for the target IP"},
	{id: "intel-shadowserver", name: "Shadowserver", env: []string{"SHADOWSERVER_API_KEY", "SHADOWSERVER_API_SECRET"}, kind: intelIP, lookup: shadowserverLookup,
		summary: "Shadowserver report events (exposed services, infections, abuse) for the target IP"},
	{id: "intel-greynoise", name: "GreyNoise", env: []string{"GREYNOISE_API_KEY"}, kind: intelIP, lookup: greynoiseLookup,
		summary: "Whether the target IP has been seen scanning or attacking the internet (possible compromise)"},
	{id: "intel-abuseipdb", name: "AbuseIPDB", env: []string{"ABUSEIPDB_API_KEY"}, kind: intelIP, lookup: abuseipdbLookup,
		summary: "Abuse reports filed against the target IP"},
	{id: "intel-crtsh", name: "Certificate transparency (crt.sh)", kind: intelDomain, lookup: crtshLookup,
		summary: "Hostnames under the target domain that appear in public certificate logs (candidates only, never added to scope)"},
	{id: "intel-hibp", name: "Have I Been Pwned", env: []string{"HIBP_API_KEY"}, kind: intelDomain, lookup: hibpLookup,
		summary: "Accounts on the target's verified domain that appear in known data breaches"},
	{id: "intel-github-leaks", name: "GitHub code search", env: []string{"GITHUB_TOKEN"}, kind: intelDomain, lookup: githubLeaksLookup,
		summary: "Public GitHub code that mentions the target domain next to credential keywords"},
	{id: "intel-dehashed", name: "DeHashed", env: []string{"DEHASHED_API_KEY"}, kind: intelDomain, lookup: dehashedLookup,
		summary: "Count of leaked credential records for the target domain (each lookup spends a DeHashed credit)"},
	{id: "intel-cloudflare", name: "Cloudflare zone audit", env: []string{"CLOUDFLARE_API_TOKEN"}, kind: intelDomain, lookup: cloudflareLookup,
		summary: "Read-only audit of the domain's Cloudflare TLS settings and DNS records that expose the origin"},
	{id: "intel-socket", name: "Socket.dev", env: []string{"SOCKET_API_TOKEN"}, kind: intelDeps, lookup: socketLookup,
		summary: "Malicious, typosquatted or risky npm packages among the locked dependencies"},
	{id: "intel-depsdev", name: "deps.dev / OpenSSF Scorecard", kind: intelDeps, lookup: depsdevLookup,
		summary: "Deprecated or poorly maintained direct npm dependencies"},
}

func intelProviderByID(id string) (intelProvider, bool) {
	for _, p := range intelProviders {
		if p.id == id {
			return p, true
		}
	}
	return intelProvider{}, false
}

func (p intelProvider) missingEnv() []string {
	var missing []string
	for _, key := range p.env {
		if strings.TrimSpace(os.Getenv(key)) == "" {
			missing = append(missing, key)
		}
	}
	return missing
}

func intelIDs() []string {
	ids := make([]string, 0, len(intelProviders))
	for _, p := range intelProviders {
		ids = append(ids, p.id)
	}
	return ids
}

// IsIntelScanner reports whether id is a third-party intelligence lookup.
func IsIntelScanner(id string) bool {
	_, ok := intelProviderByID(id)
	return ok
}

// IntelAvailability reports, per lookup, whether its API key is configured.
func IntelAvailability() map[string]bool {
	out := make(map[string]bool, len(intelProviders))
	for _, p := range intelProviders {
		out[p.id] = len(p.missingEnv()) == 0
	}
	return out
}

// IntelUnavailableReason names the missing key(s) of an unavailable lookup.
func IntelUnavailableReason(id string) string {
	p, ok := intelProviderByID(id)
	if !ok {
		return ""
	}
	if missing := p.missingEnv(); len(missing) > 0 {
		return "set " + strings.Join(missing, " and ") + " in Settings to enable " + p.name
	}
	return ""
}

// IntelKey describes one API-key environment variable for the Settings view.
type IntelKey struct{ Key, Label, Description string }

// IntelKeys lists the environment variables the lookups (and the passive
// discovery providers that accept the same keys) read.
func IntelKeys() []IntelKey {
	var out []IntelKey
	for _, p := range intelProviders {
		for _, key := range p.env {
			out = append(out, IntelKey{Key: key, Label: p.name + " key", Description: "Enables the optional " + p.name + " lookup: " + p.summary + "."})
		}
	}
	return append(out,
		IntelKey{"CENSYS_ORG_ID", "Censys organization ID", "Optional. Sent with Censys lookups; required by paid Censys organizations."},
		IntelKey{"SECURITYTRAILS_API_KEY", "SecurityTrails key", "Optional extra passive source for Subfinder subdomain discovery."},
		IntelKey{"CHAOS_API_KEY", "ProjectDiscovery Chaos key", "Optional extra passive source for Subfinder subdomain discovery."},
		IntelKey{"VIRUSTOTAL_API_KEY", "VirusTotal key", "Optional extra passive source for Subfinder and for waybackurls historical URLs."},
	)
}

func intelDefinitions() []ScannerDefinition {
	defs := make([]ScannerDefinition, 0, len(intelProviders))
	for _, p := range intelProviders {
		def := ScannerDefinition{ID: p.id, Name: p.name, Category: PhaseRecon, Group: GroupIntel, DefaultSelection: "optional", Risk: "low",
			Available: len(p.missingEnv()) == 0, AvailabilityReason: IntelUnavailableReason(p.id),
			Summary: p.summary + ". Third-party lookup: the target identifier is sent to " + p.name + "; no request reaches the target"}
		switch p.kind {
		case intelIP:
			def.AssessmentTypes = []assessment.Type{assessment.TypeNetwork, assessment.TypeWebApplication, assessment.TypeAPI}
			def.TargetKinds = []assessment.TargetKind{assessment.KindIP, assessment.KindDomain, assessment.KindHost, assessment.KindURL}
		case intelDomain:
			def.AssessmentTypes = []assessment.Type{assessment.TypeNetwork, assessment.TypeWebApplication, assessment.TypeAPI}
			def.TargetKinds = []assessment.TargetKind{assessment.KindDomain, assessment.KindURL}
		case intelDeps:
			def.Category = PhaseSAST
			def.AssessmentTypes = []assessment.Type{assessment.TypeSourceCode, assessment.TypeDependencies}
			def.TargetKinds = []assessment.TargetKind{assessment.KindRepository, assessment.KindLocalSourcePath}
			def.RequiredCapabilities = []assessment.Capability{assessment.CapSource}
		}
		defs = append(defs, def)
	}
	return defs
}

type intelRunner struct{ p intelProvider }

func (r intelRunner) Name() string { return r.p.id }
func (r intelRunner) Descriptor() Descriptor {
	return Descriptor{Name: r.p.id, Summary: r.p.summary, Phase: PhaseRecon, Tracks: []Track{TrackWeb}, Weight: WeightLight}
}

func (r intelRunner) Run(ctx context.Context, req Request, _ Config, emit EmitFunc) Run {
	p := r.p
	run := Run{Scanner: p.id, Target: req.Target, Scope: req.Scope, Status: "running", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Variant: intelCatalogVersion}
	finish := func(status, reason string) Run {
		run.Status, run.Reason, run.FinishedAt = status, reason, time.Now().UTC().Format(time.RFC3339Nano)
		return finalizeRun(run)
	}
	if reason := IntelUnavailableReason(p.id); reason != "" {
		run.GapKind = GapToolUnavailable
		return finish("not_applicable", reason)
	}
	subjects, reason := intelSubjects(ctx, p.kind, req.Target)
	if reason != "" {
		return finish("not_applicable", reason)
	}
	if emit != nil {
		emit(Event{Type: "scanner_started", Scanner: run.Scanner, Run: run})
	}
	dir := filepath.Join(req.ScanDir, "scanner-output", p.id)
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

	client := intelClient{http: &http.Client{Timeout: 30 * time.Second}}
	encoder := json.NewEncoder(file)
	count := 0
	var failures []string
	for _, subject := range subjects {
		hits, err := p.lookup(ctx, client, subject)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		shown := subject
		if p.kind == intelDeps {
			shown = "package-lock.json"
		}
		for _, hit := range hits {
			if count == intelMaxFindings {
				run.Limitations = append(run.Limitations, RunLimitation{Kind: "intel_result_cap", Reason: fmt.Sprintf("only the first %d %s results were kept", intelMaxFindings, p.name)})
				break
			}
			finding := Finding{
				SourceID: nextjsSourceID(hit.rule, subject+"\x00"+hit.key), Scanner: p.id, RuleID: hit.rule,
				Title: hit.title, Severity: hit.severity, SeverityUnrated: hit.unrated, Target: req.Target, Resource: shown,
				Port: hit.port, Package: hit.pkg, PackageVersion: hit.pkgVersion, CVE: hit.cve,
				Description: hit.description, Evidence: hit.evidence, Remediation: hit.fix, Confidence: "firm",
			}
			if err := encoder.Encode(finding); err != nil {
				return finish("failed", "write finding: "+err.Error())
			}
			count++
		}
	}
	if err := file.Sync(); err != nil {
		return finish("failed", "sync artifact: "+err.Error())
	}
	if len(failures) == len(subjects) {
		run.ExecutionOutcome = "FAILED"
		return finish("failed", p.name+" lookup failed: "+failures[0])
	}
	run.ExecutionOutcome, run.ParserOutcome, run.Completeness = "SUCCESS", "SUCCESS", "complete"
	if len(failures) > 0 {
		run.Completeness = "partial"
		run.Limitations = append(run.Limitations, RunLimitation{Kind: "intel_partial", Reason: fmt.Sprintf("%d of %d %s lookups failed: %s", len(failures), len(subjects), p.name, failures[0])})
	}
	run.Outcome = "SUCCESS_NO_FINDINGS"
	if count > 0 {
		run.Outcome = "SUCCESS_WITH_FINDINGS"
	}
	return finish("completed", fmt.Sprintf("%s lookup of %d subject(s); %d result(s) reported", p.name, len(subjects), count))
}

var _ Runner = intelRunner{}

// intelHost reduces a URL, host:port, domain or IP target to its bare host.
func intelHost(target string) string {
	target = strings.TrimSpace(target)
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil {
			target = u.Hostname()
		}
	} else if host, _, err := net.SplitHostPort(target); err == nil {
		target = host
	}
	return strings.TrimSuffix(strings.ToLower(strings.Trim(target, "[]")), ".")
}

// intelApex returns the registrable domain of host (example.co.uk), or host
// itself when it has no known public suffix.
func intelApex(host string) string {
	if apex, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return apex
	}
	return host
}

var intelResolve = func(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

func intelPublicIP(ip net.IP) bool {
	return ip != nil && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsUnspecified() && !ip.IsMulticast()
}

// intelSubjects returns what a provider is asked about, or why it does not apply.
func intelSubjects(ctx context.Context, kind intelKind, target string) ([]string, string) {
	if kind == intelDeps {
		if _, err := intelNpmDeps(target, 1); err != nil {
			return nil, err.Error()
		}
		return []string{target}, ""
	}
	host := intelHost(target)
	if host == "" {
		return nil, "target has no host name or IP address"
	}
	ip := net.ParseIP(host)
	if kind == intelDomain {
		if ip != nil || !strings.Contains(host, ".") {
			return nil, "this lookup requires a public domain name"
		}
		return []string{host}, ""
	}
	if ip != nil {
		if !intelPublicIP(ip) {
			return nil, "target is not a public IP address; external services hold no data about it"
		}
		return []string{ip.String()}, ""
	}
	addrs, err := intelResolve(ctx, host)
	if err != nil {
		return nil, "target host could not be resolved to an IP address"
	}
	var out []string
	for _, addr := range addrs {
		if intelPublicIP(addr.IP) && len(out) < intelMaxIPs {
			out = append(out, addr.IP.String())
		}
	}
	out = dedupeStrings(out)
	if len(out) == 0 {
		return nil, "target resolves only to private addresses; external services hold no data about it"
	}
	return out, ""
}

type intelClient struct{ http *http.Client }

// raw performs one request. Errors never contain the request URL or headers,
// because some providers carry the API key there. A 404 is returned as a
// status with a nil error: providers use it for "no data".
func (c intelClient) raw(ctx context.Context, method, rawURL string, header map[string]string, body []byte) (int, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, rawURL, bytes.NewReader(body))
	if err != nil {
		return 0, nil, errors.New("invalid request")
	}
	request.Header.Set("User-Agent", "21Pent")
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for key, value := range header {
		request.Header.Set(key, value)
	}
	resp, err := c.http.Do(request)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return 0, nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, intelMaxBody))
	if err != nil {
		return resp.StatusCode, nil, errors.New("response could not be read")
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return resp.StatusCode, nil, nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return resp.StatusCode, nil, fmt.Errorf("the API key was rejected or lacks access (HTTP %d)", resp.StatusCode)
	case resp.StatusCode == http.StatusTooManyRequests:
		return resp.StatusCode, nil, errors.New("the provider rate limit or quota was reached (HTTP 429)")
	case resp.StatusCode/100 != 2:
		return resp.StatusCode, nil, fmt.Errorf("the provider returned HTTP %d", resp.StatusCode)
	}
	return resp.StatusCode, data, nil
}

// json is raw plus decoding of a 2xx body into out. found is false on a 404.
func (c intelClient) json(ctx context.Context, method, rawURL string, header map[string]string, body []byte, out any) (found bool, err error) {
	status, data, err := c.raw(ctx, method, rawURL, header, body)
	if err != nil || status == http.StatusNotFound {
		return false, err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return false, errors.New("the provider response was not the expected JSON")
	}
	return true, nil
}

func intelList(values []string, limit int) string {
	values = dedupeStrings(values)
	sort.Strings(values)
	if len(values) > limit {
		return strings.Join(values[:limit], ", ") + fmt.Sprintf(" and %d more", len(values)-limit)
	}
	return strings.Join(values, ", ")
}

const intelExposureFix = "Confirm each service is meant to be reachable from the internet; close or firewall the rest and patch the software behind the ones that stay."

func shodanLookup(ctx context.Context, c intelClient, ip string) ([]intelHit, error) {
	var r struct {
		Vulns []string `json:"vulns"`
		Data  []struct {
			Port      int                        `json:"port"`
			Transport string                     `json:"transport"`
			Product   string                     `json:"product"`
			Version   string                     `json:"version"`
			Vulns     map[string]json.RawMessage `json:"vulns"`
		} `json:"data"`
	}
	found, err := c.json(ctx, http.MethodGet, intelBase["shodan"]+"/shodan/host/"+ip+"?key="+url.QueryEscape(os.Getenv("SHODAN_API_KEY")), nil, nil, &r)
	if err != nil || !found {
		return nil, err
	}
	var services []string
	cves := append([]string{}, r.Vulns...)
	for _, s := range r.Data {
		services = append(services, strings.TrimSpace(fmt.Sprintf("%d/%s %s %s", s.Port, firstNonEmpty(s.Transport, "tcp"), s.Product, s.Version)))
		for cve := range s.Vulns {
			cves = append(cves, cve)
		}
	}
	var hits []intelHit
	if len(services) > 0 {
		hits = append(hits, intelHit{rule: "intel-shodan-services", key: "services", severity: "info",
			title:       "Internet-visible services on " + ip + " (Shodan)",
			description: "Shodan's internet-wide scans have recorded these services on the target address. Anyone can look this up.",
			evidence:    "Services: " + intelList(services, 40) + ".", fix: intelExposureFix})
	}
	cves = dedupeStrings(cves)
	sort.Strings(cves)
	for _, cve := range cves {
		hits = append(hits, intelHit{rule: "intel-shodan-cve", key: cve, cve: cve, severity: "medium", unrated: true,
			title:       "Shodan associates " + cve + " with " + ip,
			description: "Shodan matched this CVE from the software version in a service banner. It is not verified: a backported patch or a hidden version would make it a false positive.",
			evidence:    "Shodan lists " + cve + " for " + ip + ".",
			fix:         "Check the installed version of the exposed software against the CVE and patch if affected."})
	}
	return hits, nil
}

func censysLookup(ctx context.Context, c intelClient, ip string) ([]intelHit, error) {
	type service struct {
		Port      int    `json:"port"`
		Protocol  string `json:"protocol"`
		Transport string `json:"transport_protocol"`
	}
	var r struct {
		Result struct {
			Services []service `json:"services"`
			Resource struct {
				Services []service `json:"services"`
			} `json:"resource"`
		} `json:"result"`
	}
	endpoint := intelBase["censys"] + "/v3/global/asset/host/" + ip
	if org := strings.TrimSpace(os.Getenv("CENSYS_ORG_ID")); org != "" {
		endpoint += "?organization_id=" + url.QueryEscape(org)
	}
	found, err := c.json(ctx, http.MethodGet, endpoint, map[string]string{"Authorization": "Bearer " + os.Getenv("CENSYS_API_TOKEN")}, nil, &r)
	if err != nil || !found {
		return nil, err
	}
	var services []string
	for _, s := range append(r.Result.Resource.Services, r.Result.Services...) {
		services = append(services, strings.TrimSpace(fmt.Sprintf("%d/%s %s", s.Port, firstNonEmpty(strings.ToLower(s.Transport), "tcp"), s.Protocol)))
	}
	if len(services) == 0 {
		return nil, nil
	}
	return []intelHit{{rule: "intel-censys-services", key: "services", severity: "info",
		title:       "Internet-visible services on " + ip + " (Censys)",
		description: "Censys's internet-wide scans have recorded these services on the target address. Anyone can look this up.",
		evidence:    "Services: " + intelList(services, 40) + ".", fix: intelExposureFix}}, nil
}

func shadowserverLookup(ctx context.Context, c intelClient, ip string) ([]intelHit, error) {
	body, _ := json.Marshal(map[string]any{"query": map[string]string{"ip": ip}, "limit": 100, "apikey": os.Getenv("SHADOWSERVER_API_KEY")})
	mac := hmac.New(sha256.New, []byte(os.Getenv("SHADOWSERVER_API_SECRET")))
	mac.Write(body)
	var events []map[string]any
	found, err := c.json(ctx, http.MethodPost, intelBase["shadowserver"]+"/reports/query", map[string]string{"HMAC2": hex.EncodeToString(mac.Sum(nil))}, body, &events)
	if err != nil || !found {
		return nil, err
	}
	text := func(event map[string]any, keys ...string) string {
		for _, key := range keys {
			if value := strings.TrimSpace(fmt.Sprint(event[key])); event[key] != nil && value != "" {
				return value
			}
		}
		return ""
	}
	type group struct {
		count        int
		port, latest string
	}
	groups := map[string]*group{}
	for _, event := range events {
		name := strings.TrimSpace(text(event, "infection", "tag", "type") + " " + text(event, "family"))
		if name == "" {
			name = "event"
		}
		port := text(event, "port", "dst_port")
		g := groups[name+"\x00"+port]
		if g == nil {
			g = &group{port: port}
			groups[name+"\x00"+port] = g
		}
		g.count++
		if seen := text(event, "timestamp", "time"); seen > g.latest {
			g.latest = seen
		}
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var hits []intelHit
	for _, key := range keys {
		g := groups[key]
		name, _, _ := strings.Cut(key, "\x00")
		evidence := fmt.Sprintf("%d Shadowserver event(s) for %s", g.count, ip)
		if g.port != "" {
			evidence += ", port " + g.port
		}
		if g.latest != "" {
			evidence += ", most recent " + g.latest
		}
		hits = append(hits, intelHit{rule: "intel-shadowserver-event", key: key, port: g.port, severity: "medium", unrated: true,
			title:       "Shadowserver reports \"" + name + "\" for " + ip,
			description: "The Shadowserver Foundation observed this from its internet-wide scanning, sinkholes or honeypots. It is the same data national CERTs forward to network owners.",
			evidence:    evidence + ".",
			fix:         "Look up the report type on shadowserver.org for its meaning and fix; some events (for example missing BCP38 filtering) must be fixed by the network operator, not the application."})
	}
	return hits, nil
}

func greynoiseLookup(ctx context.Context, c intelClient, ip string) ([]intelHit, error) {
	var r struct {
		Noise          bool   `json:"noise"`
		Classification string `json:"classification"`
		Name           string `json:"name"`
		LastSeen       string `json:"last_seen"`
	}
	found, err := c.json(ctx, http.MethodGet, intelBase["greynoise"]+"/v3/community/"+ip, map[string]string{"key": os.Getenv("GREYNOISE_API_KEY")}, nil, &r)
	if err != nil || !found || !r.Noise {
		return nil, err
	}
	severity := "low"
	if strings.EqualFold(r.Classification, "malicious") {
		severity = "high"
	}
	return []intelHit{{rule: "intel-greynoise-noise", key: "noise", severity: severity,
		title:       "Target IP " + ip + " has been seen scanning the internet (GreyNoise: " + firstNonEmpty(r.Classification, "unknown") + ")",
		description: "GreyNoise sensors recorded unsolicited scanning or attack traffic from this address. For a server you run, that usually means it is compromised, misused as a proxy, or shares its address with another tenant.",
		evidence:    strings.TrimSpace(fmt.Sprintf("Classification %s; actor %s; last seen %s.", firstNonEmpty(r.Classification, "unknown"), firstNonEmpty(r.Name, "unknown"), firstNonEmpty(r.LastSeen, "unknown"))),
		fix:         "Review the host for compromise (unexpected processes, outbound connections, cron jobs) and confirm whether the address is shared."}}, nil
}

func abuseipdbLookup(ctx context.Context, c intelClient, ip string) ([]intelHit, error) {
	var r struct {
		Data struct {
			Score        int    `json:"abuseConfidenceScore"`
			TotalReports int    `json:"totalReports"`
			LastReported string `json:"lastReportedAt"`
		} `json:"data"`
	}
	found, err := c.json(ctx, http.MethodGet, intelBase["abuseipdb"]+"/api/v2/check?maxAgeInDays=90&ipAddress="+url.QueryEscape(ip), map[string]string{"Key": os.Getenv("ABUSEIPDB_API_KEY")}, nil, &r)
	if err != nil || !found || r.Data.Score < 25 {
		return nil, err
	}
	severity := "medium"
	if r.Data.Score >= 75 {
		severity = "high"
	}
	return []intelHit{{rule: "intel-abuseipdb-reported", key: "abuse", severity: severity,
		title:       fmt.Sprintf("Target IP %s is reported for abuse (AbuseIPDB score %d%%)", ip, r.Data.Score),
		description: "Other network operators reported abusive traffic from this address in the last 90 days. Mail and API traffic from it may be blocked, and it can indicate a compromised host.",
		evidence:    fmt.Sprintf("Abuse confidence %d%%; %d report(s); last reported %s.", r.Data.Score, r.Data.TotalReports, firstNonEmpty(r.Data.LastReported, "unknown")),
		fix:         "Review the host for compromise and outbound abuse; once clean, request delisting."}}, nil
}

func crtshLookup(ctx context.Context, c intelClient, host string) ([]intelHit, error) {
	var rows []struct {
		NameValue string `json:"name_value"`
	}
	found, err := c.json(ctx, http.MethodGet, intelBase["crtsh"]+"/?output=json&q="+url.QueryEscape("%."+host), nil, nil, &rows)
	if err != nil || !found {
		return nil, err
	}
	var names []string
	for _, row := range rows {
		for _, name := range strings.Split(row.NameValue, "\n") {
			name = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(name)), "*.")
			if name != host && strings.HasSuffix(name, "."+host) {
				names = append(names, name)
			}
		}
	}
	names = dedupeStrings(names)
	if len(names) == 0 {
		return nil, nil
	}
	return []intelHit{{rule: "intel-crtsh-hostnames", key: "hostnames", severity: "info",
		title:       fmt.Sprintf("%d hostname(s) under %s appear in public certificate logs", len(names), host),
		description: "Every publicly trusted TLS certificate is logged, so these names are known to anyone. Forgotten staging, admin or test hosts are commonly found this way. They are candidates only and were not added to the assessment scope.",
		evidence:    "Hostnames: " + intelList(names, 100) + ".",
		fix:         "Review the list for hosts that should not be public; decommission or protect them, and add the ones you own to a future assessment."}}, nil
}

func hibpLookup(ctx context.Context, c intelClient, host string) ([]intelHit, error) {
	domain := intelApex(host)
	var accounts map[string][]string
	found, err := c.json(ctx, http.MethodGet, intelBase["hibp"]+"/api/v3/breacheddomain/"+url.PathEscape(domain), map[string]string{"hibp-api-key": os.Getenv("HIBP_API_KEY")}, nil, &accounts)
	if err != nil || !found || len(accounts) == 0 {
		return nil, err
	}
	// Account names are personal data: only counts and breach names are kept.
	breaches := map[string]int{}
	for _, list := range accounts {
		for _, breach := range list {
			breaches[breach]++
		}
	}
	names := make([]string, 0, len(breaches))
	for name, count := range breaches {
		names = append(names, fmt.Sprintf("%s (%d)", name, count))
	}
	return []intelHit{{rule: "intel-hibp-breached-accounts", key: "accounts", severity: "medium",
		title:       fmt.Sprintf("%d account(s) at %s appear in known data breaches", len(accounts), domain),
		description: "Email addresses on this domain appear in breach data indexed by Have I Been Pwned. Reused passwords from those breaches are a common way into company systems.",
		evidence:    "Breaches (accounts affected): " + intelList(names, 30) + ". Account names were not stored.",
		fix:         "Force password resets for affected accounts, require multi-factor authentication, and block known-breached passwords."}}, nil
}

func githubLeaksLookup(ctx context.Context, c intelClient, host string) ([]intelHit, error) {
	domain := intelApex(host)
	header := map[string]string{"Authorization": "Bearer " + os.Getenv("GITHUB_TOKEN"), "Accept": "application/vnd.github+json"}
	total := 0
	var repos []string
	for _, keyword := range []string{"password", "secret", "api_key"} {
		var r struct {
			TotalCount int `json:"total_count"`
			Items      []struct {
				Repository struct {
					FullName string `json:"full_name"`
				} `json:"repository"`
			} `json:"items"`
		}
		if _, err := c.json(ctx, http.MethodGet, intelBase["github"]+"/search/code?per_page=20&q="+url.QueryEscape(`"`+domain+`" `+keyword), header, nil, &r); err != nil {
			return nil, err
		}
		total += r.TotalCount
		for _, item := range r.Items {
			repos = append(repos, item.Repository.FullName)
		}
	}
	if total == 0 {
		return nil, nil
	}
	return []intelHit{{rule: "intel-github-domain-references", key: "code", severity: "low",
		title:       fmt.Sprintf("Public GitHub code mentions %s next to credential keywords (%d result(s))", domain, total),
		description: "Public repositories contain files that mention this domain together with words such as password, secret or api_key. Most results are harmless, but leaked configuration and credentials are found this way. The matches were not downloaded or verified.",
		evidence:    "Repositories: " + intelList(repos, 20) + ".",
		fix:         "Review the listed repositories; if a real secret is found, rotate it first, then have the file removed."}}, nil
}

func dehashedLookup(ctx context.Context, c intelClient, host string) ([]intelHit, error) {
	domain := intelApex(host)
	body, _ := json.Marshal(map[string]any{"query": "domain:" + domain, "page": 1, "size": 1, "de_dupe": true})
	var r struct {
		Total int `json:"total"`
	}
	found, err := c.json(ctx, http.MethodPost, intelBase["dehashed"]+"/v2/search", map[string]string{"Dehashed-Api-Key": os.Getenv("DEHASHED_API_KEY")}, body, &r)
	if err != nil || !found || r.Total == 0 {
		return nil, err
	}
	return []intelHit{{rule: "intel-dehashed-leaked-records", key: "records", severity: "medium",
		title:       fmt.Sprintf("%d leaked credential record(s) exist for %s (DeHashed)", r.Total, domain),
		description: "DeHashed indexes breach and stealer-log data. Records for this domain may include working passwords. Only the count was retrieved; no records were stored.",
		evidence:    fmt.Sprintf("DeHashed reports %d record(s) for domain:%s.", r.Total, domain),
		fix:         "Review the records in DeHashed, reset affected passwords and require multi-factor authentication."}}, nil
}

func cloudflareLookup(ctx context.Context, c intelClient, host string) ([]intelHit, error) {
	domain := intelApex(host)
	header := map[string]string{"Authorization": "Bearer " + os.Getenv("CLOUDFLARE_API_TOKEN")}
	base := intelBase["cloudflare"] + "/client/v4/zones"
	var zones struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if _, err := c.json(ctx, http.MethodGet, base+"?name="+url.QueryEscape(domain), header, nil, &zones); err != nil {
		return nil, err
	}
	if len(zones.Result) == 0 {
		return nil, errors.New("the token cannot see a Cloudflare zone named " + domain)
	}
	zone := base + "/" + url.PathEscape(zones.Result[0].ID)
	var settings struct {
		Result []struct {
			ID    string `json:"id"`
			Value any    `json:"value"`
		} `json:"result"`
	}
	if _, err := c.json(ctx, http.MethodGet, zone+"/settings", header, nil, &settings); err != nil {
		return nil, err
	}
	value := map[string]string{}
	for _, s := range settings.Result {
		if text, ok := s.Value.(string); ok {
			value[s.ID] = text
		}
	}
	var hits []intelHit
	add := func(rule, severity, title, description, evidence, fix string) {
		hits = append(hits, intelHit{rule: rule, key: rule, severity: severity, title: title, description: description, evidence: evidence, fix: fix})
	}
	if mode := value["ssl"]; mode == "off" || mode == "flexible" {
		add("intel-cloudflare-ssl-mode", "high", "Cloudflare SSL mode for "+domain+" is \""+mode+"\"",
			"In this mode traffic between Cloudflare and the origin server is unencrypted, although visitors see HTTPS.",
			"Zone setting ssl = "+mode+".", "Install a certificate on the origin and set the SSL/TLS mode to Full (strict).")
	}
	if min := value["min_tls_version"]; min == "1.0" || min == "1.1" {
		add("intel-cloudflare-min-tls", "medium", "Cloudflare accepts TLS "+min+" for "+domain,
			"TLS 1.0 and 1.1 are deprecated and have known weaknesses.", "Zone setting min_tls_version = "+min+".", "Set the minimum TLS version to 1.2 or higher.")
	}
	if value["always_use_https"] == "off" {
		add("intel-cloudflare-always-https", "low", "Cloudflare does not redirect HTTP to HTTPS for "+domain,
			"Visitors who use an http:// link stay on an unencrypted connection.", "Zone setting always_use_https = off.", "Enable Always Use HTTPS.")
	}
	var records struct {
		Result []struct {
			Name    string `json:"name"`
			Type    string `json:"type"`
			Proxied bool   `json:"proxied"`
		} `json:"result"`
	}
	if _, err := c.json(ctx, http.MethodGet, zone+"/dns_records?per_page=500", header, nil, &records); err != nil {
		return nil, err
	}
	proxied := 0
	var direct []string
	for _, record := range records.Result {
		if record.Type != "A" && record.Type != "AAAA" && record.Type != "CNAME" {
			continue
		}
		if record.Proxied {
			proxied++
		} else {
			direct = append(direct, record.Name)
		}
	}
	if proxied > 0 && len(direct) > 0 {
		add("intel-cloudflare-unproxied-records", "low", fmt.Sprintf("%d DNS record(s) of %s bypass the Cloudflare proxy", len(dedupeStrings(direct)), domain),
			"These records answer with the real server address while other records are proxied. If they point at the same origin, attackers can reach it directly and skip the WAF and DDoS protection.",
			"DNS-only records: "+intelList(direct, 40)+".", "Proxy the records that serve web traffic, or restrict the origin firewall to Cloudflare's address ranges.")
	}
	return hits, nil
}

// intelNpmDeps returns the direct dependencies of the npm project at dir as
// name/version pairs, resolved from package-lock.json.
// ponytail: root package.json + package-lock.json only. pnpm/yarn locks and
// workspace packages are not read; reuse the nextjs lock parsers when needed.
func intelNpmDeps(dir string, limit int) ([][2]string, error) {
	read := func(name string, out any) error {
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
			return errors.New("this lookup requires package.json and package-lock.json at the source root")
		}
		data, err := os.ReadFile(path)
		if err != nil || json.Unmarshal(data, out) != nil {
			return errors.New(name + " could not be read as JSON")
		}
		return nil
	}
	var manifest struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := read("package.json", &manifest); err != nil {
		return nil, err
	}
	if err := read("package-lock.json", &lock); err != nil {
		return nil, err
	}
	var names []string
	for name := range manifest.Dependencies {
		names = append(names, name)
	}
	for name := range manifest.DevDependencies {
		names = append(names, name)
	}
	names = dedupeStrings(names)
	sort.Strings(names)
	var out [][2]string
	for _, name := range names {
		version := lock.Packages["node_modules/"+name].Version
		if version == "" {
			version = lock.Dependencies[name].Version
		}
		if version != "" && len(out) < limit {
			out = append(out, [2]string{name, version})
		}
	}
	if len(out) == 0 {
		return nil, errors.New("package-lock.json resolves no direct dependency of package.json")
	}
	return out, nil
}

func socketLookup(ctx context.Context, c intelClient, dir string) ([]intelHit, error) {
	deps, err := intelNpmDeps(dir, 300)
	if err != nil {
		return nil, err
	}
	token := os.Getenv("SOCKET_API_TOKEN")
	header := map[string]string{"Authorization": "Bearer " + token}
	severity := map[string]string{"low": "low", "middle": "medium", "medium": "medium", "high": "high", "critical": "critical"}
	var hits []intelHit
	for start := 0; start < len(deps); start += 100 {
		var components []map[string]string
		for _, dep := range deps[start:min(start+100, len(deps))] {
			components = append(components, map[string]string{"purl": "pkg:npm/" + strings.Replace(dep[0], "@", "%40", 1) + "@" + dep[1]})
		}
		body, _ := json.Marshal(map[string]any{"components": components})
		_, data, err := c.raw(ctx, http.MethodPost, intelBase["socket"]+"/v0/purl?alerts=true", header, body)
		if err != nil {
			return nil, err
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		for {
			var pkg struct {
				Namespace string `json:"namespace"`
				Name      string `json:"name"`
				Version   string `json:"version"`
				Alerts    []struct {
					Type     string `json:"type"`
					Severity string `json:"severity"`
					Category string `json:"category"`
				} `json:"alerts"`
			}
			if err := decoder.Decode(&pkg); err != nil {
				break
			}
			name := pkg.Name
			if pkg.Namespace != "" {
				name = pkg.Namespace + "/" + pkg.Name
			}
			for _, alert := range pkg.Alerts {
				level := severity[strings.ToLower(alert.Severity)]
				if level != "high" && level != "critical" && alert.Category != "supplyChainRisk" {
					continue
				}
				hits = append(hits, intelHit{rule: "intel-socket-" + alert.Type, key: name + "@" + pkg.Version + "\x00" + alert.Type,
					pkg: name, pkgVersion: pkg.Version, severity: firstNonEmpty(level, "medium"),
					title:       "Socket flags " + name + "@" + pkg.Version + ": " + alert.Type,
					description: "Socket.dev analyses what a package does (install scripts, network and shell access, obfuscation, known malware, typosquatting) rather than only its known CVEs.",
					evidence:    fmt.Sprintf("Alert %s, category %s, severity %s.", alert.Type, firstNonEmpty(alert.Category, "unknown"), firstNonEmpty(alert.Severity, "unknown")),
					fix:         "Review the alert on socket.dev; remove or replace the package if the behaviour is not expected."})
			}
		}
	}
	return hits, nil
}

func depsdevLookup(ctx context.Context, c intelClient, dir string) ([]intelHit, error) {
	deps, err := intelNpmDeps(dir, 60)
	if err != nil {
		return nil, err
	}
	base := intelBase["depsdev"] + "/v3"
	var hits []intelHit
	failed := 0
	for _, dep := range deps {
		var version struct {
			IsDeprecated    bool `json:"isDeprecated"`
			RelatedProjects []struct {
				ProjectKey struct {
					ID string `json:"id"`
				} `json:"projectKey"`
				RelationType string `json:"relationType"`
			} `json:"relatedProjects"`
		}
		found, err := c.json(ctx, http.MethodGet, base+"/systems/npm/packages/"+url.PathEscape(dep[0])+"/versions/"+url.PathEscape(dep[1]), nil, nil, &version)
		if err != nil {
			failed++
			continue
		}
		if !found {
			continue
		}
		if version.IsDeprecated {
			hits = append(hits, intelHit{rule: "intel-depsdev-deprecated", key: dep[0], pkg: dep[0], pkgVersion: dep[1], severity: "low",
				title:       dep[0] + "@" + dep[1] + " is deprecated",
				description: "The maintainers marked this version as deprecated, so it will not receive security fixes.",
				evidence:    "deps.dev reports isDeprecated for " + dep[0] + "@" + dep[1] + ".", fix: "Move to the maintained version or replacement the deprecation notice names."})
		}
		for _, project := range version.RelatedProjects {
			if project.RelationType != "SOURCE_REPO" || project.ProjectKey.ID == "" {
				continue
			}
			var info struct {
				Scorecard struct {
					OverallScore float64 `json:"overallScore"`
				} `json:"scorecard"`
			}
			if found, err := c.json(ctx, http.MethodGet, base+"/projects/"+url.PathEscape(project.ProjectKey.ID), nil, nil, &info); err == nil && found && info.Scorecard.OverallScore > 0 && info.Scorecard.OverallScore < 3 {
				hits = append(hits, intelHit{rule: "intel-depsdev-low-scorecard", key: dep[0], pkg: dep[0], pkgVersion: dep[1], severity: "info",
					title:       fmt.Sprintf("%s has a low OpenSSF Scorecard (%.1f/10)", dep[0], info.Scorecard.OverallScore),
					description: "OpenSSF Scorecard rates a project's security practices (maintenance, code review, branch protection, pinned dependencies). A low score means a higher chance of unpatched or compromised releases.",
					evidence:    fmt.Sprintf("Source repository %s scores %.1f/10.", project.ProjectKey.ID, info.Scorecard.OverallScore),
					fix:         "Prefer a better-maintained alternative for security-sensitive use, or pin and review updates of this package."})
			}
			break
		}
	}
	if failed == len(deps) {
		return nil, errors.New("deps.dev could not be reached")
	}
	return hits, nil
}
