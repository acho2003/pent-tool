package scanner

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/storage"
)

const (
	AttackSurfaceSchemaVersion = 2
	// AttackSurfaceClassifierVersion is bumped whenever eligibility semantics
	// change, so cached snapshots are re-parsed from their raw JSONL (without
	// contacting the target) instead of being reused. v2: endpoint State,
	// exclusions and placeholder refusal. v3: retain scoped OpenAPI operations
	// that still need explicit inputs.
	AttackSurfaceClassifierVersion = 6
)

// Endpoint states. An empty State (seeds, OpenAPI merges, the legacy parse and
// snapshots written before State existed) is treated as in_scope; every other
// non-in_scope state is kept in the inventory with a reason but never
// dispatched.
const (
	EndpointStateInScope              = "in_scope"
	EndpointStateOutOfScope           = "out_of_scope"
	EndpointStateExcluded             = "excluded"
	EndpointStateStatic               = "static"
	EndpointStateHistoricalUnverified = "historical_unverified"
	EndpointStateUnmaterialized       = "unmaterialized"
	EndpointStateUnreachable          = "unreachable"
	EndpointStateUnauthorized         = "unauthorized"
)

// EndpointCoverageBatchCompleted is the coverage status of an endpoint that
// was part of a completed run whose adapter only reports batch-level evidence,
// so the run cannot say that this particular endpoint was exercised.
const EndpointCoverageBatchCompleted = "batch_completed"

// assessmentEndpointCapReason is the skip reason of an endpoint refused by the
// assessment-wide unique endpoint cap.
const assessmentEndpointCapReason = "assessment endpoint budget exhausted"

// batchEvidenceScanners only report results for the dispatched batch as a
// whole; a completed run of one of them marks its endpoints batch_completed.
var batchEvidenceScanners = map[string]bool{"nuclei": true, "wapiti": true, "dalfox": true, "katana": true, "zap": true}

// EndpointProvenance records which tool observed an endpoint, where, and
// whether the observation was made with an authenticated session.
type EndpointProvenance struct {
	Tool          string `json:"tool"`
	Source        string `json:"source,omitempty"`
	Artifact      string `json:"artifact,omitempty"`
	ObservedAt    string `json:"observed_at,omitempty"`
	Authenticated bool   `json:"authenticated,omitempty"`
}

type EndpointParameter struct {
	Name     string `json:"name"`
	Location string `json:"location"`
}

type EndpointScannerCoverage struct {
	AttemptID       string `json:"attempt_id,omitempty"`
	PlanFingerprint string `json:"plan_fingerprint,omitempty"`
	EvidenceRef     string `json:"evidence_reference,omitempty"`
	Scanner         string `json:"scanner"`
	Status          string `json:"status"`
	Reason          string `json:"reason,omitempty"`
	StartedAt       string `json:"started_at,omitempty"`
	FinishedAt      string `json:"finished_at,omitempty"`
}

// AttackSurfaceEndpoint is one normalized request surface. URL is a concrete,
// in-scope sample used by scanners; CanonicalURL is the stable identity with
// query values replaced by placeholders. A fragment is metadata only and never
// participates in the HTTP request identity.
type AttackSurfaceEndpoint struct {
	ReplayRef          string                    `json:"replay_reference,omitempty"`
	ReadOnly           bool                      `json:"read_only,omitempty"`
	ReplayBody         string                    `json:"-"`
	ReplayHeaders      map[string]string         `json:"-"`
	GroupID            string                    `json:"group_id,omitempty"`
	AuthContextID      string                    `json:"auth_context_id,omitempty"`
	RequestContentType string                    `json:"request_content_type,omitempty"`
	BodyDigest         string                    `json:"body_digest,omitempty"`
	ObservationKind    string                    `json:"observation_kind,omitempty"`
	CoverageHistory    []EndpointScannerCoverage `json:"coverage_history,omitempty"`
	ID                 string                    `json:"id"`
	URL                string                    `json:"url"`
	CanonicalURL       string                    `json:"canonical_url"`
	Method             string                    `json:"method"`
	Path               string                    `json:"path"`
	SPARoutes          []string                  `json:"spa_routes,omitempty"`
	Kind               string                    `json:"kind"`
	Sources            []string                  `json:"sources,omitempty"`
	Parameters         []EndpointParameter       `json:"parameters,omitempty"`
	StatusCode         int                       `json:"status_code,omitempty"`
	ContentType        string                    `json:"content_type,omitempty"`
	Sensitive          bool                      `json:"sensitive,omitempty"`
	HasParameters      bool                      `json:"has_parameters,omitempty"`
	HasForm            bool                      `json:"has_form,omitempty"`
	ObservedWithAuth   bool                      `json:"observed_with_auth,omitempty"`
	RequiresAuth       *bool                     `json:"requires_auth,omitempty"`
	DiscoveredAt       string                    `json:"discovered_at,omitempty"`
	State              string                    `json:"state,omitempty"`
	StateReason        string                    `json:"state_reason,omitempty"`
	Provenance         []EndpointProvenance      `json:"provenance,omitempty"`
	ScannerCoverage    []EndpointScannerCoverage `json:"scanner_coverage,omitempty"`
}

type AttackSurface struct {
	WorkflowVersion   string                  `json:"workflow_version,omitempty"`
	Hosts             []InventoryHost         `json:"hosts,omitempty"`
	Services          []InventoryService      `json:"services,omitempty"`
	Definitions       []InventoryDefinition   `json:"definitions,omitempty"`
	DiscoveryGaps     []string                `json:"discovery_gaps,omitempty"`
	SchemaVersion     int                     `json:"schema_version"`
	ClassifierVersion int                     `json:"classifier_version"`
	Scope             string                  `json:"scope"`
	Target            string                  `json:"target"`
	GeneratedAt       string                  `json:"generated_at"`
	RawCount          int                     `json:"raw_count"`
	SourceChecksum    string                  `json:"source_checksum,omitempty"`
	Endpoints         []AttackSurfaceEndpoint `json:"endpoints"`
}

func NewSeedAttackSurface(scope, target string) *AttackSurface {
	surface := &AttackSurface{
		SchemaVersion: AttackSurfaceSchemaVersion, ClassifierVersion: AttackSurfaceClassifierVersion,
		Scope: scope, Target: target, GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano), Endpoints: []AttackSurfaceEndpoint{},
	}
	if ep, ok := normalizeAttackSurfaceEndpoint(target, "GET", "seed", surface.GeneratedAt, 0, "", endpointParameters(target), false, false); ok {
		ep.ObservationKind = "seed"
		surface.RawCount = 1
		surface.Endpoints = append(surface.Endpoints, ep)
	}
	return surface
}

func EnsureSeedEndpoint(surface *AttackSurface, target string) {
	if surface == nil {
		return
	}
	byID := make(map[string]int, len(surface.Endpoints))
	for i := range surface.Endpoints {
		byID[surface.Endpoints[i].ID] = i
	}
	if ep, ok := normalizeAttackSurfaceEndpoint(target, "GET", "seed", surface.GeneratedAt, 0, "", endpointParameters(target), false, false); ok {
		ep.ObservationKind = "seed"
		mergeSurfaceEndpoint(surface, byID, ep)
	}
}

// ParseKatanaAttackSurface tolerates malformed JSONL rows and returns every
// usable request record, normalized and deduplicated in discovery order. It is
// the legacy entry point: endpoints off the target's host are dropped and no
// State is stamped (see ParseKatanaAttackSurfaceScoped).
func ParseKatanaAttackSurface(artifact, scope, target string, observedWithAuth bool) (*AttackSurface, error) {
	return ParseKatanaAttackSurfaceScoped(artifact, scope, target, observedWithAuth, nil)
}

// ParseKatanaAttackSurfaceScoped parses katana JSONL like
// ParseKatanaAttackSurface and stamps every endpoint's State against appScope:
// rows outside the approved origins or matching an exclusion are KEPT as
// out_of_scope/excluded with the reason, so they stay visible but are never
// dispatched. A nil appScope keeps the legacy host-only boundary, under which
// the legacy pipeline crawls nmap-discovered ports: off-host rows are dropped,
// every port on the target host is kept and no State is stamped.
func ParseKatanaAttackSurfaceScoped(artifact, scope, target string, observedWithAuth bool, appScope *assessment.AppScope) (*AttackSurface, error) {
	data, err := os.ReadFile(artifact)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	surface := &AttackSurface{
		SchemaVersion: AttackSurfaceSchemaVersion, ClassifierVersion: AttackSurfaceClassifierVersion,
		Scope: scope, Target: target, GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
		SourceChecksum: hex.EncodeToString(sum[:]), Endpoints: []AttackSurfaceEndpoint{},
	}
	byID := map[string]int{}
	// Scope guard: katana emits off-host URLs it finds ON in-scope pages
	// (external links like owasp.org, CDN fonts). Those must never be
	// dispatched to scanners. Legacy (nil appScope) keeps only endpoints on the
	// assessed host; an empty target disables that filter. A typed scope keeps
	// them with an out_of_scope State instead.
	targetHost := hostFromTarget(target)
	artifactName := filepath.Base(artifact)
	var requestBody, requestType, recordedBodyDigest, replayRef, requestID, recordedAuthContext string
	var readOnly, trustedBrowser bool
	var nativeObservationKind, nativeDispositionReason string
	observationAuth := observedWithAuth
	add := func(rawURL, method, source, timestamp string, status int, contentType string, params []EndpointParameter, hasForm bool) {
		allowed, reason := inSurfaceScope(rawURL, targetHost, appScope)
		if !allowed && appScope == nil {
			return
		}
		ep, ok := normalizeAttackSurfaceEndpoint(rawURL, method, source, timestamp, status, contentType, params, hasForm, observationAuth)
		if !ok {
			return
		}
		if recordedBodyDigest != "" {
			ep.BodyDigest = recordedBodyDigest
			ep.ID = inventoryID(ep.ID, recordedBodyDigest)
		} else if requestBody != "" {
			sum := sha256.Sum256([]byte(requestBody))
			ep.BodyDigest = hex.EncodeToString(sum[:])
			ep.ID = inventoryID(ep.ID, ep.BodyDigest)
		}
		ep.RequestContentType = requestType
		if requestType != "" {
			ep.ID = inventoryID(ep.ID, requestType)
		}
		if observationAuth {
			ep.AuthContextID = inventoryID(scope, "target-bound")
			if validAuthenticationContextID(recordedAuthContext) {
				ep.AuthContextID = recordedAuthContext
			}
			ep.ID = inventoryID(ep.ID, ep.AuthContextID)
		}
		ep.ReplayRef, ep.ReadOnly = replayRef, readOnly
		if decoded, err := hex.DecodeString(requestID); err == nil && len(decoded) == 12 {
			ep.ID = requestID
		}
		ep.Provenance = []EndpointProvenance{{Tool: "katana", Source: strings.TrimSpace(source), Artifact: artifactName, ObservedAt: timestamp, Authenticated: observationAuth}}
		if appScope != nil {
			stampEndpointState(&ep, *appScope, allowed, reason)
		}
		if trustedBrowser && ep.ReplayRef == "" && replayURLRedacted(ep.URL) && endpointStateDispatchable(ep.State) {
			ep.State, ep.StateReason = EndpointStateUnmaterialized, "redacted discovery URL requires its original encrypted replay"
		}
		if trustedBrowser && nativeObservationKind == "candidate" {
			ep.ObservationKind = "candidate"
			if endpointStateDispatchable(ep.State) {
				ep.State, ep.StateReason = EndpointStateUnmaterialized, nativeDispositionReason
			}
		}
		mergeSurfaceEndpoint(surface, byID, ep)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 64<<10), 8<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		surface.RawCount++
		var raw map[string]any
		if json.Unmarshal([]byte(line), &raw) != nil {
			surface.DiscoveryGaps = append(surface.DiscoveryGaps, fmt.Sprintf("malformed crawler record %d", surface.RawCount))
			continue
		}
		request, _ := raw["request"].(map[string]any)
		response, _ := raw["response"].(map[string]any)
		endpoint := firstStringValue(request, "endpoint", "url")
		if endpoint == "" {
			endpoint = firstStringValue(raw, "endpoint", "url")
		}
		requestBody = firstStringValue(request, "body")
		replayRef, requestID, readOnly = "", "", false
		recordedAuthContext = ""
		trustedBrowser = (firstStringValue(request, "source") == "browser" || firstStringValue(request, "source") == "browser-dom") && filepath.Base(artifact) == "browser.jsonl"
		trustedBrowser = trustedBrowser || (firstStringValue(request, "source") == "zap-discovery" && filepath.Base(artifact) == "zap-discovery.jsonl")
		nativeObservationKind, nativeDispositionReason = "", ""
		if filepath.Base(artifact) == "zap-discovery.jsonl" && firstStringValue(request, "source") == "zap-discovery" {
			nativeObservationKind = firstStringValue(request, "observation_kind")
			nativeDispositionReason = firstStringValue(request, "disposition_reason")
		}
		if trustedBrowser {
			recordedAuthContext = firstStringValue(request, "auth_context_id")
		}
		if trustedBrowser && firstStringValue(request, "source") == "browser" {
			replayRef, requestID = firstStringValue(request, "replay_reference"), firstStringValue(request, "request_id")
			readOnly, _ = request["read_only"].(bool)
		}
		observationAuth = observedWithAuth
		if flag, ok := request["authenticated"].(bool); ok && trustedBrowser {
			observationAuth = flag
		}
		recordedBodyDigest = firstStringValue(request, "body_digest")
		if decoded, err := hex.DecodeString(recordedBodyDigest); err != nil || len(decoded) != sha256.Size {
			recordedBodyDigest = ""
		}
		requestType = headerValue(request["headers"], "content-type")
		method := firstStringValue(request, "method")
		tag := firstStringValue(request, "tag")
		source := firstStringValue(request, "source")
		if source == "" {
			source = "katana"
		}
		status := intValue(response["status_code"])
		contentType := headerValue(response["headers"], "content-type")
		params := endpointParameters(endpoint)
		if supplied, ok := request["parameters"].([]any); ok {
			for _, item := range supplied {
				if parameter, ok := item.(map[string]any); ok {
					name, location := firstStringValue(parameter, "name"), firstStringValue(parameter, "location")
					if name != "" && (location == "body" || location == "query" || location == "path") {
						params = append(params, EndpointParameter{Name: name, Location: location})
					}
				}
			}
		}
		params = append(params, bodyParameters(firstStringValue(request, "body"), headerValue(request["headers"], "content-type"))...)
		hasForm := strings.EqualFold(tag, "form")
		if hasForm {
			for i := range params {
				if params[i].Location == "body" {
					params[i].Location = "form"
				}
			}
		}
		if endpoint != "" {
			add(endpoint, method, source, firstStringValue(raw, "timestamp"), status, contentType, params, hasForm)
		}
		// Katana versions have emitted form extraction at both the top level and
		// under response. Decode generically so upgrades do not make forms vanish.
		requestBody, requestType, recordedBodyDigest, replayRef, requestID = "", "", "", "", ""
		readOnly = false
		for _, form := range collectForms(raw) {
			action := firstStringValue(form, "action", "url", "endpoint")
			if action == "" {
				continue
			}
			if base, parseErr := url.Parse(endpoint); parseErr == nil {
				if ref, refErr := url.Parse(action); refErr == nil {
					action = base.ResolveReference(ref).String()
				}
			}
			add(action, firstStringValue(form, "method"), source, firstStringValue(raw, "timestamp"), 0, "", formParameters(form), true)
			if trustedBrowser {
				for i := range surface.Endpoints {
					ep := &surface.Endpoints[i]
					if ep.URL == action && ep.HasForm && ep.ReplayRef == "" && endpointStateDispatchable(ep.State) {
						ep.State, ep.StateReason = EndpointStateUnmaterialized, "form submission requires an approved operation and supplied inputs"
					}
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return surface, nil
}

// inSurfaceScope reports whether rawURL is inside the crawl boundary and why
// not. A typed scope delegates to AppScope.Allows (scheme, host and port with
// default ports normalized, plus the path prefix). A nil scope is the legacy
// host-only boundary (see inSurfaceHostScope).
func inSurfaceScope(rawURL, targetHost string, scope *assessment.AppScope) (bool, string) {
	if scope != nil {
		return scope.Allows(rawURL)
	}
	if inSurfaceHostScope(rawURL, targetHost) {
		return true, ""
	}
	return false, "endpoint is not on the assessed host"
}

// inSurfaceHostScope reports whether rawURL is on the assessed host, so the
// legacy crawl stays scoped and off-host links are dropped before scanning. An
// empty targetHost disables the filter (keep everything).
func inSurfaceHostScope(rawURL, targetHost string) bool {
	if targetHost == "" {
		return true
	}
	return strings.EqualFold(hostFromTarget(rawURL), targetHost)
}

// stampEndpointState records ep's State against scope at parse time, so the
// dispatch gate stays a pure function of the endpoint. allowed/reason are the
// already-computed scope.Allows decision for ep.
func stampEndpointState(ep *AttackSurfaceEndpoint, scope assessment.AppScope, allowed bool, reason string) {
	switch {
	case !allowed:
		ep.State, ep.StateReason = EndpointStateOutOfScope, reason
	default:
		if excluded, why := scope.Excluded(ep.Method, ep.URL); excluded {
			ep.State, ep.StateReason = EndpointStateExcluded, why
		} else if ep.Kind == "static" {
			ep.State, ep.StateReason = EndpointStateStatic, "static resource is discovery-only"
		} else {
			ep.State, ep.StateReason = EndpointStateInScope, ""
		}
	}
}

// endpointStateDispatchable reports whether a State may be dispatched: only
// in_scope and the legacy empty State.
func endpointStateDispatchable(state string) bool {
	return state == "" || state == EndpointStateInScope
}

func normalizeAttackSurfaceEndpoint(rawURL, method, source, timestamp string, status int, contentType string, params []EndpointParameter, hasForm, observedWithAuth bool) (AttackSurfaceEndpoint, bool) {
	observed, canonical, route, endpointPath, ok := canonicalizeAttackSurfaceURL(rawURL)
	if !ok {
		return AttackSurfaceEndpoint{}, false
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}
	params = mergeParameters(params)
	hash := sha256.Sum256([]byte(method + "\x00" + observed + fmt.Sprint(params) + fmt.Sprint(observedWithAuth)))
	group := sha256.Sum256([]byte(method + "\x00" + canonical))
	requiresAuth := (*bool)(nil)
	if status == 401 || status == 403 {
		v := true
		requiresAuth = &v
	}
	ep := AttackSurfaceEndpoint{
		GroupID: hex.EncodeToString(group[:12]), ObservationKind: "observed", ID: hex.EncodeToString(hash[:12]), URL: observed, CanonicalURL: canonical, Method: method,
		Path: endpointPath, Sources: []string{strings.TrimSpace(source)}, Parameters: params,
		StatusCode: status, ContentType: contentType, HasParameters: len(params) > 0, HasForm: hasForm,
		ObservedWithAuth: observedWithAuth, RequiresAuth: requiresAuth, DiscoveredAt: timestamp,
	}
	ep.Kind, ep.Sensitive = classifyAttackSurfaceEndpoint(endpointPath, contentType)
	if route != "" {
		ep.SPARoutes = []string{route}
	}
	return ep, true
}

func canonicalizeAttackSurfaceURL(raw string) (observed, canonical, route, endpointPath string, ok bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return "", "", "", "", false
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port != "" && !((u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443")) {
		u.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	route = u.Fragment
	u.Fragment = ""
	u.RawFragment = ""
	if u.Path == "" {
		u.Path = "/"
	}
	endpointPath = u.Path
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", "", "", "", false
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	canonicalParts := make([]string, 0, len(keys))
	for _, key := range keys {

		canonicalParts = append(canonicalParts, url.QueryEscape(key)+"={value}")
	}
	// Preserve the encoded query and its original order for replay identity.
	// The parsed values are only used for the separate grouping key.
	observed = u.String()
	u.RawQuery = strings.Join(canonicalParts, "&")
	canonical = u.String()
	return observed, canonical, route, endpointPath, true
}

func classifyAttackSurfaceEndpoint(endpointPath, contentType string) (kind string, sensitive bool) {
	lowerPath := strings.ToLower(endpointPath)
	ext := strings.ToLower(path.Ext(lowerPath))
	staticExts := map[string]bool{".js": true, ".mjs": true, ".css": true, ".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true, ".ico": true, ".woff": true, ".woff2": true, ".ttf": true, ".map": true, ".webp": true}
	if staticExts[ext] {
		kind = "static"
	} else if strings.Contains(lowerPath, "/api/") || strings.HasPrefix(lowerPath, "/api") || strings.Contains(lowerPath, "/rest/") || strings.HasPrefix(lowerPath, "/rest") || strings.Contains(lowerPath, "graphql") || strings.Contains(lowerPath, "swagger") || strings.Contains(lowerPath, "openapi") || strings.Contains(strings.ToLower(contentType), "application/json") {
		kind = "api"
	} else {
		kind = "web"
	}
	for _, marker := range []string{"/admin", "/metrics", "/debug", "/actuator", "/swagger", "/api-docs", "/backup", "/ftp", "/.env"} {
		if lowerPath == marker || strings.HasPrefix(lowerPath, marker+"/") || strings.HasPrefix(lowerPath, marker+".") || strings.HasSuffix(lowerPath, marker) {
			sensitive = true
			break
		}
	}
	return kind, sensitive
}

func endpointParameters(raw string) []EndpointParameter {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	var out []EndpointParameter
	for name := range u.Query() {
		out = append(out, EndpointParameter{Name: name, Location: "query"})
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if len(segment) > 2 && strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			out = append(out, EndpointParameter{Name: strings.TrimSuffix(strings.TrimPrefix(segment, "{"), "}"), Location: "path"})
		}
	}
	return out
}

func bodyParameters(body, contentType string) []EndpointParameter {
	body = strings.TrimSpace(body)
	if body == "" {
		return nil
	}
	var out []EndpointParameter
	if strings.Contains(strings.ToLower(contentType), "json") || strings.HasPrefix(body, "{") {
		var value map[string]any
		if json.Unmarshal([]byte(body), &value) == nil {
			for name := range value {
				out = append(out, EndpointParameter{Name: name, Location: "body"})
			}
			return out
		}
	}
	if values, err := url.ParseQuery(body); err == nil {
		for name := range values {
			out = append(out, EndpointParameter{Name: name, Location: "body"})
		}
	}
	return out
}

func mergeSurfaceEndpoint(surface *AttackSurface, byID map[string]int, incoming AttackSurfaceEndpoint) {
	if index, exists := byID[incoming.ID]; exists {
		ep := &surface.Endpoints[index]
		if incoming.ObservationKind == "observed" {
			ep.ObservationKind = "observed"
		}
		if incoming.ReplayRef != "" {
			ep.ReplayRef = incoming.ReplayRef
			ep.ReadOnly = incoming.ReadOnly
		}
		ep.Sources = mergeStrings(ep.Sources, incoming.Sources)
		ep.Parameters = mergeParameters(append(ep.Parameters, incoming.Parameters...))
		ep.HasParameters = len(ep.Parameters) > 0
		ep.HasForm = ep.HasForm || incoming.HasForm
		ep.Sensitive = ep.Sensitive || incoming.Sensitive
		ep.SPARoutes = mergeStrings(ep.SPARoutes, incoming.SPARoutes)
		if ep.StatusCode == 0 {
			ep.StatusCode = incoming.StatusCode
		}
		if ep.ContentType == "" {
			ep.ContentType = incoming.ContentType
		}
		if ep.RequiresAuth == nil {
			ep.RequiresAuth = incoming.RequiresAuth
		}
		// A stamped State replaces an empty one, and a refusing State wins over
		// a dispatchable one, so merging never widens what may be dispatched.
		if ep.State == "" || (endpointStateDispatchable(ep.State) && !endpointStateDispatchable(incoming.State)) {
			if incoming.State != "" {
				ep.State, ep.StateReason = incoming.State, incoming.StateReason
			}
		}
		ep.Provenance = mergeProvenance(ep.Provenance, incoming.Provenance)
		return
	}
	byID[incoming.ID] = len(surface.Endpoints)
	surface.Endpoints = append(surface.Endpoints, incoming)
}

func mergeProvenance(left, right []EndpointProvenance) []EndpointProvenance {
	out := left
	for _, p := range right {
		duplicate := false
		for _, existing := range out {
			if existing.Tool == p.Tool && existing.Source == p.Source && existing.Artifact == p.Artifact && existing.Authenticated == p.Authenticated {
				duplicate = true
				break
			}
		}
		if !duplicate {
			out = append(out, p)
		}
	}
	return out
}

func mergeParameters(in []EndpointParameter) []EndpointParameter {
	seen := map[string]bool{}
	out := make([]EndpointParameter, 0, len(in))
	for _, p := range in {
		p.Name, p.Location = strings.TrimSpace(p.Name), strings.ToLower(strings.TrimSpace(p.Location))
		if p.Name == "" {
			continue
		}
		key := p.Location + "\x00" + p.Name
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Location == out[j].Location {
			return out[i].Name < out[j].Name
		}
		return out[i].Location < out[j].Location
	})
	return out
}

func mergeStrings(left, right []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range [][]string{left, right} {
		for _, value := range list {
			value = strings.TrimSpace(value)
			if value != "" && !seen[value] {
				seen[value] = true
				out = append(out, value)
			}
		}
	}
	return out
}

func firstStringValue(value map[string]any, keys ...string) string {
	for _, key := range keys {
		if text, ok := value[key].(string); ok && strings.TrimSpace(text) != "" {
			return strings.TrimSpace(text)
		}
	}
	return ""
}

func intValue(value any) int {
	switch v := value.(type) {
	case float64:
		return int(v)
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	}
	return 0
}

func headerValue(value any, name string) string {
	headers, _ := value.(map[string]any)
	for key, raw := range headers {
		if strings.EqualFold(strings.ReplaceAll(key, "_", "-"), name) {
			switch v := raw.(type) {
			case string:
				return v
			case []any:
				if len(v) > 0 {
					return fmt.Sprint(v[0])
				}
			}
		}
	}
	return ""
}

func collectForms(raw map[string]any) []map[string]any {
	var out []map[string]any
	var walk func(any, int)
	walk = func(value any, depth int) {
		if depth > 4 {
			return
		}
		switch v := value.(type) {
		case map[string]any:
			for key, child := range v {
				if strings.EqualFold(key, "forms") || strings.EqualFold(key, "form") {
					switch forms := child.(type) {
					case []any:
						for _, item := range forms {
							if form, ok := item.(map[string]any); ok {
								out = append(out, form)
							}
						}
					case map[string]any:
						out = append(out, forms)
					}
				}
				walk(child, depth+1)
			}
		case []any:
			for _, child := range v {
				walk(child, depth+1)
			}
		}
	}
	walk(raw, 0)
	return out
}

func formParameters(form map[string]any) []EndpointParameter {
	var out []EndpointParameter
	for _, key := range []string{"inputs", "fields", "parameters"} {
		switch values := form[key].(type) {
		case []any:
			for _, item := range values {
				if field, ok := item.(map[string]any); ok {
					if name := firstStringValue(field, "name", "id"); name != "" {
						out = append(out, EndpointParameter{Name: name, Location: "form"})
					}
				}
			}
		case map[string]any:
			for name := range values {
				out = append(out, EndpointParameter{Name: name, Location: "form"})
			}
		}
	}
	return mergeParameters(out)
}

// DispatchTargets returns concrete URLs eligible for a scanner and records the
// deterministic decision on every endpoint. It is the legacy entry point: no
// scope re-check and no assessment-wide endpoint cap (see
// DispatchTargetsScoped).
func DispatchTargets(surface *AttackSurface, scannerName string, max int) []string {
	return DispatchTargetsScoped(surface, scannerName, max, nil, nil)
}

// DispatchTargetsScoped is the single dispatch gate. Each endpoint must pass
// endpointEligibleInScope (State, approved origins, exclusions, placeholder
// paths, safe method and scanner traits); at most max (<=0: unlimited) unique
// URLs are dispatched, and each dispatched endpoint must also be granted by
// budget's assessment-wide unique endpoint cap. A nil scope skips the boundary
// re-check (legacy) and a nil budget never caps. Every endpoint records the
// decision and its reason in its scanner coverage.
func DispatchTargetsScoped(surface *AttackSurface, scannerName string, max int, scope *assessment.AppScope, budget *AssessmentBudget) []string {
	return dispatchTargetsWithPolicy(surface, scannerName, max, scope, budget, UnifiedWorkflowEnabled())
}
func dispatchTargetsWithPolicy(surface *AttackSurface, scannerName string, max int, scope *assessment.AppScope, budget *AssessmentBudget, expanded bool, contextIDs ...string) []string {
	if surface == nil {
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	seen := map[string]bool{}
	var targets []string
	selectedVariants := 0
	for i := range surface.Endpoints {
		ep := &surface.Endpoints[i]
		contextID := ""
		if len(contextIDs) > 0 {
			contextID = contextIDs[0]
		}
		if contextID != "" && ep.AuthContextID != contextID {
			continue
		}
		eligible, reason := endpointEligibleWithPolicy(*ep, scannerName, scope, expanded)
		if expanded && scannerName != "apichecks" && ep.AuthContextID != "" && ep.AuthContextID != inventoryID(surface.Scope, "target-bound") && ep.AuthContextID != contextID {
			eligible, reason = false, "request requires a separate named authentication context"
		}
		status := "skipped"
		switch {
		case !eligible:
		case max > 0 && ((expanded && selectedVariants >= max) || (!expanded && len(targets) >= max)):
			reason = "endpoint budget exhausted"
		case budget != nil && len(budget.ReserveEndpoints([]string{ep.ID})) == 0:
			reason = assessmentEndpointCapReason
		default:
			status = "dispatched"
			selectedVariants++
			if !seen[ep.URL] {
				seen[ep.URL] = true
				targets = append(targets, ep.URL)
			}
		}
		setEndpointCoverage(ep, EndpointScannerCoverage{Scanner: scannerName, Status: status, Reason: reason, StartedAt: now})
	}
	return targets
}

func SkipEndpointCoverage(surface *AttackSurface, scannerName, reason string) {
	if surface == nil {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for i := range surface.Endpoints {
		setEndpointCoverage(&surface.Endpoints[i], EndpointScannerCoverage{Scanner: scannerName, Status: "skipped", Reason: reason, FinishedAt: now})
	}
}

func endpointDispatchLimit(scannerName string, configured int) int {
	return endpointDispatchLimitForWorkflow(scannerName, configured, false)
}

func endpointDispatchLimitForWorkflow(scannerName string, configured int, expanded bool) int {
	switch scannerName {
	case "wapiti":
		if expanded {
			return configured
		}
		if configured <= 0 || configured > wapitiMaxStartURLs {
			return wapitiMaxStartURLs
		}
	case "nikto", "testssl":
		return 1
	}
	return configured
}

func requestEndpointTargets(req Request) []string {
	if req.StructuredDispatch || len(req.EndpointTargets) > 0 {
		return req.EndpointTargets
	}
	return req.WebEndpoints
}

// endpointEligibleForScanner is the pure gate over the endpoint alone (its
// stamped State included); see endpointEligibleInScope.
func endpointEligibleForScanner(ep AttackSurfaceEndpoint, scannerName string) (bool, string) {
	return endpointEligibleInScope(ep, scannerName, nil)
}

// endpointEligibleInScope decides whether scannerName may be sent ep, and why
// not. It refuses, in order: a non-dispatchable State, a URL outside scope or
// matching one of its exclusions (re-checked because seeds, OpenAPI merges and
// resumed snapshots carry no State), a path holding an unresolved {placeholder}
// (literal or percent-encoded), an unsafe method, static resources, and
// endpoints without the traits the scanner needs. A nil scope skips the
// boundary re-check.
func endpointEligibleInScope(ep AttackSurfaceEndpoint, scannerName string, scope *assessment.AppScope) (bool, string) {
	return endpointEligibleWithPolicy(ep, scannerName, scope, UnifiedWorkflowEnabled())
}
func endpointEligibleWithPolicy(ep AttackSurfaceEndpoint, scannerName string, scope *assessment.AppScope, expanded bool) (bool, string) {
	if !endpointStateDispatchable(ep.State) {
		reason := "endpoint state is " + ep.State
		if ep.StateReason != "" {
			reason += ": " + ep.StateReason
		}
		return false, reason
	}
	if scope != nil {
		if allowed, why := scope.Allows(ep.URL); !allowed {
			return false, "endpoint is out of scope: " + why
		}
		if excluded, why := scope.Excluded(ep.Method, ep.URL); excluded {
			return false, "endpoint is excluded: " + why
		}
	}
	if endpointHasPlaceholderPath(ep.URL) {
		return false, "endpoint path contains an unresolved {placeholder}"
	}
	safeMethod := ep.Method == "GET" || ep.Method == "HEAD" || ep.Method == "OPTIONS" || (expanded && scannerName == "zap" && ep.Method == "POST" && ep.ReadOnly && ep.ReplayRef != "")
	if !safeMethod {
		return false, "unsafe or state-changing method is inventory-only"
	}
	if ep.Kind == "static" {
		return false, "static resource is discovery-only"
	}
	if ep.Method != "GET" && (scannerName == "nuclei" || scannerName == "wapiti" || scannerName == "dalfox") {
		return false, "URL-only adapter does not preserve this HTTP method; route the request to ZAP"
	}
	switch scannerName {
	case "nuclei":
		return true, ""
	case "apichecks":
		if ep.Kind == "api" {
			return true, ""
		}
		return false, "endpoint is not classified as an API operation"
	case "zap":
		if expanded {
			return true, ""
		}
		if ep.Kind == "api" || ep.HasParameters || ep.HasForm || ep.Sensitive {
			return true, ""
		}
		return false, "endpoint has no API, parameter, form, or sensitive trait"
	case "wapiti":
		if ep.HasParameters || ep.HasForm {
			return true, ""
		}
		return false, "endpoint has no input surface"
	case "dalfox":
		for _, parameter := range ep.Parameters {
			if parameter.Location == "query" {
				return true, ""
			}
		}
		return false, "endpoint has no query parameter"
	case "nikto", "testssl":
		u, err := url.Parse(ep.URL)
		if err == nil && u.Path == "/" && u.RawQuery == "" {
			return true, ""
		}
		return false, "host-level scanner only tests the origin root"
	default:
		return false, "scanner is not endpoint-dispatched"
	}
}

// endpointHasPlaceholderPath reports whether rawURL's path still holds a
// template placeholder such as {id}, literally or percent-encoded (once or
// twice). An unparseable URL is treated as a placeholder (fail closed).
func endpointHasPlaceholderPath(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return true
	}
	for _, p := range []string{u.Path, u.EscapedPath()} {
		p = strings.ToLower(p)
		if strings.ContainsAny(p, "{}") || strings.Contains(p, "%7b") || strings.Contains(p, "%7d") {
			return true
		}
	}
	return false
}

// CompleteEndpointCoverage records run's outcome on every endpoint dispatched
// to scannerName. A completed run of a batch-evidence adapter is recorded as
// batch_completed; completed is kept for adapters with per-endpoint evidence.
func CompleteEndpointCoverage(surface *AttackSurface, scannerName string, run Run) {
	if surface == nil {
		return
	}
	status := run.Status
	if status == "not_applicable" || status == "cancelled" {
		status = "failed"
	}
	if run.Completeness == "partial" && status == "completed" {
		status = "partial"
	}
	if status == "completed" && batchEvidenceScanners[scannerName] {
		status = EndpointCoverageBatchCompleted
	}
	for i := range surface.Endpoints {
		for j := range surface.Endpoints[i].ScannerCoverage {
			coverage := &surface.Endpoints[i].ScannerCoverage[j]
			if coverage.Scanner != scannerName || coverage.Status != "dispatched" {
				continue
			}
			coverage.AttemptID, coverage.PlanFingerprint, coverage.EvidenceRef = run.AttemptID, run.PlanFingerprint, run.ArtifactPath
			coverage.Status = status
			coverage.FinishedAt = run.FinishedAt
			if run.Reason != "" {
				coverage.Reason = run.Reason
			}
			surface.Endpoints[i].CoverageHistory = append(surface.Endpoints[i].CoverageHistory, *coverage)
		}
	}
}

func setEndpointCoverage(ep *AttackSurfaceEndpoint, coverage EndpointScannerCoverage) {
	for i := range ep.ScannerCoverage {
		if ep.ScannerCoverage[i].Scanner == coverage.Scanner {
			ep.ScannerCoverage[i] = coverage
			return
		}
	}
	ep.ScannerCoverage = append(ep.ScannerCoverage, coverage)
}

func attackSurfacePath(scanDir, scope string) string {
	name := sanitizeHost(scope)
	if name == "" {
		name = "scope"
	}
	sum := sha256.Sum256([]byte(scope))
	return filepath.Join(scanDir, "attack-surface", name+"-"+hex.EncodeToString(sum[:4])+".json")
}

func SaveAttackSurface(scanDir string, surface *AttackSurface) error {
	if surface == nil {
		return nil
	}
	dst := attackSurfacePath(scanDir, surface.Scope)
	if err := storage.EnsureSecureDir(filepath.Dir(dst)); err != nil {
		return err
	}
	snapshot := *surface
	snapshot.Endpoints = append([]AttackSurfaceEndpoint(nil), surface.Endpoints...)
	if surface.WorkflowVersion == "unified-v1" {
		snapshot.Target = SafeTelemetryURL(surface.Target)
		for i := range snapshot.Endpoints {
			endpoint := &snapshot.Endpoints[i]
			clean := SafeTelemetryURL(endpoint.URL)
			if clean != endpoint.URL && endpoint.ReplayRef == "" {
				endpoint.State, endpoint.StateReason = EndpointStateUnmaterialized, "sensitive request URL requires encrypted replay"
			}
			endpoint.URL = clean
			endpoint.SPARoutes = append([]string(nil), endpoint.SPARoutes...)
			for j, route := range endpoint.SPARoutes {
				endpoint.SPARoutes[j] = SafeTelemetryURL(route)
			}
		}
	}
	data, err := json.MarshalIndent(&snapshot, "", "  ")
	if err != nil {
		return err
	}
	return storage.WriteAtomic(dst, append(data, '\n'))
}

func LoadAttackSurface(scanDir, scope, rawArtifact string) (*AttackSurface, bool) {
	data, err := os.ReadFile(attackSurfacePath(scanDir, scope))
	if err != nil {
		return nil, false
	}
	var surface AttackSurface
	if json.Unmarshal(data, &surface) != nil || (surface.SchemaVersion != AttackSurfaceSchemaVersion && surface.SchemaVersion != 1) || surface.ClassifierVersion != AttackSurfaceClassifierVersion {
		return nil, false
	}
	if rawArtifact != "" {
		raw, readErr := os.ReadFile(rawArtifact)
		if readErr != nil {
			return nil, false
		}
		sum := sha256.Sum256(raw)
		if surface.SourceChecksum != hex.EncodeToString(sum[:]) {
			return nil, false
		}
	}
	return &surface, true
}

func LoadAttackSurfaces(scanDir string) []AttackSurface {
	entries, err := os.ReadDir(filepath.Join(scanDir, "attack-surface"))
	if err != nil {
		return nil
	}
	var out []AttackSurface
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(scanDir, "attack-surface", entry.Name()))
		if readErr != nil {
			continue
		}
		var surface AttackSurface
		if json.Unmarshal(data, &surface) == nil && surface.SchemaVersion == AttackSurfaceSchemaVersion {
			out = append(out, surface)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Scope < out[j].Scope })
	return out
}

// MergeOpenAPIEndpoints adds the accepted plan's API operations to the same
// inventory used for crawl discoveries. Unresolved/state-changing operations
// remain visible but the dispatcher will not actively test them.
func MergeOpenAPIEndpoints(surface *AttackSurface, applicationURL string, endpoints []APIEndpoint) {
	if surface == nil {
		return
	}
	byID := make(map[string]int, len(surface.Endpoints))
	for i := range surface.Endpoints {
		byID[surface.Endpoints[i].ID] = i
	}
	base, err := url.Parse(applicationURL)
	if err != nil || base.Host == "" {
		return
	}
	for _, endpoint := range endpoints {
		ref, parseErr := url.Parse(endpoint.Path)
		if parseErr != nil {
			continue
		}
		resolved := base.ResolveReference(ref).String()
		ep, ok := normalizeAttackSurfaceEndpoint(resolved, endpoint.Method, endpoint.Source, time.Now().UTC().Format(time.RFC3339Nano), 0, "application/json", nil, false, false)
		if ok {
			mergeSurfaceEndpoint(surface, byID, ep)
		}
	}
}

// MergeOpenAPIEndpointsScoped keeps API operations visible in the shared
// inventory while requiring explicit scope and materialization before any
// operation can be dispatched. Placeholder operations are represented for
// review but remain non-dispatchable until inputs are supplied.
func MergeOpenAPIEndpointsScoped(surface *AttackSurface, applicationURL string, endpoints []APIEndpoint, scope *assessment.AppScope) {
	if surface == nil {
		return
	}
	byID := make(map[string]int, len(surface.Endpoints))
	for i := range surface.Endpoints {
		byID[surface.Endpoints[i].ID] = i
	}
	definitionIndex := map[string]int{}
	for i, definition := range surface.Definitions {
		definitionIndex[definition.ID] = i
	}
	for _, endpoint := range endpoints {
		if endpoint.DefinitionID == "" {
			continue
		}
		index, known := definitionIndex[endpoint.DefinitionID]
		if !known {
			index = len(surface.Definitions)
			definitionIndex[endpoint.DefinitionID] = index
			surface.Definitions = append(surface.Definitions, InventoryDefinition{ID: endpoint.DefinitionID, Kind: endpoint.Source, State: "supplied", EvidenceRef: endpoint.DefinitionID})
		}
		if scope == nil {
			continue
		}
		for _, server := range endpoint.SpecServers {
			u, err := url.Parse(server)
			if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Host == "" || strings.ContainsAny(u.Host, "{}") || (u.Scheme != "http" && u.Scheme != "https") {
				continue
			}
			if allowed, _ := scope.Allows(server); allowed {
				continue
			}
			candidates := surface.Definitions[index].CandidateOrigins
			if !slices.Contains(candidates, server) {
				surface.Definitions[index].CandidateOrigins = append(candidates, server)
			}
		}
	}
	for _, endpoint := range endpoints {
		if endpoint.Resolved && endpoint.Eligible && endpoint.RequestURL == "" {
			if _, err := apiEndpointURL(applicationURL, endpoint); err != nil {
				endpoint.Resolved, endpoint.Eligible = false, false
				endpoint.Reason = err.Error()
			}
		}
		resolved, err := openAPIInventoryURL(applicationURL, endpoint)
		if err != nil {
			continue
		}
		params := endpointParameters(resolved)
		ep, ok := normalizeAttackSurfaceEndpoint(resolved, endpoint.Method, endpoint.Source, time.Now().UTC().Format(time.RFC3339Nano), 0, "application/json", params, false, false)
		if !ok {
			continue
		}
		ep.ObservationKind = "schema"
		ep.Provenance = []EndpointProvenance{{Tool: endpoint.Source, Source: endpoint.Source, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}}
		allowed, reason := true, ""
		if scope != nil {
			allowed, reason = scope.Allows(ep.URL)
			stampEndpointState(&ep, *scope, allowed, reason)
		}
		if allowed && (scope == nil || ep.State == EndpointStateInScope) && (!endpoint.Resolved || !endpoint.Eligible) {
			ep.State = EndpointStateUnmaterialized
			ep.StateReason = endpoint.Reason
			if ep.StateReason == "" {
				ep.StateReason = "operation requires explicit inputs or approval before dispatch"
			}
		}
		mergeSurfaceEndpoint(surface, byID, ep)
	}
}

func openAPIInventoryURL(applicationURL string, endpoint APIEndpoint) (string, error) {
	if endpoint.RequestURL != "" {
		return endpoint.RequestURL, nil
	}
	if endpoint.Resolved && endpoint.Eligible {
		if resolved, err := apiEndpointURL(applicationURL, endpoint); err == nil {
			return resolved, nil
		} else if endpoint.Origin == "" {
			return "", err
		}
	}
	base, err := url.Parse(applicationURL)
	if err != nil || base.Host == "" || base.User != nil {
		return "", fmt.Errorf("invalid application URL")
	}
	if endpoint.Path == "" || !strings.HasPrefix(endpoint.Path, "/") || strings.ContainsAny(endpoint.Path, "?#\\") {
		return "", fmt.Errorf("invalid API operation path")
	}
	operationPath, err := url.PathUnescape(endpoint.Path)
	if err != nil {
		return "", fmt.Errorf("invalid API operation path")
	}
	for _, segment := range strings.Split(operationPath, "/") {
		if segment == "." || segment == ".." {
			return "", fmt.Errorf("API operation path escapes application boundary")
		}
	}
	if endpoint.Origin != "" {
		origin, parseErr := url.Parse(endpoint.Origin)
		if parseErr != nil || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" {
			return "", fmt.Errorf("invalid API operation origin")
		}
		base.Scheme, base.Host, base.Path = origin.Scheme, origin.Host, origin.Path
	}
	if endpoint.Source == "graphql" {
		// A GraphQL operation's path is the endpoint's own absolute path.
		base.Path = "/" + strings.TrimLeft(operationPath, "/")
	} else {
		base.Path = strings.TrimSuffix(base.Path, "/") + "/" + strings.TrimLeft(operationPath, "/")
	}
	base.RawPath, base.RawQuery, base.Fragment = "", "", ""
	return base.String(), nil
}
