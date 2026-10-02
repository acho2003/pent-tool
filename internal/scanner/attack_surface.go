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
	"sort"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/storage"
)

const (
	AttackSurfaceSchemaVersion     = 1
	AttackSurfaceClassifierVersion = 1
)

type EndpointParameter struct {
	Name     string `json:"name"`
	Location string `json:"location"`
}

type EndpointScannerCoverage struct {
	Scanner    string `json:"scanner"`
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
	StartedAt  string `json:"started_at,omitempty"`
	FinishedAt string `json:"finished_at,omitempty"`
}

// AttackSurfaceEndpoint is one normalized request surface. URL is a concrete,
// in-scope sample used by scanners; CanonicalURL is the stable identity with
// query values replaced by placeholders. A fragment is metadata only and never
// participates in the HTTP request identity.
type AttackSurfaceEndpoint struct {
	ID               string                    `json:"id"`
	URL              string                    `json:"url"`
	CanonicalURL     string                    `json:"canonical_url"`
	Method           string                    `json:"method"`
	Path             string                    `json:"path"`
	SPARoutes        []string                  `json:"spa_routes,omitempty"`
	Kind             string                    `json:"kind"`
	Sources          []string                  `json:"sources,omitempty"`
	Parameters       []EndpointParameter       `json:"parameters,omitempty"`
	StatusCode       int                       `json:"status_code,omitempty"`
	ContentType      string                    `json:"content_type,omitempty"`
	Sensitive        bool                      `json:"sensitive,omitempty"`
	HasParameters    bool                      `json:"has_parameters,omitempty"`
	HasForm          bool                      `json:"has_form,omitempty"`
	ObservedWithAuth bool                      `json:"observed_with_auth,omitempty"`
	RequiresAuth     *bool                     `json:"requires_auth,omitempty"`
	DiscoveredAt     string                    `json:"discovered_at,omitempty"`
	ScannerCoverage  []EndpointScannerCoverage `json:"scanner_coverage,omitempty"`
}

type AttackSurface struct {
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
	if ep, ok := normalizeAttackSurfaceEndpoint(target, "GET", "seed", surface.GeneratedAt, 0, "", nil, false, false); ok {
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
	if ep, ok := normalizeAttackSurfaceEndpoint(target, "GET", "seed", surface.GeneratedAt, 0, "", nil, false, false); ok {
		mergeSurfaceEndpoint(surface, byID, ep)
	}
}

// ParseKatanaAttackSurface tolerates malformed JSONL rows and returns every
// usable request record, normalized and deduplicated in discovery order.
func ParseKatanaAttackSurface(artifact, scope, target string, observedWithAuth bool) (*AttackSurface, error) {
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
	// (external links like owasp.org, CDN fonts). Those must never enter the
	// attack surface or be dispatched to scanners, so keep only endpoints on the
	// assessed host. An empty target disables the filter.
	targetHost := hostFromTarget(target)
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
			continue
		}
		request, _ := raw["request"].(map[string]any)
		response, _ := raw["response"].(map[string]any)
		endpoint := firstStringValue(request, "endpoint", "url")
		if endpoint == "" {
			endpoint = firstStringValue(raw, "endpoint", "url")
		}
		method := firstStringValue(request, "method")
		tag := firstStringValue(request, "tag")
		source := firstStringValue(request, "source")
		if source == "" {
			source = "katana"
		}
		status := intValue(response["status_code"])
		contentType := headerValue(response["headers"], "content-type")
		params := endpointParameters(endpoint)
		params = append(params, bodyParameters(firstStringValue(request, "body"), headerValue(request["headers"], "content-type"))...)
		hasForm := strings.EqualFold(tag, "form")
		if hasForm {
			for i := range params {
				if params[i].Location == "body" {
					params[i].Location = "form"
				}
			}
		}
		if endpoint != "" && inSurfaceHostScope(endpoint, targetHost) {
			if ep, ok := normalizeAttackSurfaceEndpoint(endpoint, method, source, firstStringValue(raw, "timestamp"), status, contentType, params, hasForm, observedWithAuth); ok {
				mergeSurfaceEndpoint(surface, byID, ep)
			}
		}
		// Katana versions have emitted form extraction at both the top level and
		// under response. Decode generically so upgrades do not make forms vanish.
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
			if !inSurfaceHostScope(action, targetHost) {
				continue
			}
			formParams := formParameters(form)
			if ep, ok := normalizeAttackSurfaceEndpoint(action, firstStringValue(form, "method"), source, firstStringValue(raw, "timestamp"), 0, "", formParams, true, observedWithAuth); ok {
				mergeSurfaceEndpoint(surface, byID, ep)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return surface, nil
}

// inSurfaceHostScope reports whether rawURL is on the assessed host, so the
// crawl stays scoped and off-host links are dropped before scanning. An empty
// targetHost disables the filter (keep everything).
func inSurfaceHostScope(rawURL, targetHost string) bool {
	if targetHost == "" {
		return true
	}
	return strings.EqualFold(hostFromTarget(rawURL), targetHost)
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
	hash := sha256.Sum256([]byte(method + "\x00" + canonical))
	requiresAuth := (*bool)(nil)
	if status == 401 || status == 403 {
		v := true
		requiresAuth = &v
	}
	ep := AttackSurfaceEndpoint{
		ID: hex.EncodeToString(hash[:12]), URL: observed, CanonicalURL: canonical, Method: method,
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
	cleaned := path.Clean("/" + strings.TrimLeft(u.Path, "/"))
	if cleaned == "." || cleaned == "" {
		cleaned = "/"
	}
	if cleaned != "/" {
		cleaned = strings.TrimSuffix(cleaned, "/")
	}
	u.Path, u.RawPath = cleaned, ""
	endpointPath = cleaned
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", "", "", "", false
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	observedQuery := url.Values{}
	canonicalParts := make([]string, 0, len(keys))
	for _, key := range keys {
		vals := values[key]
		if len(vals) == 0 {
			vals = []string{""}
		}
		for _, value := range vals {
			observedQuery.Add(key, value)
		}
		canonicalParts = append(canonicalParts, url.QueryEscape(key)+"={value}")
	}
	u.RawQuery = observedQuery.Encode()
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
		return
	}
	byID[incoming.ID] = len(surface.Endpoints)
	surface.Endpoints = append(surface.Endpoints, incoming)
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
// deterministic decision on every endpoint.
func DispatchTargets(surface *AttackSurface, scannerName string, max int) []string {
	if surface == nil {
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	seen := map[string]bool{}
	var targets []string
	for i := range surface.Endpoints {
		ep := &surface.Endpoints[i]
		eligible, reason := endpointEligibleForScanner(*ep, scannerName)
		status := "skipped"
		if eligible && (max <= 0 || len(targets) < max) {
			status = "dispatched"
			if !seen[ep.URL] {
				seen[ep.URL] = true
				targets = append(targets, ep.URL)
			}
		} else if eligible {
			reason = "endpoint budget exhausted"
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
	switch scannerName {
	case "wapiti":
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

func endpointEligibleForScanner(ep AttackSurfaceEndpoint, scannerName string) (bool, string) {
	safeMethod := ep.Method == "GET" || ep.Method == "HEAD"
	if !safeMethod {
		return false, "unsafe or state-changing method is inventory-only"
	}
	if ep.Kind == "static" {
		return false, "static resource is discovery-only"
	}
	switch scannerName {
	case "nuclei":
		return true, ""
	case "zap":
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

func CompleteEndpointCoverage(surface *AttackSurface, scannerName string, run Run) {
	if surface == nil {
		return
	}
	status := run.Status
	if status == "not_applicable" || status == "cancelled" {
		status = "failed"
	}
	for i := range surface.Endpoints {
		for j := range surface.Endpoints[i].ScannerCoverage {
			coverage := &surface.Endpoints[i].ScannerCoverage[j]
			if coverage.Scanner != scannerName || coverage.Status != "dispatched" {
				continue
			}
			coverage.Status = status
			coverage.FinishedAt = run.FinishedAt
			if run.Reason != "" {
				coverage.Reason = run.Reason
			}
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
	data, err := json.MarshalIndent(surface, "", "  ")
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
	if json.Unmarshal(data, &surface) != nil || surface.SchemaVersion != AttackSurfaceSchemaVersion || surface.ClassifierVersion != AttackSurfaceClassifierVersion {
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
