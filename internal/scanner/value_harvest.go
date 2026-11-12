package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

// Path-value harvesting turns read-only API operations such as
// GET /common/villages/{id}, whose only missing inputs are path parameters,
// into concrete requests using values the application itself returned from a
// related list operation (GET /common/villages/all). Nothing is invented: a
// value is used only when it was observed in an in-scope, read-only response,
// and the operation records where it came from. Operations without an
// observable value keep their "missing inputs" disposition.

const (
	maxHarvestFetches   = 120
	maxHarvestBodyBytes = 1 << 20
	maxHarvestNodes     = 5000
	maxHarvestValueLen  = 128
)

var harvestPathParam = regexp.MustCompile(`\{([^{}/]+)\}`)

type harvestList struct {
	path string
	url  string
}

// HarvestPathValues returns copies of the unresolved read-only operations it
// could materialize, each with RequestURL set and ValueSource naming the list
// responses its path values came from. endpoints are the target's operations
// (plan and discovered); applicationURL is the target URL.
func HarvestPathValues(ctx context.Context, req Request, cfg Config, applicationURL string, endpoints []APIEndpoint) []APIEndpoint {
	var lists []harvestList
	seenList := map[string]bool{}
	for _, endpoint := range endpoints {
		if endpoint.Method != http.MethodGet || !endpoint.Resolved || !endpoint.Eligible || strings.Contains(endpoint.Path, "{") || endpoint.Source == "graphql" {
			continue
		}
		raw := endpoint.RequestURL
		if raw == "" {
			var err error
			if raw, err = apiEndpointURL(applicationURL, endpoint); err != nil {
				continue
			}
		}
		if !seenList[raw] {
			seenList[raw] = true
			lists = append(lists, harvestList{path: endpoint.Path, url: raw})
		}
	}
	if len(lists) == 0 {
		return nil
	}
	fetcher := &harvestFetcher{req: req, cfg: cfg, cache: map[string]any{}}
	var out []APIEndpoint
	for _, endpoint := range endpoints {
		if (endpoint.Method != http.MethodGet && endpoint.Method != http.MethodHead) || (endpoint.Resolved && endpoint.Eligible) || endpoint.RequestBodyRequired || !onlyPathInputsMissing(endpoint) {
			continue
		}
		params := harvestPathParam.FindAllStringSubmatch(endpoint.Path, -1)
		values := map[string]string{}
		var sources []string
		for _, match := range params {
			name := match[1]
			if _, done := values[name]; done {
				continue
			}
			for _, list := range candidateLists(endpoint.Path, name, lists) {
				document := fetcher.get(ctx, list.url)
				if document == nil {
					continue
				}
				if value := findHarvestValue(document, harvestKeys(name)); value != "" {
					values[name] = value
					sources = append(sources, list.url)
					break
				}
			}
			if _, found := values[name]; !found {
				break
			}
		}
		if len(values) == 0 || len(values) != len(uniqueParamNames(params)) {
			continue
		}
		concrete := harvestPathParam.ReplaceAllStringFunc(endpoint.Path, func(token string) string {
			return url.PathEscape(values[strings.Trim(token, "{}")])
		})
		probe := endpoint
		probe.Path, probe.Parameters, probe.RequestURL = concrete, nil, ""
		probe.Resolved, probe.Eligible, probe.Reason = true, true, ""
		requestURL, err := apiEndpointURL(applicationURL, probe)
		if err != nil {
			continue
		}
		materialized := endpoint
		materialized.RequestURL = requestURL
		materialized.Resolved, materialized.Eligible, materialized.Reason = true, true, ""
		materialized.MissingInputs = nil
		materialized.Parameters = nil
		materialized.ValueSource = "path values observed in the response of GET " + strings.Join(compactStrings(sources), ", GET ")
		out = append(out, materialized)
	}
	return out
}

func onlyPathInputsMissing(endpoint APIEndpoint) bool {
	if len(endpoint.MissingInputs) == 0 {
		return strings.HasPrefix(endpoint.Reason, "path parameters have no supplied values") && strings.Contains(endpoint.Path, "{")
	}
	for _, missing := range endpoint.MissingInputs {
		if !strings.HasPrefix(missing, "path:") {
			return false
		}
	}
	return true
}

func uniqueParamNames(matches [][]string) map[string]bool {
	names := map[string]bool{}
	for _, match := range matches {
		names[match[1]] = true
	}
	return names
}

// harvestBase strips identifier suffixes: gewogId -> gewog, dzongkhag_id ->
// dzongkhag, gewogCode -> gewog, thromdeName -> thromde.
func harvestBase(name string) string {
	lower := strings.ToLower(name)
	for _, suffix := range []string{"_id", "id", "_code", "code", "_name", "name", "_no", "no", "number"} {
		if len(lower) > len(suffix) && strings.HasSuffix(lower, suffix) {
			return strings.TrimRight(lower[:len(lower)-len(suffix)], "_-")
		}
	}
	return lower
}

// harvestKeys lists the response fields that can carry a value for a path
// parameter, most specific first.
func harvestKeys(name string) []string {
	keys := []string{name}
	lower := strings.ToLower(name)
	switch {
	case lower == "id":
		keys = append(keys, "uuid", "_id")
	case strings.HasSuffix(lower, "id"):
		keys = append(keys, "id")
	case strings.HasSuffix(lower, "code"):
		keys = append(keys, "code")
	case strings.HasSuffix(lower, "name"):
		keys = append(keys, "name")
	}
	return keys
}

// candidateLists orders the list operations that may contain a value for
// param in templatePath: the operation's own collection first (the path
// before the parameter, and its /all, /simple, /active variants), then for a
// foreign key such as {gewogId} the collection named after it.
func candidateLists(templatePath, param string, lists []harvestList) []harvestList {
	index := strings.Index(templatePath, "{"+param+"}")
	if index < 0 {
		return nil
	}
	prefix := strings.TrimSuffix(templatePath[:index], "/")
	type scored struct {
		list    harvestList
		score   int
		foreign bool // matched by the parameter's resource name, not the own collection
		shared  int  // words shared with the operation path
	}
	var ranked []scored
	base := harvestBase(param)
	resources := []string{}
	// A plain {id} belongs to the operation's own collection; any other name
	// ({gewogId}, {dzongkhagCode}, {slug}) may also come from a collection named
	// after it.
	if strings.ToLower(param) != "id" && base != "" {
		resources = append(resources, base, base+"s", base+"es")
		if strings.HasSuffix(base, "y") {
			resources = append(resources, strings.TrimSuffix(base, "y")+"ies")
		}
	}
	for _, list := range lists {
		score, shared := 0, 0
		switch list.path {
		case prefix:
			score = 100
		case prefix + "/all", prefix + "/simple", prefix + "/active":
			score = 90
		}
		if score == 0 && len(resources) > 0 {
			segments := strings.Split(strings.Trim(list.path, "/"), "/")
			for i, segment := range segments {
				segment = strings.ToLower(segment)
				for _, resource := range resources {
					if resource == "" {
						continue
					}
					if segment == resource || strings.HasSuffix(segment, "-"+resource) || strings.HasSuffix(segment, "_"+resource) {
						// Prefer the collection itself or its /all, /simple listing.
						rest := len(segments) - 1 - i
						candidate := 0
						if rest == 0 {
							candidate = 80
						} else if rest == 1 && (segments[i+1] == "all" || segments[i+1] == "simple" || segments[i+1] == "active") {
							candidate = 75
						} else {
							candidate = 40
						}
						// Several collections can share a name (announcement-categories,
						// office-categories): prefer the one whose other words also
						// appear in the operation's own path (office-contacts).
						words := sharedWords(segment, prefix, resource)
						candidate += 5 * words
						if candidate > score {
							score, shared = candidate, words
						}
					}
				}
			}
		}
		if score > 0 {
			ranked = append(ranked, scored{list: list, score: score, foreign: score < 90, shared: shared})
		}
	}
	// When a related collection shares words with the operation, unrelated
	// collections that merely share the resource name are not used as a
	// fallback: an announcement category is not an office category.
	specific := false
	for _, r := range ranked {
		specific = specific || (r.foreign && r.shared > 0)
	}
	if specific {
		filtered := ranked[:0]
		for _, r := range ranked {
			if !r.foreign || r.shared > 0 {
				filtered = append(filtered, r)
			}
		}
		ranked = filtered
	}
	sort.SliceStable(ranked, func(a, b int) bool { return ranked[a].score > ranked[b].score })
	out := make([]harvestList, 0, len(ranked))
	for _, r := range ranked {
		out = append(out, r.list)
	}
	if len(out) > 4 {
		out = out[:4]
	}
	return out
}

// findHarvestValue searches a JSON document breadth first for the first
// usable scalar under one of keys (exact name first, then case-insensitive).
func findHarvestValue(document any, keys []string) string {
	queue := []any{document}
	visited := 0
	for len(queue) > 0 && visited < maxHarvestNodes {
		node := queue[0]
		queue = queue[1:]
		visited++
		switch typed := node.(type) {
		case map[string]any:
			for _, key := range keys {
				if value, ok := typed[key]; ok {
					if s := harvestScalar(value); s != "" {
						return s
					}
				}
			}
			for _, key := range keys {
				for name, value := range typed {
					if strings.EqualFold(name, key) {
						if s := harvestScalar(value); s != "" {
							return s
						}
					}
				}
			}
			names := make([]string, 0, len(typed))
			for name := range typed {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				switch typed[name].(type) {
				case map[string]any, []any:
					queue = append(queue, typed[name])
				}
			}
		case []any:
			for _, item := range typed {
				switch item.(type) {
				case map[string]any, []any:
					queue = append(queue, item)
				}
			}
		}
	}
	return ""
}

func harvestScalar(value any) string {
	var s string
	switch typed := value.(type) {
	case string:
		s = strings.TrimSpace(typed)
	case json.Number:
		s = typed.String()
	default:
		return ""
	}
	if s == "" || len(s) > maxHarvestValueLen || s == "." || s == ".." || strings.ContainsAny(s, "/\\?#%\r\n\x00 ") {
		return ""
	}
	return s
}

type harvestFetcher struct {
	req     Request
	cfg     Config
	cache   map[string]any
	fetches int
}

// get performs one read-only GET of an in-scope list operation (with the
// target's verified session on its own origin) and returns its parsed JSON,
// or nil. Results are cached; at most maxHarvestFetches requests are sent.
func (f *harvestFetcher) get(ctx context.Context, raw string) any {
	if document, ok := f.cache[raw]; ok {
		return document
	}
	f.cache[raw] = nil
	if f.fetches >= maxHarvestFetches || browserRequestAllowed(f.req, f.cfg, http.MethodGet, raw) != nil {
		return nil
	}
	if err := f.cfg.Budget.Wait(ctx); err != nil {
		return nil
	}
	f.fetches++
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil
	}
	request.Header.Set("Accept", "application/json")
	bound, _ := assessment.ParseApprovedOrigin("", f.req.Target)
	origin, _ := assessment.ParseApprovedOrigin("", raw)
	if bound.Scheme == origin.Scheme && bound.Host == origin.Host && bound.Port == origin.Port {
		for _, line := range strings.Split(f.req.TargetAuth, "\n") {
			if name, value, ok := strings.Cut(line, ":"); ok {
				request.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
			}
		}
	}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return nil
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxHarvestBodyBytes+1))
	if err != nil || len(body) > maxHarvestBodyBytes || response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var document any
	if decoder.Decode(&document) != nil {
		return nil
	}
	f.cache[raw] = document
	return document
}

// sharedWords counts the words of a collection segment, other than the
// resource word itself, that also appear in the operation path. Plural "s" is
// ignored, so quick-link-categories shares "quick" and "link" with
// /common/quick-links/category.
func sharedWords(segment, operationPath, resource string) int {
	split := func(s string) []string {
		return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return r == '-' || r == '_' || r == '/' })
	}
	singular := func(w string) string {
		if strings.HasSuffix(w, "ies") {
			return strings.TrimSuffix(w, "ies") + "y"
		}
		return strings.TrimSuffix(w, "s")
	}
	words := map[string]bool{}
	for _, w := range split(operationPath) {
		words[singular(w)] = true
	}
	shared := 0
	for _, w := range split(segment) {
		if w == resource || singular(w) == singular(resource) {
			continue
		}
		if words[singular(w)] {
			shared++
		}
	}
	return shared
}
