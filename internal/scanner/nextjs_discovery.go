package scanner

import (
	"bytes"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"golang.org/x/net/html"
)

// These are candidate extractors, not JavaScript or flight protocol parsers.
// Only explicit static asset references are fetched; API strings remain seeds.
var nextjsAssetReference = regexp.MustCompile(`["']([^"'\s<>]*?/_next/static/[^"'\s<>]+\.(?:m?js))["']`)
var nextjsAPIReference = regexp.MustCompile(`["'](/(?:[^"'\s<>/]+/)*api/[^"'\s<>]*)["']`)

type nextjsPageReferences struct {
	Scripts []string
	Links   []string
}

func nextjsHTMLReferences(base *url.URL, body []byte) nextjsPageReferences {
	var refs nextjsPageReferences
	document, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return refs
	}
	resolve := func(raw string) string {
		u, err := base.Parse(strings.TrimSpace(raw))
		if err != nil || u.User != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return ""
		}
		u.Fragment, u.RawFragment = "", ""
		return u.String()
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			attrs := map[string]string{}
			for _, a := range n.Attr {
				attrs[a.Key] = a.Val
			}
			switch n.Data {

			case "script", "link":
				raw := attrs["src"]
				if n.Data == "link" {
					if attrs["rel"] != "modulepreload" && !(attrs["rel"] == "preload" && attrs["as"] == "script") {
						break
					}
					raw = attrs["href"]
				}
				if u := resolve(raw); raw != "" && u != "" {
					parsed, _ := url.Parse(u)
					if strings.Contains(parsed.Path, "/_next/static/") && (path.Ext(parsed.Path) == ".js" || path.Ext(parsed.Path) == ".mjs") {
						refs.Scripts = append(refs.Scripts, u)
					}
				}
			case "a":
				if u := resolve(attrs["href"]); attrs["href"] != "" && u != "" {
					refs.Links = append(refs.Links, u)
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(document)
	// Literal asset URLs also occur in App Router inline bootstrap/flight data.
	for _, match := range nextjsAssetReference.FindAllSubmatch(body, nextjsMaxRoutes) {
		if u := resolve(string(match[1])); u != "" {
			refs.Scripts = append(refs.Scripts, u)
		}
	}
	refs.Scripts = uniqueNextjsURLs(refs.Scripts)
	refs.Links = uniqueNextjsURLs(refs.Links)
	return refs
}

func nextjsURLCandidate(req Request, raw, source string) HistoricalCandidate {
	c := HistoricalCandidate{URL: raw, Provider: "nextjs-assets", Source: source, State: EndpointStateHistoricalUnverified, Reason: "referenced candidate; not requested"}
	u, err := url.Parse(raw)
	switch {
	case err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https"):
		c.State, c.Reason = EndpointStateOutOfScope, "invalid HTTP(S) destination"
	case !nextjsAllows(req, raw):
		c.State, c.Reason = EndpointStateOutOfScope, "destination is outside approved scope"
	case nextjsExcluded(req, raw):
		c.State, c.Reason = EndpointStateExcluded, "destination is excluded"
	case strings.ContainsAny(u.Path, "[]"):
		c.State, c.Reason = EndpointStateUnmaterialized, "dynamic route needs an observed or supplied value"
	case nextjsUnsafeRouteName.MatchString(u.Path):
		c.Reason = "not requested: the route name suggests a GET may change state"
	}
	return c
}

func nextjsPageEligible(req Request, cfg Config, raw string) bool {
	c := nextjsURLCandidate(req, raw, "html_link")
	if c.State != EndpointStateHistoricalUnverified || strings.HasPrefix(c.Reason, "not requested:") {
		return false
	}
	u, _ := url.Parse(raw)
	// Crawl pages, not downloads, arbitrary API calls, or destructive GET routes.
	ext := strings.ToLower(path.Ext(u.Path))
	return (ext == "" || ext == ".html") && !strings.Contains(u.Path, "/api/") && browserRequestAllowed(req, cfg, http.MethodGet, raw) == nil
}

func nextjsLimits(req Request) assessment.NextjsScanOptions {
	limits := assessment.NextjsScanOptions{MaxPages: 1, MaxScripts: nextjsMaxScripts, MaxRouteChecks: nextjsMaxRouteChecks, MaxRequests: 300, MaxResponseBytes: 32 << 20}
	if req.Profile == ProfileNextjsDeep {
		limits.MaxPages = 25
		limits.MaxScripts = 120
		limits.MaxRouteChecks = 200
		limits.MaxRequests = 600
		limits.MaxResponseBytes = 64 << 20
	}
	// Clamp direct runner callers as well as validating API assessment input.
	if req.Nextjs.MaxPages > 0 {
		limits.MaxPages = min(req.Nextjs.MaxPages, 250)
	}
	if req.Nextjs.MaxScripts > 0 {
		limits.MaxScripts = min(req.Nextjs.MaxScripts, 500)
	}
	if req.Nextjs.MaxRouteChecks > 0 {
		limits.MaxRouteChecks = min(req.Nextjs.MaxRouteChecks, 500)
	}
	if req.Nextjs.MaxRequests > 0 {
		limits.MaxRequests = min(req.Nextjs.MaxRequests, 5000)
	}
	if req.Nextjs.MaxResponseBytes > 0 {
		limits.MaxResponseBytes = min(req.Nextjs.MaxResponseBytes, 256<<20)
	}
	return limits
}

func uniqueNextjsURLs(values []string) []string {
	var result []string
	for _, value := range values {
		if !slices.Contains(result, value) {
			result = append(result, value)
		}
	}
	return result
}
