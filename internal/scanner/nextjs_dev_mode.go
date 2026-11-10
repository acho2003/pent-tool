package scanner

import (
	"fmt"
	"net/http"
	"strings"
)

// Detection-only Next.js development-mode exposure. A production deployment
// left in development mode ships unminified source and source maps, exposes the
// dev error overlay (which can reveal server-side source and stack frames),
// enables hot-module replacement, and runs without production hardening. Every
// signal here comes from the landing HTML that nextjs-assets already fetched, so
// there is no extra request and no payload is sent — these are markers Next.js
// itself emits only in a dev build.

type devModeMarker struct {
	token string
	desc  string
	// A definitive marker alone establishes development mode; the others only
	// corroborate it.
	definitive bool
}

var nextjsDevModeMarkers = []devModeMarker{
	{"/_next/static/development/", "development static asset path", true},
	{"react-refresh", "React Fast Refresh runtime (development only)", true},
	{"webpack-hmr", "hot-module-replacement endpoint", true},
	{"__nextjs_original-stack-frame", "development error-overlay stack-frame endpoint", true},
	{"next/dist/compiled/react-refresh", "compiled React Fast Refresh module", true},
	{"__next_dev", "Next.js development runtime marker", false},
}

// nextjsDevModeFindings inspects already-fetched landing HTML for markers that
// only appear in a Next.js development build. buildID is the value already
// parsed from the page. The evidence names the matched markers only.
func nextjsDevModeFindings(req Request, endpoint, html, buildID, evidenceRef string) []Finding {
	lower := strings.ToLower(html)
	var matched []string
	definitive := false
	if strings.EqualFold(strings.TrimSpace(buildID), "development") {
		matched = append(matched, `__NEXT_DATA__ buildId is "development"`)
		definitive = true
	}
	for _, m := range nextjsDevModeMarkers {
		if strings.Contains(lower, m.token) {
			matched = append(matched, m.desc)
			if m.definitive {
				definitive = true
			}
		}
	}
	if len(matched) == 0 {
		return nil
	}
	severity := "medium"
	if definitive {
		severity = "high"
	}
	safe := SafeTelemetryURL(endpoint)
	return []Finding{{
		SourceID: nextjsSourceID("nextjs-development-mode", endpoint), Scanner: "nextjs-assets", RuleID: "nextjs-development-mode",
		Title: "Next.js application appears to run in development mode", Severity: severity, Target: req.Target, Endpoint: safe, Method: http.MethodGet,
		Description: "The served page carries markers that Next.js emits only in a development build. A production site running in development mode ships unminified source and source maps, exposes the development error overlay (which can reveal server-side source and stack frames), enables hot-module replacement, and runs without production hardening or performance optimization.",
		Evidence:    fmt.Sprintf("Development indicators at %s: %s.", safe, strings.Join(dedupeStrings(matched), "; ")),
		Remediation: "Build and serve the application in production mode (`next build` then `next start`, or the platform's production deployment). Never expose a `next dev` process to the public.",
		CWE:         "CWE-489", Confidence: "confirmed", EvidenceRef: evidenceRef,
	}}
}
