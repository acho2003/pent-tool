package scanner

import (
	"strings"
	"testing"
)

func TestNextjsDevModeDetection(t *testing.T) {
	req := Request{Target: "https://app.example.test/"}
	endpoint := "https://app.example.test/"

	// A React Fast Refresh runtime reference is a definitive dev-mode marker.
	refresh := nextjsDevModeFindings(req, endpoint,
		`<html><head><script src="/_next/static/chunks/react-refresh.js"></script></head></html>`, "abc123", "ev")
	if len(refresh) != 1 || refresh[0].RuleID != "nextjs-development-mode" || refresh[0].Severity != "high" {
		t.Fatalf("react-refresh not reported as high dev-mode finding: %+v", refresh)
	}

	// buildId "development" alone is definitive.
	devBuild := nextjsDevModeFindings(req, endpoint, "<html><body>x</body></html>", "development", "ev")
	if len(devBuild) != 1 || devBuild[0].Severity != "high" {
		t.Fatalf("buildId development not flagged as high: %+v", devBuild)
	}

	// A clean production page yields nothing.
	if f := nextjsDevModeFindings(req, endpoint, "<html><body>prod</body></html>", "k9fJ2x", "ev"); len(f) != 0 {
		t.Fatalf("production page flagged: %+v", f)
	}

	// Evidence must describe markers, not dump raw HTML.
	if strings.Contains(refresh[0].Evidence, "<script") {
		t.Fatalf("raw HTML leaked into evidence: %q", refresh[0].Evidence)
	}
}
