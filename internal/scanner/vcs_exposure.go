package scanner

import (
	"bytes"
	"context"
	"net/http"
	"regexp"
	"strings"
)

// vcsCatalogVersion is part of the plan fingerprint. Keep the catalog small.
const vcsCatalogVersion = "vcs-exposure-v1"

type vcsExposureRunner struct{}

func (vcsExposureRunner) Name() string { return "vcs-exposure" }
func (vcsExposureRunner) Descriptor() Descriptor {
	return Descriptor{Name: "vcs-exposure", Summary: "Bounded read-only exposed source-control metadata checks", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightLight}
}

func (vcsExposureRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	return runExposureCatalog(ctx, req, cfg, emit, "vcs-exposure", vcsCatalogVersion, "exposed source-control metadata", vcsCatalog, classifyVCS)
}

// vcsCatalog probes for source-control metadata directories served to the web.
// When present these let an attacker reconstruct the application source and its
// history (and sometimes credentials embedded in a remote URL). Every probe is a
// read-only GET for a single marker file, not a recursive download.
var vcsCatalog = []exposureCheck{
	{ID: "git-head", Path: "/.git/HEAD", Purpose: "Exposed Git repository HEAD"},
	{ID: "git-config", Path: "/.git/config", Purpose: "Exposed Git repository config"},
	{ID: "git-index", Path: "/.git/index", Purpose: "Exposed Git index"},
	{ID: "git-logs-head", Path: "/.git/logs/HEAD", Purpose: "Exposed Git reflog"},
	{ID: "git-packed-refs", Path: "/.git/packed-refs", Purpose: "Exposed Git packed refs"},
	{ID: "svn-entries", Path: "/.svn/entries", Purpose: "Exposed Subversion entries"},
	{ID: "svn-wcdb", Path: "/.svn/wc.db", Purpose: "Exposed Subversion working-copy database"},
	{ID: "hg-requires", Path: "/.hg/requires", Purpose: "Exposed Mercurial requires"},
	{ID: "bzr-branch", Path: "/.bzr/branch-format", Purpose: "Exposed Bazaar branch format"},
}

var (
	gitHeadRef = regexp.MustCompile(`(?m)^ref:\s+refs/`)
	gitSHALine = regexp.MustCompile(`(?m)^[0-9a-f]{40,64}\b`)
)

// classifyVCS requires the response body to match the raw metadata file's
// signature, not merely return HTTP 200. A single-page app or a custom 404 page
// that answers every path with 200 HTML must not be reported as a repository.
func classifyVCS(check exposureCheck, resp *http.Response, body []byte) exposureVerdict {
	if resp.StatusCode != http.StatusOK {
		return exposureVerdict{}
	}
	trimmed := bytes.TrimSpace(body)
	lower := strings.ToLower(string(trimmed))
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	// An HTML body is a catch-all page, never a raw VCS metadata file.
	if strings.Contains(ct, "text/html") || strings.HasPrefix(lower, "<!doctype html") || strings.HasPrefix(lower, "<html") {
		return exposureVerdict{}
	}
	source := func(sev string) exposureVerdict {
		return exposureVerdict{Classification: "source_control_exposed", Severity: sev, Title: "Exposed source-control metadata allows source reconstruction"}
	}
	switch check.ID {
	case "git-head":
		if gitHeadRef.Match(trimmed) || gitSHALine.Match(trimmed) {
			return source("high")
		}
	case "git-config":
		if strings.Contains(lower, "[core]") && strings.Contains(lower, "repositoryformatversion") {
			return source("high")
		}
	case "git-index":
		if bytes.HasPrefix(trimmed, []byte("DIRC")) {
			return source("high")
		}
	case "git-logs-head":
		if gitSHALine.Match(trimmed) && strings.Contains(lower, "commit") {
			return source("high")
		}
	case "git-packed-refs":
		if strings.Contains(lower, "# pack-refs") || strings.Contains(lower, "refs/") {
			return source("medium")
		}
	case "svn-entries":
		if strings.HasPrefix(lower, "8\n") || strings.HasPrefix(lower, "9\n") || strings.HasPrefix(lower, "10\n") || strings.HasPrefix(lower, "11\n") || strings.HasPrefix(lower, "12\n") || strings.Contains(lower, "svn://") || strings.Contains(lower, "has-props") {
			return source("high")
		}
	case "svn-wcdb":
		if bytes.HasPrefix(trimmed, []byte("SQLite format 3")) {
			return source("high")
		}
	case "hg-requires":
		if strings.Contains(lower, "revlog") || strings.Contains(lower, "dotencode") || strings.Contains(lower, "store") || strings.Contains(lower, "fncache") {
			return source("high")
		}
	case "bzr-branch":
		if strings.Contains(lower, "bazaar") {
			return source("high")
		}
	}
	return exposureVerdict{}
}
