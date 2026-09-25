package scanner

import (
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// FindingSource is one scanner's report of a finding that cross-scanner merge
// collapsed into a single record. It keeps every contributor traceable to its
// own native evidence.
type FindingSource struct {
	Scanner     string `json:"scanner"`
	SourceID    string `json:"source_id"`
	Endpoint    string `json:"endpoint,omitempty"`
	EvidenceRef string `json:"evidence_reference"`
}

var singleCVEPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// singleCVE returns s upper-cased when it is exactly one well-formed CVE ID, and
// "" otherwise, so lists and non-CVE identifiers never drive a merge.
func singleCVE(s string) string {
	c := strings.ToUpper(strings.TrimSpace(s))
	if singleCVEPattern.MatchString(c) {
		return c
	}
	return ""
}

func severityRank(s string) int {
	switch severity(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func sourceOf(f Finding) FindingSource {
	return FindingSource{Scanner: f.Scanner, SourceID: f.SourceID, Endpoint: f.Endpoint, EvidenceRef: f.EvidenceRef}
}

// mergeLocation is the extra merge-key component that keeps one CVE in two
// files of a source tree apart: the file (Target) on source scopes, nothing on
// host scopes (where different scanners describe the location differently —
// a URL vs a port — so the scope alone identifies the asset).
func mergeLocation(f Finding) string {
	if strings.HasPrefix(f.Scope, "source:") {
		return filepath.ToSlash(filepath.Clean(f.Target))
	}
	return ""
}

// mergeCrossScanner collapses findings that report the same CVE on the same
// scope (and, on a source scope, the same file) from different scanners (e.g.
// openvas and nuclei both flagging one CVE on one host, or trivy and osv both
// flagging one CVE in one lockfile) into one finding that lists every source.
// The first-seen contributor stays the primary record, keeping its SourceID and
// EvidenceRef, so the report's source-ID trace is unchanged. Severity and CVSS
// are raised to the highest any contributor reported, so a merge never
// downgrades a finding. A scanner's own repeated reports (e.g. trivy flagging
// one CVE in two lockfiles) stay separate. Output keeps first-seen order.
func mergeCrossScanner(in []Finding) []Finding {
	primary := map[string]int{} // scope\x00CVE -> index in out
	out := make([]Finding, 0, len(in))
	for _, f := range in {
		cve := singleCVE(f.CVE)
		if cve == "" {
			out = append(out, f)
			continue
		}
		key := f.Scope + "\x00" + cve + "\x00" + mergeLocation(f)
		i, ok := primary[key]
		if !ok {
			primary[key] = len(out)
			out = append(out, f)
			continue
		}
		m := &out[i]
		if m.Scanner == f.Scanner || slices.ContainsFunc(m.Sources, func(s FindingSource) bool { return s.Scanner == f.Scanner }) {
			out = append(out, f)
			continue
		}
		if len(m.Sources) == 0 {
			m.Sources = []FindingSource{sourceOf(*m)}
		}
		m.Sources = append(m.Sources, sourceOf(f))
		// An unrated placeholder never raises a rating; a rated contributor
		// replaces an unrated primary's placeholder outright.
		switch {
		case f.SeverityUnrated:
		case m.SeverityUnrated:
			m.Severity, m.SeverityUnrated = f.Severity, false
		case severityRank(f.Severity) > severityRank(m.Severity):
			m.Severity = f.Severity
		}
		if f.CVSS > m.CVSS {
			m.CVSS = f.CVSS
		}
		if m.CWE == "" {
			m.CWE = f.CWE
		}
	}
	return out
}
