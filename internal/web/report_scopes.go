package web

import (
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

// reportScope is one host or source block of a scanner report: what it is, the
// classifier's tracks for it, what recon found on it, and the terminal status
// every tool recorded there, so the report accounts for every scope x tool.
type reportScope struct {
	ID        string           `json:"id"`
	Kind      string           `json:"kind"`
	Target    string           `json:"target,omitempty"`
	Origin    string           `json:"origin,omitempty"`
	Tracks    []string         `json:"tracks,omitempty"`
	OpenPorts []string         `json:"open_ports,omitempty"`
	Services  []string         `json:"services,omitempty"`
	LiveURLs  []string         `json:"live_urls,omitempty"`
	Runs      []reportScopeRun `json:"runs"`
}

type reportScopeRun struct {
	Scanner string `json:"scanner"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
}

// reportReconSummary is the scan-wide recon rollup shown above the per-scope
// coverage blocks.
type reportReconSummary struct {
	Hosts     int      `json:"hosts"`
	OpenPorts int      `json:"open_ports"`
	Services  []string `json:"services,omitempty"`
}

// reportScopeID is the scope a run belongs to: the same scope its findings are
// stamped with (a pre-scope run folds to the implicit host scope; a per-host
// nmap recon run belongs to that host).
func reportScopeID(run scanner.Run) string {
	return scanner.FindingScope(run)
}

// reportScopeTarget is the target a run contributes to its report scope. A run
// folded into a host scope from another scope (a per-host nmap recon run, whose
// Target is the request target) contributes the host itself.
func reportScopeTarget(run scanner.Run, id string) string {
	if run.Scope != "" && run.Scope != id {
		return strings.TrimPrefix(id, "host:")
	}
	return run.Target
}

// buildReportScopes derives the report's scope list from the scan's runs and the
// recon-scopes.json persisted under scanDir. Recon-phase runs are excluded (they
// are summarized, not scoped). Host scopes keep first-seen run order; the
// source scope always comes last. Tracks use scanner.EffectiveTracks, the same
// fail-open rule the pipeline scanned with.
func buildReportScopes(scanDir string, runs []scanner.Run) []reportScope {
	evidence := map[string]scanner.HostEvidence{}
	if persisted, ok := scanner.LoadReconScopes(scanDir); ok {
		for _, sc := range persisted {
			evidence[sc.ID] = sc.Evidence
		}
	}
	sourceScope, hasSourceScope := scanner.LoadSourceScope(scanDir)
	var out []reportScope
	index := map[string]int{}
	for _, run := range runs {
		id := reportScopeID(run)
		if strings.HasPrefix(id, "recon:") {
			continue
		}
		i, ok := index[id]
		if !ok {
			rs := reportScope{ID: id, Kind: string(scanner.ScopeHost), Target: reportScopeTarget(run, id)}
			if strings.HasPrefix(id, "source:") {
				rs.Kind = string(scanner.ScopeSource)
				if hasSourceScope && sourceScope.ID == id {
					rs.Origin = sourceOrigin(sourceScope)
				}
			} else {
				ev := evidence[id]
				for _, t := range scanner.EffectiveTracks(ev) {
					rs.Tracks = append(rs.Tracks, string(t))
				}
				for _, p := range ev.OpenPorts {
					rs.OpenPorts = append(rs.OpenPorts, formatReportPort(p))
					if svc := strings.TrimSpace(p.Service); svc != "" && !slices.Contains(rs.Services, svc) {
						rs.Services = append(rs.Services, svc)
					}
				}
				sort.Strings(rs.Services)
				rs.LiveURLs = append([]string(nil), ev.LiveURLs...)
			}
			i = len(out)
			index[id] = i
			out = append(out, rs)
		}
		if out[i].Target == "" {
			out[i].Target = reportScopeTarget(run, id)
		}
		out[i].Runs = append(out[i].Runs, reportScopeRun{Scanner: run.Scanner, Status: run.Status, Reason: run.Reason})
	}
	sort.SliceStable(out, func(a, b int) bool {
		return out[a].Kind != string(scanner.ScopeSource) && out[b].Kind == string(scanner.ScopeSource)
	})
	return out
}

// sourceOrigin is how the report names a source scope: the repository it was
// cloned from (credentials removed), or the directory the operator provided.
// Empty when no source resolved.
func sourceOrigin(sc scanner.Scope) string {
	prov := sc.Source.Provenance
	if u, ok := strings.CutPrefix(prov, "clone:"); ok {
		return redactURL(u)
	}
	if prov == "provided:filesystem" {
		return sc.Source.Path
	}
	return ""
}

// redactURL drops any userinfo (e.g. a token in https://user:tok@host/...) from
// a URL. Non-URL forms such as scp-style git@host:path are returned unchanged.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.User == nil {
		return raw
	}
	u.User = nil
	return u.String()
}

func formatReportPort(p scanner.Port) string {
	s := fmt.Sprintf("%d/%s", p.Number, firstNonBlank(p.Protocol, "tcp"))
	if svc := strings.Join(strings.Fields(p.Service+" "+p.Product), " "); svc != "" {
		s += " " + svc
	}
	return s
}

// summarizeReportRecon rolls host scopes up into hosts discovered, open ports,
// and the sorted distinct detected services.
func summarizeReportRecon(scopes []reportScope) reportReconSummary {
	var sum reportReconSummary
	for _, sc := range scopes {
		if sc.Kind != string(scanner.ScopeHost) {
			continue
		}
		sum.Hosts++
		sum.OpenPorts += len(sc.OpenPorts)
		for _, svc := range sc.Services {
			if !slices.Contains(sum.Services, svc) {
				sum.Services = append(sum.Services, svc)
			}
		}
	}
	sort.Strings(sum.Services)
	return sum
}

// orderReportFindings sorts findings in place by scope (report scope order,
// unknown scopes last), then severity (highest first), then source ID, a total
// order so the report is deterministic.
func orderReportFindings(findings []reportFinding, scopes []reportScope) {
	rank := make(map[string]int, len(scopes))
	for i, sc := range scopes {
		rank[sc.ID] = i
	}
	pos := func(id string) int {
		if r, ok := rank[id]; ok {
			return r
		}
		return len(scopes)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if pa, pb := pos(a.Scope), pos(b.Scope); pa != pb {
			return pa < pb
		}
		if ra, rb := severityRankValue(a.Severity), severityRankValue(b.Severity); ra != rb {
			return ra > rb
		}
		return a.SourceID < b.SourceID
	})
}
