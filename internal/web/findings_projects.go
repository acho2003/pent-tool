package web

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

type findingsProjectScan struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	Target           string         `json:"target"`
	ParentTarget     string         `json:"parent_target,omitempty"`
	StartedAt        string         `json:"started_at"`
	Status           string         `json:"status"`
	FindingCount     int            `json:"finding_count"`
	ActiveCount      int            `json:"active_count"`
	ObservationCount int            `json:"observation_count"`
	Severity         map[string]int `json:"severity"`
}

type findingsProject struct {
	ID               string                `json:"id"`
	Label            string                `json:"label"`
	LatestAt         string                `json:"latest_at"`
	ScanCount        int                   `json:"scan_count"`
	FindingCount     int                   `json:"finding_count"`
	ActiveCount      int                   `json:"active_count"`
	ObservationCount int                   `json:"observation_count"`
	Severity         map[string]int        `json:"severity"`
	Scans            []findingsProjectScan `json:"scans"`
}

func emptyFindingSeverity() map[string]int {
	return map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
}

// A project is a view over saved scan targets, not a separate persisted object.
// Wildcard children inherit their recorded parent; independent subdomains do not.
func findingsProjectIdentity(rec ScanRecord) (string, string) {
	target := strings.TrimSpace(rec.Target)
	if strings.TrimSpace(rec.ParentTarget) != "" {
		target = strings.TrimSpace(rec.ParentTarget)
	}
	if parsed, err := url.Parse(target); err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Hostname() != "" {
		host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
		return "host:" + host, host
	}
	if ip := net.ParseIP(strings.Trim(target, "[]")); ip != nil {
		return "host:" + ip.String(), ip.String()
	}
	if _, network, err := net.ParseCIDR(target); err == nil {
		return "host:" + network.String(), network.String()
	}
	if !strings.ContainsAny(target, "/@\\") {
		host := strings.TrimSuffix(strings.ToLower(target), ".")
		if name, _, err := net.SplitHostPort(target); err == nil {
			host = strings.TrimSuffix(strings.ToLower(name), ".")
		}
		return "host:" + host, host
	}
	if target == "" {
		return "resource:unknown", "Unknown resource"
	}
	return "resource:" + target, target
}

func (s *Server) handleFindingsProjects(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	byID := map[string]*findingsProject{}
	for _, entry := range s.findAllScanSummaries() {
		rec := entry.rec
		if rec.ID == "" {
			continue
		}
		id, label := findingsProjectIdentity(rec)
		project := byID[id]
		if project == nil {
			project = &findingsProject{ID: id, Label: label, Severity: emptyFindingSeverity(), Scans: []findingsProjectScan{}}
			byID[id] = project
		}
		scan := findingsProjectScan{ID: rec.ID, Name: rec.Name, Target: rec.Target, ParentTarget: rec.ParentTarget, StartedAt: rec.StartedAt, Status: rec.Status, Severity: emptyFindingSeverity()}
		vulns := normalizedVulnsForEntry(entry)
		scan.FindingCount = len(vulns)
		if snapshot, ok := scanner.LoadFindingsSnapshot(entry.dir); ok {
			scan.ObservationCount = len(snapshot.RawObservations)
		} else {
			scan.ObservationCount = len(vulns)
		}
		for _, vuln := range vulns {
			status := scanner.FindingStatus(vuln.Status)
			if status == "" {
				status = scanner.StatusPotential
			}
			if !scanner.FindingActive(status) {
				continue
			}
			scan.ActiveCount++
			scan.Severity[normalizeSeverityBucket(vuln.Severity)]++
		}
		project.Scans = append(project.Scans, scan)
		project.ScanCount++
		project.FindingCount += scan.FindingCount
		project.ActiveCount += scan.ActiveCount
		project.ObservationCount += scan.ObservationCount
		for severity, count := range scan.Severity {
			project.Severity[severity] += count
		}
		if rec.StartedAt > project.LatestAt {
			project.LatestAt = rec.StartedAt
		}
	}
	projects := make([]findingsProject, 0, len(byID))
	for _, project := range byID {
		sort.Slice(project.Scans, func(i, j int) bool {
			if project.Scans[i].StartedAt == project.Scans[j].StartedAt {
				return project.Scans[i].ID < project.Scans[j].ID
			}
			return project.Scans[i].StartedAt > project.Scans[j].StartedAt
		})
		projects = append(projects, *project)
	}
	sort.Slice(projects, func(i, j int) bool {
		if projects[i].LatestAt == projects[j].LatestAt {
			return projects[i].ID < projects[j].ID
		}
		return projects[i].LatestAt > projects[j].LatestAt
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	_ = json.NewEncoder(w).Encode(map[string]any{"projects": projects})
}
