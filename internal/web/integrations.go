package web

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"sort"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

// integrationEntry describes one tool on the Integrations page: how it is
// integrated, whether it can run here, and why not when it cannot. It is a
// read-only view and does not feed scan setup or plan selection.
type integrationEntry struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Group              string `json:"group"`
	Summary            string `json:"summary"`
	Integration        string `json:"integration"` // bundled, service, built-in, operator-supplied
	Available          bool   `json:"available"`
	AvailabilityReason string `json:"availability_reason,omitempty"`
	Path               string `json:"path,omitempty"`
	Version            string `json:"version,omitempty"`
	DefaultSelection   string `json:"default_selection,omitempty"`
	Risk               string `json:"risk,omitempty"`
}

func (s *Server) integrationPaths() map[string]string {
	return map[string]string{
		"subfinder": s.cfg.SubfinderPath, "amass": s.cfg.AmassPath, "dnsx": s.cfg.DNSXPath, "httpx": s.cfg.HttpxPath,
		"katana": s.cfg.KatanaPath, "nmap": s.cfg.NmapPath, "masscan": s.cfg.MasscanPath, "nikto": s.cfg.NiktoPath,
		"nuclei": s.cfg.NucleiPath, "testssl": s.cfg.TestsslPath, "sslyze": s.cfg.SSLyzePath, "dalfox": s.cfg.DalfoxPath,
		"wapiti": s.cfg.WapitiPath, "schemathesis": s.cfg.SchemathesisPath,
		"vuls": s.cfg.VulsPath, "lynis": s.cfg.SSHPath, "trivy": s.cfg.TrivyPath, "semgrep": s.cfg.SemgrepPath,
		"nextjs-sast": s.cfg.SemgrepPath, "gitleaks": s.cfg.GitleaksPath, "osv": s.cfg.OsvPath,
		"kube-bench": s.cfg.KubeBenchPath, "prowler": s.cfg.ProwlerPath, "scoutsuite": s.cfg.ScoutSuitePath,
		"gau": s.cfg.GauPath, "waybackurls": s.cfg.WaybackurlsPath,
	}
}

func (s *Server) handleIntegrations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	available := s.assessmentScannerAvailability()
	paths := s.integrationPaths()
	present := func(path string) bool {
		if strings.TrimSpace(path) == "" {
			return false
		}
		_, err := exec.LookPath(path)
		return err == nil
	}
	version := func(id string) string {
		first, _, _ := strings.Cut(strings.TrimSpace(s.toolVersions[id]), "\n")
		return first
	}
	var entries []integrationEntry
	for _, def := range scanner.ScannerRegistry() {
		entry := integrationEntry{ID: def.ID, Name: def.Name, Group: def.Group, Summary: def.Summary, DefaultSelection: def.DefaultSelection, Risk: def.Risk, Version: version(def.ID)}
		entry.Available = available[def.ID]
		path, hasPath := paths[def.ID]
		switch {
		case def.ID == "zap":
			entry.Integration, entry.Path = "service", "ZAP daemon at "+firstNonEmptyString(s.cfg.ZAPURL, "(not configured)")
			if !entry.Available {
				entry.AvailabilityReason = "a dedicated, healthy ZAP service is required"
			}
		case def.ID == "openvas":
			entry.Integration, entry.Path = "service", "Greenbone "+firstNonEmptyString(s.cfg.GVMSocket, s.cfg.GVMHost, "(not configured)")
			if !entry.Available {
				entry.AvailabilityReason = "Greenbone credentials and socket or host are required"
			}
		case hasPath:
			entry.Integration, entry.Path = "bundled", path
			if !present(path) {
				entry.AvailabilityReason = "executable not found: " + path
			} else if !entry.Available {
				entry.AvailabilityReason = def.AvailabilityReason
			}
		default:
			entry.Integration = "built-in"
			if !entry.Available {
				entry.AvailabilityReason = "no assessment adapter in this build"
			}
		}
		if def.ID == "masscan" && !entry.Available && entry.AvailabilityReason == "" {
			entry.AvailabilityReason = scanner.MasscanCapabilityReason()
		}
		entries = append(entries, entry)
	}
	// Providers and services that are not planned as registry scanners.
	for _, extra := range []struct{ id, name, group, summary string }{
		{"gau", "gau", scanner.GroupWebAPI, "Historical URL candidates from public archives (discovery provider)"},
		{"waybackurls", "waybackurls", scanner.GroupWebAPI, "Historical URL candidates from the Wayback Machine (alternative to gau)"},
	} {
		path := paths[extra.id]
		entry := integrationEntry{ID: extra.id, Name: extra.name, Group: extra.group, Summary: extra.summary, Integration: "bundled", Path: path, Available: present(path), Version: version(extra.id)}
		if !entry.Available {
			entry.AvailabilityReason = "executable not found: " + path
		}
		entries = append(entries, entry)
	}
	browser := integrationEntry{ID: "chromium", Name: "Chromium", Group: scanner.GroupWebAPI, Summary: "Headless browser for authenticated crawling, login, access tests and XHR/GraphQL discovery", Integration: "bundled", Path: s.cfg.BrowserPath, Available: present(s.cfg.BrowserPath)}
	if !browser.Available {
		browser.AvailabilityReason = "browser executable not found: " + s.cfg.BrowserPath
	}
	entries = append(entries, browser)
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Group != entries[j].Group {
			return entries[i].Group < entries[j].Group
		}
		return entries[i].Name < entries[j].Name
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"registry_version": scanner.PlanRegistryVersion, "integrations": entries})
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
