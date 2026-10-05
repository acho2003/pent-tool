package web

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

type attackSurfaceSummary struct {
	Raw           int `json:"raw"`
	Unique        int `json:"unique"`
	Static        int `json:"static"`
	API           int `json:"api"`
	Web           int `json:"web"`
	Sensitive     int `json:"sensitive"`
	Parameterized int `json:"parameterized"`
	Forms         int `json:"forms"`
}

type attackSurfaceResponse struct {
	ScanID  string                          `json:"scan_id"`
	State   string                          `json:"state"`
	Reason  string                          `json:"reason,omitempty"`
	Summary attackSurfaceSummary            `json:"summary"`
	Items   []scanner.AttackSurfaceEndpoint `json:"items"`
	Total   int                             `json:"total"`
	Page    int                             `json:"page"`
	Size    int                             `json:"size"`
}

func isScanAttackSurfacePath(path string) bool {
	parts := strings.Split(strings.TrimPrefix(path, "/api/scans/"), "/")
	return len(parts) == 2 && parts[0] != "" && parts[1] == "attack-surface"
}

func (s *Server) handleAttackSurface(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/scans/"), "/attack-surface")
	scanDir, rec := s.findScanByID(id)
	if rec == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	page, size := parsePageParams(r.URL.Query().Get("page"), r.URL.Query().Get("size"))
	response := attackSurfaceResponse{
		ScanID: id, State: "ready", Items: []scanner.AttackSurfaceEndpoint{}, Page: page, Size: size,
	}
	surfaces := scanner.LoadAttackSurfaces(scanDir)
	if len(surfaces) == 0 {
		response.State = "legacy"
		response.Reason = "This scan has no structured attack-surface snapshot."
		if rec.Status == "running" {
			response.State = "discovering"
			response.Reason = "Endpoint discovery has not produced an inventory yet."
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
		return
	}
	if rec.Status == "running" {
		response.State = "partial"
	}
	var all []scanner.AttackSurfaceEndpoint
	for _, surface := range surfaces {
		response.Summary.Raw += surface.RawCount
		for _, endpoint := range surface.Endpoints {
			response.Summary.Unique++
			switch endpoint.Kind {
			case "static":
				response.Summary.Static++
			case "api":
				response.Summary.API++
			default:
				response.Summary.Web++
			}
			if endpoint.Sensitive {
				response.Summary.Sensitive++
			}
			if endpoint.HasParameters {
				response.Summary.Parameterized++
			}
			if endpoint.HasForm {
				response.Summary.Forms++
			}
			endpoint.URL = scanner.SafeTelemetryURL(endpoint.URL)
			all = append(all, endpoint)
		}
	}
	kind := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("kind")))
	scannerName := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("scanner")))
	status := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	filtered := make([]scanner.AttackSurfaceEndpoint, 0, len(all))
	for _, endpoint := range all {
		if kind != "" && kind != "all" && endpoint.Kind != kind {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(endpoint.CanonicalURL+" "+endpoint.Path), query) {
			continue
		}
		if scannerName != "" || status != "" {
			matched := false
			for _, coverage := range endpoint.ScannerCoverage {
				if (scannerName == "" || strings.EqualFold(coverage.Scanner, scannerName)) && (status == "" || strings.EqualFold(coverage.Status, status)) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		filtered = append(filtered, endpoint)
	}
	response.Total = len(filtered)
	start := (page - 1) * size
	if start > len(filtered) {
		start = len(filtered)
	}
	end := start + size
	if end > len(filtered) {
		end = len(filtered)
	}
	response.Items = filtered[start:end]
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}
