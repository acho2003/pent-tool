package web

import (
	"encoding/json"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
	"net/http"
	"strings"
)

func (s *Server) handleCoverageItems(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", 405)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/scans/"), "/")
	if len(parts) != 3 || parts[1] != "coverage" || parts[2] != "items" {
		http.Error(w, "invalid coverage drilldown", 400)
		return
	}
	dir, rec := s.findScanByID(parts[0])
	if rec == nil {
		http.Error(w, "scan not found", 404)
		return
	}
	metric := r.URL.Query().Get("metric")
	name := r.URL.Query().Get("scanner")
	switch metric {
	case "discovered", "observed", "approved", "eligible", "seeds", "candidates", "hosts", "services", "tls_services", "forms", "parameterized", "observed_with_auth":
		if name != "" {
			http.Error(w, "discovery metrics do not have a scanner filter", 400)
			return
		}
	case "enabled_templates", "selected", "submitted", "acknowledged", "exercised", "batch_completed", "failed", "skipped", "unknown":
		if name == "" {
			http.Error(w, "scanner required", 400)
			return
		}
	default:
		http.Error(w, "unknown metric", 400)
		return
	}
	proof := scanner.BuildCoverageProof(scanner.LoadAttackSurfaces(dir), rec.ScannerRuns)
	key := metric
	if name != "" {
		key = name + ":" + metric
	}
	items := proof.Items[key]
	if items == nil {
		items = []scanner.ProofItem{}
	}
	page, size := parsePageParams(r.URL.Query().Get("page"), r.URL.Query().Get("size"))
	start := (page - 1) * size
	if start > len(items) {
		start = len(items)
	}
	end := start + size
	if end > len(items) {
		end = len(items)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"items": items[start:end], "total": len(items), "page": page, "size": size, "metric": metric, "scanner": name})
}
