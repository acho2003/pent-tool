package web

import (
	"encoding/json"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
	"net/http"
	"strings"
)

func (s *Server) handleEndpointTrace(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", 405)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/scans/"), "/")
	if len(parts) != 4 || parts[1] != "endpoints" || parts[3] != "trace" {
		http.Error(w, "invalid endpoint trace", 400)
		return
	}
	dir, rec := s.findScanByID(parts[0])
	if rec == nil {
		http.Error(w, "scan not found", 404)
		return
	}
	var endpoint *scanner.AttackSurfaceEndpoint
	for _, surface := range scanner.LoadAttackSurfaces(dir) {
		for _, e := range surface.Endpoints {
			if e.ID == parts[2] {
				copy := e
				copy.URL = scanner.SafeTelemetryURL(copy.URL)
				endpoint = &copy
			}
		}
	}
	if endpoint == nil {
		http.Error(w, "endpoint not found", 404)
		return
	}
	events := []scanner.CoverageEvent{}
	for _, run := range rec.ScannerRuns {
		if requested := r.URL.Query().Get("scanner"); requested != "" && requested != run.Scanner {
			continue
		}
		if attempt := r.URL.Query().Get("attempt_id"); attempt != "" && attempt != run.AttemptID {
			continue
		}
		for _, submission := range run.Submissions {
			if submission.EndpointID == endpoint.ID {
				events = append(events, scanner.CoverageEvent{AttemptID: run.AttemptID, Scanner: run.Scanner, EndpointIDs: []string{endpoint.ID}, URL: submission.URL, Method: submission.Method, Phase: "seeding", Kind: submission.Status, At: submission.At, Reason: submission.Reason})
			}
		}
		if rows, err := scanner.ReadCoverageEvents(run.CoverageEventsPath); err == nil {
			for _, e := range rows {
				for _, id := range e.EndpointIDs {
					if id == endpoint.ID {
						events = append(events, e)
						break
					}
				}
			}
		}
	}
	page, size := parsePageParams(r.URL.Query().Get("page"), r.URL.Query().Get("size"))
	start := (page - 1) * size
	if start > len(events) {
		start = len(events)
	}
	end := start + size
	if end > len(events) {
		end = len(events)
	}
	state := "recorded"
	if len(events) == 0 {
		state = "NOT TRACKED"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"endpoint": endpoint, "state": state, "items": events[start:end], "total": len(events), "page": page, "size": size})
}
