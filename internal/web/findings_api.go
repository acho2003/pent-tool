package web

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

func findingRouteParts(path string) ([]string, bool) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(path, "/api/scans/"), "/"), "/")
	return parts, len(parts) >= 2 && parts[0] != "" && parts[1] == "findings"
}

func isFindingsRoutePath(path string) bool { _, ok := findingRouteParts(path); return ok }

func (s *Server) handleFindingsAPI(w http.ResponseWriter, r *http.Request) {
	parts, ok := findingRouteParts(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	scanID := parts[0]
	dir, rec := s.findScanByID(scanID)
	if rec == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}

	if len(parts) == 3 && parts[2] == "rebuild" {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		snapshot, errs := rebuildFindingsSnapshot(rec, dir, true)
		if len(errs) > 0 && snapshot == nil {
			http.Error(w, errs[0].Error(), http.StatusInternalServerError)
			return
		}
		if snapshot != nil {
			rec.Vulns = snapshotSummaries(snapshot)
			s.saveScanRecordTo(rec, dir)
		}
		// The download handler serves the PDF saved at scan end; regenerate it
		// so the report reflects the re-imported findings, not the stale ones.
		reportRegenerated := false
		if rec.SchemaVersion >= scanner.SchemaVersion && rec.Status != "running" {
			reportRegenerated = s.generateScannerReport(rec, dir, rec.InstanceID) != ""
		}
		writeFindingJSON(w, http.StatusOK, map[string]any{"status": "rebuilt", "summary": snapshot.Summary, "report_regenerated": reportRegenerated, "errors": errorStrings(errs)})
		return
	}

	snapshot, ok := scanner.LoadFindingsSnapshot(dir)
	if !ok {
		snapshot, _ = rebuildFindingsSnapshot(rec, dir, false)
	}
	if snapshot == nil {
		snapshot = &scanner.FindingsSnapshot{UniqueFindings: []scanner.SecurityFinding{}}
	}

	if len(parts) == 2 {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		items := filterSecurityFindings(snapshot.UniqueFindings, r)
		for i := range items {
			items[i] = sanitizeSecurityFinding(items[i])
		}
		page, size := parsePageParams(r.URL.Query().Get("page"), firstNonBlank(r.URL.Query().Get("limit"), r.URL.Query().Get("size")))
		writeFindingJSON(w, http.StatusOK, pagedFindingResponse(items, page, size))
		return
	}

	findingID := parts[2]
	var finding *scanner.SecurityFinding
	for i := range snapshot.UniqueFindings {
		if snapshot.UniqueFindings[i].ID == findingID || snapshot.UniqueFindings[i].Fingerprint == findingID {
			finding = &snapshot.UniqueFindings[i]
			break
		}
	}
	if finding == nil {
		http.Error(w, "finding not found", http.StatusNotFound)
		return
	}
	if len(parts) == 3 {
		switch r.Method {
		case http.MethodGet:
			writeFindingJSON(w, http.StatusOK, sanitizeSecurityFinding(*finding))
		case http.MethodPatch:
			var req struct {
				Status scanner.FindingStatus `json:"status"`
				Reason string                `json:"reason"`
			}
			if err := decodeFindingJSON(r, &req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if req.Status != scanner.StatusLikelyFalsePositive && req.Status != scanner.StatusFalsePositive && req.Status != scanner.StatusRemediated && req.Status != scanner.StatusAcceptedRisk {
				http.Error(w, "status must be FALSE_POSITIVE, REMEDIATED, or ACCEPTED_RISK", http.StatusBadRequest)
				return
			}
			if err := updateFindingStatus(dir, snapshot, finding.Fingerprint, req.Status, req.Reason); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			rec.Vulns = snapshotSummaries(snapshot)
			s.saveScanRecordTo(rec, dir)
			writeFindingJSON(w, http.StatusOK, finding)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	if len(parts) == 4 && (parts[3] == "endpoints" || parts[3] == "observations") {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		if parts[3] == "endpoints" {
			page, size := parsePageParams(r.URL.Query().Get("page"), firstNonBlank(r.URL.Query().Get("limit"), r.URL.Query().Get("size")))
			writeFindingJSON(w, http.StatusOK, pageFindingItems(sanitizeSecurityFinding(*finding).Endpoints, page, size))
			return
		}
		observations := make([]scanner.RawObservation, 0, len(finding.ObservationIDs))
		byID := map[string]scanner.RawObservation{}
		for _, o := range snapshot.RawObservations {
			byID[o.ID] = o
		}
		for _, id := range finding.ObservationIDs {
			if o, exists := byID[id]; exists {
				observations = append(observations, sanitizeFindingObservation(o))
			}
		}
		page, size := parsePageParams(r.URL.Query().Get("page"), firstNonBlank(r.URL.Query().Get("limit"), r.URL.Query().Get("size")))
		writeFindingJSON(w, http.StatusOK, pageFindingItems(observations, page, size))
		return
	}
	http.NotFound(w, r)
}

func errorStrings(errs []error) []string {
	out := make([]string, 0, len(errs))
	for _, err := range errs {
		if err != nil {
			out = append(out, err.Error())
		}
	}
	return out
}
func writeFindingJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func decodeFindingJSON(r *http.Request, dst any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 32<<10)).Decode(dst)
}

func filterSecurityFindings(in []scanner.SecurityFinding, r *http.Request) []scanner.SecurityFinding {
	q, status, severity, scannerName := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q"))), strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("status"))), strings.ToLower(strings.TrimSpace(r.URL.Query().Get("severity"))), strings.ToLower(strings.TrimSpace(r.URL.Query().Get("scanner")))
	out := make([]scanner.SecurityFinding, 0, len(in))
	for _, f := range in {
		if status != "" && string(f.Status) != status {
			continue
		}
		if severity != "" && strings.ToLower(f.Severity) != severity {
			continue
		}
		if scannerName != "" {
			found := false
			for _, name := range f.Scanners {
				if strings.EqualFold(name, scannerName) {
					found = true
				}
			}
			if !found {
				continue
			}
		}
		searchable := []string{f.Title, f.NormalizedType, f.Target, f.Fingerprint, strings.Join(f.CVE, " "), strings.Join(f.CWE, " ")}
		for _, endpoint := range f.Endpoints {
			searchable = append(searchable, endpoint.Endpoint, endpoint.CanonicalEndpoint, endpoint.Parameter)
		}
		if q != "" && !strings.Contains(strings.ToLower(strings.Join(searchable, " ")), q) {
			continue
		}
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := findingSeverityRankValue(out[i].Severity), findingSeverityRankValue(out[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return out[i].ID < out[j].ID
	})
	return out
}
func findingSeverityRankValue(value string) int {
	switch strings.ToLower(value) {
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
func pageFindingItems[T any](items []T, page, size int) map[string]any {
	total := len(items)
	start := (page - 1) * size
	if start > total {
		start = total
	}
	end := start + size
	if end > total {
		end = total
	}
	return map[string]any{"items": items[start:end], "page": page, "size": size, "total": total, "pages": (total + size - 1) / size}
}
func pagedFindingResponse(items []scanner.SecurityFinding, page, size int) map[string]any {
	return pageFindingItems(items, page, size)
}
