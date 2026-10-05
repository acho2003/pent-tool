package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

var discoveryRevisionMu sync.Mutex

func (s *Server) handleDiscoveryRevision(w http.ResponseWriter, r *http.Request) {
	if !scanner.UnifiedWorkflowEnabled() {
		http.Error(w, "expanded workflow is disabled", http.StatusNotFound)
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/scans/"), "/discovery")
	if id == "" || strings.Contains(id, "/") {
		http.Error(w, "invalid scan", 400)
		return
	}
	discoveryRevisionMu.Lock()
	defer discoveryRevisionMu.Unlock()
	dir, record := s.findScanByID(id)
	if record == nil || record.AssessmentPlan == nil {
		http.Error(w, "assessment not found", 404)
		return
	}
	preview := scanner.BuildDiscoveryPreview(*record.AssessmentPlan, record.ScannerRuns, scanner.LoadAttackSurfaces(dir))
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		preview.ApprovedRevision = scanner.FindApprovedDiscoveryRevision(dir, preview.Fingerprint)
		json.NewEncoder(w).Encode(preview)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "GET or POST only", 405)
		return
	}
	if record.Status == "running" {
		http.Error(w, "wait for accepted jobs to finish before revising", 409)
		return
	}
	var request struct {
		Fingerprint string   `json:"fingerprint"`
		SelectedIDs []string `json:"selected_ids"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&request); err != nil {
		http.Error(w, "invalid approval", 400)
		return
	}
	if request.Fingerprint != preview.Fingerprint {
		http.Error(w, "stale discovery preview", 409)
		return
	}
	cfg, err := scanner.ApproveDiscoveryConfig(*record.AssessmentPlan, preview, request.Fingerprint, request.SelectedIDs)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	cfg.ParentAssessmentID, cfg.ParentPlanFingerprint, cfg.ApprovalPreviewFingerprint = id, record.PlanFingerprint, preview.Fingerprint
	cfg = newAssessmentWorkflowConfig(cfg)
	plan := s.buildAssessmentPlan(cfg)
	if len(plan.Errors) > 0 {
		w.WriteHeader(422)
		json.NewEncoder(w).Encode(plan)
		return
	}
	revision := scanner.DiscoveryRevision{AcceptedAt: time.Now().UTC().Format(time.RFC3339Nano), ParentFingerprint: record.PlanFingerprint, PreviewFingerprint: preview.Fingerprint, SelectedIDs: request.SelectedIDs, Plan: plan}
	if err := scanner.SaveDiscoveryRevision(dir, revision); err != nil {
		http.Error(w, "could not persist approved revision", 500)
		return
	}
	json.NewEncoder(w).Encode(revision)
}
