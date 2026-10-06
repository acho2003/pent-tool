package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

func TestDiscoveryApprovalSurvivesServerRestartAndRejectsStalePreview(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	server := newTestServer(t, nil)
	plan := server.buildAssessmentPlan(assessment.AssessmentConfig{WorkflowVersion: "unified-v1", Mode: assessment.ModeBlackBox, Types: []assessment.Type{assessment.TypeWebApplication}, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://approved.example.test/"}}, ScannerSelection: assessment.ScannerSelection{Mode: "custom", Variants: []string{"httpx", "katana"}}})
	if len(plan.Errors) > 0 {
		t.Fatalf("fixture plan: %+v", plan.Errors)
	}
	dir := filepath.Join(server.dataDir, "approval-restart")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	record := &ScanRecord{ID: "approval-restart", Status: "finished", AssessmentPlan: &plan, PlanFingerprint: plan.Fingerprint, ScannerRuns: []scanner.Run{{Scanner: "httpx", HTTPObservations: []scanner.HTTPObservation{{URL: "https://candidate.example.test/", StatusCode: 200}}}}}
	server.saveScanRecordTo(record, dir)
	request := func(s *Server, method string, body any) *httptest.ResponseRecorder {
		t.Helper()
		encoded, _ := json.Marshal(body)
		response := httptest.NewRecorder()
		s.handleDiscoveryRevision(response, httptest.NewRequest(method, "/api/scans/approval-restart/discovery", bytes.NewReader(encoded)))
		return response
	}
	previewResponse := request(server, http.MethodGet, nil)
	var preview scanner.DiscoveryPreview
	if previewResponse.Code != 200 || json.Unmarshal(previewResponse.Body.Bytes(), &preview) != nil || len(preview.Candidates) != 1 {
		t.Fatalf("preview: %d %s", previewResponse.Code, previewResponse.Body.String())
	}
	stale := request(server, http.MethodPost, map[string]any{"fingerprint": "stale", "selected_ids": []string{preview.Candidates[0].ID}})
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale preview accepted: %d %s", stale.Code, stale.Body.String())
	}
	// A fresh server has no prior preview or revision in memory.
	restarted := newTestServer(t, nil)
	restarted.dataDir = server.dataDir
	pendingResponse := request(restarted, http.MethodGet, nil)
	var pending scanner.DiscoveryPreview
	if pendingResponse.Code != 200 || json.Unmarshal(pendingResponse.Body.Bytes(), &pending) != nil || pending.Fingerprint != preview.Fingerprint || pending.State != "awaiting_approval" {
		t.Fatalf("pending approval lost: %d %s", pendingResponse.Code, pendingResponse.Body.String())
	}
	acceptedResponse := request(restarted, http.MethodPost, map[string]any{"fingerprint": pending.Fingerprint, "selected_ids": []string{pending.Candidates[0].ID}})
	var accepted scanner.DiscoveryRevision
	if acceptedResponse.Code != 200 || json.Unmarshal(acceptedResponse.Body.Bytes(), &accepted) != nil {
		t.Fatalf("accept: %d %s", acceptedResponse.Code, acceptedResponse.Body.String())
	}
	if accepted.ParentFingerprint != plan.Fingerprint || accepted.Plan.Fingerprint == plan.Fingerprint || len(accepted.Plan.Config.Targets) != 2 {
		t.Fatalf("revision lost parent/scope: %+v", accepted)
	}
	again := newTestServer(t, nil)
	again.dataDir = server.dataDir
	savedResponse := request(again, http.MethodGet, nil)
	var saved scanner.DiscoveryPreview
	if savedResponse.Code != 200 || json.Unmarshal(savedResponse.Body.Bytes(), &saved) != nil || saved.ApprovedRevision == nil || saved.ApprovedRevision.Plan.Fingerprint != accepted.Plan.Fingerprint {
		t.Fatalf("accepted approval lost after restart: %d %s", savedResponse.Code, savedResponse.Body.String())
	}
	_, parent := again.findScanByID(record.ID)
	if parent == nil || len(parent.AssessmentPlan.Config.Targets) != 1 || parent.PlanFingerprint != plan.Fingerprint {
		t.Fatal("approval mutated accepted parent")
	}
}
