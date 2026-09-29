package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

func TestAttackSurfaceAPIListsFiltersAndPaginates(t *testing.T) {
	s := newTestServer(t, nil)
	dir := filepath.Join(s.dataDir, "target", "2026-09-29", "surface-scan")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s.saveScanRecordTo(&ScanRecord{SchemaVersion: 3, ID: "surface-scan", Target: "https://example.test", Status: "finished", Events: []WSEvent{}, Vulns: []VulnSummary{}}, dir)
	surface := &scanner.AttackSurface{SchemaVersion: scanner.AttackSurfaceSchemaVersion, ClassifierVersion: scanner.AttackSurfaceClassifierVersion, Scope: "app:test", Target: "https://example.test", RawCount: 4, Endpoints: []scanner.AttackSurfaceEndpoint{
		{ID: "1", URL: "https://example.test/", CanonicalURL: "https://example.test/", Method: "GET", Path: "/", Kind: "web"},
		{ID: "2", URL: "https://example.test/api/users?q=one", CanonicalURL: "https://example.test/api/users?q={value}", Method: "GET", Path: "/api/users", Kind: "api", HasParameters: true, ScannerCoverage: []scanner.EndpointScannerCoverage{{Scanner: "zap", Status: "completed"}}},
		{ID: "3", URL: "https://example.test/app.js", CanonicalURL: "https://example.test/app.js", Method: "GET", Path: "/app.js", Kind: "static"},
	}}
	if err := scanner.SaveAttackSurface(dir, surface); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	s.handleAttackSurface(rr, httptest.NewRequest(http.MethodGet, "/api/scans/surface-scan/attack-surface?kind=api&scanner=zap&status=completed&page=1&size=1", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var response attackSurfaceResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Summary.Raw != 4 || response.Summary.Unique != 3 || response.Summary.API != 1 || response.Summary.Static != 1 || response.Total != 1 || len(response.Items) != 1 || response.Items[0].ID != "2" {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestAttackSurfaceAPIReturnsLegacyEmptyResponse(t *testing.T) {
	s := newTestServer(t, nil)
	dir := filepath.Join(s.dataDir, "legacy")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s.saveScanRecordTo(&ScanRecord{ID: "legacy-surface", Target: "old.test", Status: "finished", Events: []WSEvent{}, Vulns: []VulnSummary{}}, dir)
	rr := httptest.NewRecorder()
	s.handleAttackSurface(rr, httptest.NewRequest(http.MethodGet, "/api/scans/legacy-surface/attack-surface", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var response attackSurfaceResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.State != "legacy" || response.Items == nil || response.Total != 0 {
		t.Fatalf("unexpected legacy response: %+v", response)
	}
}

func TestAttackSurfacePathValidation(t *testing.T) {
	for path, want := range map[string]bool{
		"/api/scans/abc/attack-surface":   true,
		"/api/scans//attack-surface":      false,
		"/api/scans/abc/attack-surface/x": false,
	} {
		if got := isScanAttackSurfacePath(path); got != want {
			t.Errorf("isScanAttackSurfacePath(%q)=%v want %v", path, got, want)
		}
	}
}
