package web

import (
	"encoding/json"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCoverageDrilldownPaginatesAndRedactsLocations(t *testing.T) {
	server := newTestServer(t, nil)
	dir := filepath.Join(server.dataDir, "fixture")
	os.MkdirAll(dir, 0700)
	server.saveScanRecordTo(&ScanRecord{ID: "proof", Status: "finished"}, dir)
	surface := scanner.NewSeedAttackSurface("app:fixture", "https://app.test/?token=secret")
	if err := scanner.SaveAttackSurface(dir, surface); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.handleCoverageItems(response, httptest.NewRequest(http.MethodGet, "/api/scans/proof/coverage/items?metric=discovered&page=1&size=1", nil))
	if response.Code != 200 || strings.Contains(response.Body.String(), "token=secret") {
		t.Fatal(response.Code, response.Body.String())
	}
	var got struct {
		Total int                 `json:"total"`
		Items []scanner.ProofItem `json:"items"`
	}
	json.Unmarshal(response.Body.Bytes(), &got)
	if got.Total != 1 || len(got.Items) != 1 || got.Items[0].EndpointID == "" {
		t.Fatal(got)
	}
	response = httptest.NewRecorder()
	server.handleCoverageItems(response, httptest.NewRequest(http.MethodGet, "/api/scans/proof/coverage/items?metric=invalid", nil))
	if response.Code != 400 {
		t.Fatal(response.Code)
	}
}
