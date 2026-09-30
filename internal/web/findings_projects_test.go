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

func TestFindingsProjectIdentity(t *testing.T) {
	cases := []struct {
		target, parent, id string
	}{
		{"https://EXAMPLE.test:443/a", "", "host:example.test"},
		{"example.test.", "", "host:example.test"},
		{"192.0.2.10", "", "host:192.0.2.10"},
		{"https://api.example.test", "https://example.test", "host:example.test"},
		{"https://api.example.test", "", "host:api.example.test"},
		{"/srv/source", "", "resource:/srv/source"},
		{"registry.test/app:tag", "", "resource:registry.test/app:tag"},
	}
	for _, tc := range cases {
		id, _ := findingsProjectIdentity(ScanRecord{Target: tc.target, ParentTarget: tc.parent})
		if id != tc.id {
			t.Errorf("target %q parent %q: got %q, want %q", tc.target, tc.parent, id, tc.id)
		}
	}
}

func TestScanFindingFiltersSearchEndpointAndCVE(t *testing.T) {
	findings := []scanner.SecurityFinding{{ID: "f1", Title: "Injection", Severity: "high", Status: scanner.StatusPotential, Scanners: []string{"zap"}, CVE: []string{"CVE-2026-1234"}, Endpoints: []scanner.FindingEndpoint{{Endpoint: "https://example.test/search?q=x"}}}}
	for _, query := range []string{"q=search", "q=CVE-2026-1234", "q=search&severity=high&scanner=zap&status=POTENTIAL"} {
		request := httptest.NewRequest(http.MethodGet, "/api/scans/id/findings?"+query, nil)
		if got := filterSecurityFindings(findings, request); len(got) != 1 {
			t.Errorf("query %q returned %d findings", query, len(got))
		}
	}
	if got := filterSecurityFindings(findings, httptest.NewRequest(http.MethodGet, "/api/scans/id/findings?q=other", nil)); len(got) != 0 {
		t.Errorf("unmatched query returned %d findings", len(got))
	}
}

func TestFindingsProjectsKeepsScanHistoryAndLegacyRecords(t *testing.T) {
	s := newTestServer(t, nil)
	records := []ScanRecord{
		{ID: "older", Target: "https://example.test/a", StartedAt: "2026-01-01T00:00:00Z", Status: "finished", Vulns: []VulnSummary{{ID: "f1", Title: "CSP", Severity: "medium", Status: "POTENTIAL"}}},
		{ID: "newer", Target: "example.test", StartedAt: "2026-02-01T00:00:00Z", Status: "finished", Vulns: []VulnSummary{{ID: "f2", Title: "CSP", Severity: "medium", Status: "POTENTIAL"}, {ID: "f3", Title: "Technology", Severity: "info", Status: "OBSERVATION"}}},
		{ID: "child", Target: "api.example.test", ParentTarget: "example.test", StartedAt: "2026-03-01T00:00:00Z", Status: "running"},
		{ID: "other", Target: "other.test", StartedAt: "2026-02-02T00:00:00Z", Status: "finished"},
	}
	for _, rec := range records {
		dir := filepath.Join(s.dataDir, rec.ID)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "scan.json"), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	w := httptest.NewRecorder()
	s.handleFindingsProjects(w, httptest.NewRequest(http.MethodGet, "/api/findings/projects", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var response struct {
		Projects []findingsProject `json:"projects"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Projects) != 2 || response.Projects[0].ID != "host:example.test" {
		t.Fatalf("projects = %+v", response.Projects)
	}
	project := response.Projects[0]
	if project.ScanCount != 3 || project.FindingCount != 3 || project.ActiveCount != 2 || project.Severity["medium"] != 2 {
		t.Errorf("project counts = %+v", project)
	}
	if project.Scans[0].ID != "child" || project.Scans[1].ID != "newer" || project.Scans[2].ID != "older" {
		t.Errorf("scan order = %+v", project.Scans)
	}
	if project.Scans[1].FindingCount != 2 || project.Scans[2].FindingCount != 1 {
		t.Errorf("repeated finding missing from scan history: %+v", project.Scans)
	}
	for id, want := range map[string]int{"older": 1, "newer": 2} {
		w = httptest.NewRecorder()
		s.handleFindingsAPI(w, httptest.NewRequest(http.MethodGet, "/api/scans/"+id+"/findings?page=1&size=50", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("scan %s findings status = %d: %s", id, w.Code, w.Body.String())
		}
		var page struct {
			Total int `json:"total"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		if page.Total != want {
			t.Errorf("scan %s findings total = %d, want %d", id, page.Total, want)
		}
	}
	w = httptest.NewRecorder()
	s.handleFindingsProjects(w, httptest.NewRequest(http.MethodPost, "/api/findings/projects", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d", w.Code)
	}
}
