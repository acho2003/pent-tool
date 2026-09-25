package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestScannerStatusListsCatalog(t *testing.T) {
	s := newTestServer(t, nil)
	rr := httptest.NewRecorder()
	s.handleScannerStatus(rr, httptest.NewRequest(http.MethodGet, "/api/scanners/status", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	var body struct {
		Scanners []struct {
			Name       string `json:"name"`
			Phase      string `json:"phase"`
			Selectable bool   `json:"selectable"`
			Summary    string `json:"summary"`
			Available  *bool  `json:"available"`
		} `json:"scanners"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, sc := range body.Scanners {
		names = append(names, sc.Name)
		if sc.Phase == "" || sc.Summary == "" || sc.Available == nil {
			t.Errorf("%s missing phase/summary/available: %+v", sc.Name, sc)
		}
	}
	want := []string{"subfinder", "httpx", "nmap", "nuclei", "zap", "testssl", "openvas", "vuls", "trivy", "semgrep", "gitleaks", "osv"}
	if !slices.Equal(names, want) {
		t.Fatalf("names = %v, want %v", names, want)
	}
	if body.Scanners[0].Selectable || !body.Scanners[3].Selectable {
		t.Fatalf("recon must not be selectable, nuclei must be: %+v", body.Scanners[:4])
	}
}
