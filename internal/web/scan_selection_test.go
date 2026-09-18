package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// TestHandleScan_ScannerSelection covers the operator-chosen scanner subset:
// unknown names are rejected at the API boundary, and an accepted selection is
// stored in pipeline order so a later start/restart reruns the same subset.
func TestHandleScan_ScannerSelection(t *testing.T) {
	post := func(s *Server, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		s.handleScan(rr, httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(body)))
		return rr
	}

	t.Run("unknown scanner is rejected", func(t *testing.T) {
		s := newTestServer(t, &config.Config{RateLimitRequests: 60, RateLimitWindow: 60})
		rr := post(s, `{"targets":["example.com"],"scan_mode":"single","save_only":true,"scanners":["nuclei","nmap"]}`)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "nmap") {
			t.Fatalf("error should name the rejected scanner: %s", rr.Body.String())
		}
	})

	t.Run("selection is normalized and stored", func(t *testing.T) {
		s := newTestServer(t, &config.Config{RateLimitRequests: 60, RateLimitWindow: 60})
		rr := post(s, `{"targets":["example.com"],"scan_mode":"single","save_only":true,"scanners":["trivy","NUCLEI","trivy"]}`)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
		var resp map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		id, _ := resp["instance_id"].(string)
		if id == "" {
			id, _ = resp["id"].(string)
		}
		s.instancesMu.RLock()
		inst := s.instances[id]
		s.instancesMu.RUnlock()
		if inst == nil {
			t.Fatalf("saved instance %q not found (response: %s)", id, rr.Body.String())
		}
		if want := []string{"nuclei", "trivy"}; !reflect.DeepEqual(inst.Scanners, want) {
			t.Fatalf("stored scanners = %v, want %v", inst.Scanners, want)
		}
	})

	t.Run("empty selection stays empty so the whole pipeline runs", func(t *testing.T) {
		s := newTestServer(t, &config.Config{RateLimitRequests: 60, RateLimitWindow: 60})
		rr := post(s, `{"targets":["example.com"],"scan_mode":"single","save_only":true,"scanners":[]}`)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
		s.instancesMu.RLock()
		defer s.instancesMu.RUnlock()
		for _, inst := range s.instances {
			if len(inst.Scanners) != 0 {
				t.Fatalf("stored scanners = %v, want none", inst.Scanners)
			}
		}
	})
}
