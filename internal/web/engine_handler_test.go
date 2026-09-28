package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// TestHandleScan_EngineSelection covers the "just scan" vs "full autonomous"
// switch at the API boundary: the default is deterministic, an explicit choice
// is stored on the saved instance, an unknown value degrades to deterministic,
// and autonomous is rejected up front when no AI provider is configured.
func TestHandleScan_EngineSelection(t *testing.T) {
	post := func(s *Server, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		s.handleScan(rr, httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(body)))
		return rr
	}
	savedInstanceEngine := func(t *testing.T, s *Server) string {
		t.Helper()
		s.instancesMu.RLock()
		defer s.instancesMu.RUnlock()
		for _, inst := range s.instances {
			return inst.Engine
		}
		t.Fatal("no saved instance found")
		return ""
	}

	baseCfg := func() *config.Config {
		return &config.Config{RateLimitRequests: 60, RateLimitWindow: 60}
	}
	cfgWithProvider := func() *config.Config {
		c := baseCfg()
		c.APIKey = "sk-test"
		return c
	}

	t.Run("default is deterministic", func(t *testing.T) {
		s := newTestServer(t, baseCfg())
		rr := post(s, `{"targets":["example.com"],"scan_mode":"single","save_only":true}`)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
		if got := savedInstanceEngine(t, s); got != engineDeterministic {
			t.Fatalf("engine = %q, want %q", got, engineDeterministic)
		}
	})

	t.Run("unknown engine degrades to deterministic", func(t *testing.T) {
		s := newTestServer(t, baseCfg())
		rr := post(s, `{"targets":["example.com"],"scan_mode":"single","save_only":true,"engine":"magic"}`)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
		if got := savedInstanceEngine(t, s); got != engineDeterministic {
			t.Fatalf("engine = %q, want %q", got, engineDeterministic)
		}
	})

	t.Run("autonomous stored when provider configured", func(t *testing.T) {
		s := newTestServer(t, cfgWithProvider())
		rr := post(s, `{"targets":["example.com"],"scan_mode":"single","save_only":true,"engine":"autonomous"}`)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
		if got := savedInstanceEngine(t, s); got != engineAutonomous {
			t.Fatalf("engine = %q, want %q", got, engineAutonomous)
		}
	})

	t.Run("autonomous rejected without provider", func(t *testing.T) {
		s := newTestServer(t, baseCfg())
		rr := post(s, `{"targets":["example.com"],"scan_mode":"single","save_only":true,"engine":"autonomous"}`)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(strings.ToLower(rr.Body.String()), "autonomous") {
			t.Fatalf("error should explain the autonomous requirement: %s", rr.Body.String())
		}
	})
}
