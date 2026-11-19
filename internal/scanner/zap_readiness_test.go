package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestZapAwaitReadyWaitsThenSucceeds(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Unresponsive for the first 2 probes (simulate a restarting daemon),
		// then healthy — the readiness gate must wait and then succeed.
		if atomic.AddInt32(&hits, 1) <= 2 {
			http.Error(w, "starting", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"version":"2.16.0"}`))
	}))
	defer srv.Close()
	var logs int
	err := zapAwaitReady(context.Background(), Config{ZAPURL: srv.URL, ZAPAPIKey: "k"}, 30*time.Second, func(string) { logs++ })
	if err != nil {
		t.Fatalf("should recover: %v", err)
	}
	if atomic.LoadInt32(&hits) < 3 {
		t.Fatalf("expected retries before success, hits=%d", hits)
	}
}

func TestZapAwaitReadyTimesOutClearly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer srv.Close()
	start := time.Now()
	err := zapAwaitReady(context.Background(), Config{ZAPURL: srv.URL, ZAPAPIKey: "k"}, 2*time.Second, nil)
	if err == nil {
		t.Fatal("expected a timeout error for a daemon that never recovers")
	}
	if !contains(err.Error(), "did not become responsive") || !contains(err.Error(), "restart the ZAP service") {
		t.Fatalf("error should be actionable: %v", err)
	}
	if time.Since(start) < 2*time.Second {
		t.Fatalf("returned before the window elapsed: %s", time.Since(start))
	}
}

func TestZapAwaitReadyDisabledWithZeroWindow(t *testing.T) {
	// window <= 0 skips the wait entirely (opt-out).
	if err := zapAwaitReady(context.Background(), Config{ZAPURL: "http://127.0.0.1:0"}, 0, nil); err != nil {
		t.Fatalf("zero window should skip the probe: %v", err)
	}
}

func TestZapReadyTimeoutEnvOverride(t *testing.T) {
	t.Setenv("XALGORIX_ZAP_READY_TIMEOUT_SEC", "5")
	if got := zapReadyTimeout(); got != 5*time.Second {
		t.Fatalf("env override = %s", got)
	}
	t.Setenv("XALGORIX_ZAP_READY_TIMEOUT_SEC", "0")
	if got := zapReadyTimeout(); got != 0 {
		t.Fatalf("zero override = %s", got)
	}
	t.Setenv("XALGORIX_ZAP_READY_TIMEOUT_SEC", "")
	if got := zapReadyTimeout(); got != 90*time.Second {
		t.Fatalf("default = %s", got)
	}
}
