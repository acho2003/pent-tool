package scanner

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWapitiRuntimeApprovedFormPostBudgetCleanupAndReplay(t *testing.T) {
	if os.Getenv("XALGORIX_TEST_WAPITI_POST") == "" {
		t.Skip("native installed Wapiti form fixture opt-in")
	}
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	var mu sync.Mutex
	posts, cleanups := 0, 0
	bodies := []string{}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == "POST" {
			posts++
			data, _ := io.ReadAll(r.Body)
			bodies = append(bodies, string(data))
			if r.URL.Path != "/items" {
				t.Error("POST escaped approved path")
			}
		}
		if r.Method == "DELETE" {
			cleanups++
			if r.URL.Path != "/items/fixture" {
				t.Error("cleanup path changed")
			}
		}
		w.Header().Set("Content-Type", "text/html")
		if r.Method == "DELETE" {
			w.WriteHeader(204)
			return
		}
		fmt.Fprint(w, "<html><body>controlled fixture</body></html>")
	}))
	defer target.Close()
	req, cfg := formFuzzFixture(t, target.URL+"/")
	cfg.WapitiTimeout = 45 * time.Second
	cfg.MaxOutputBytes = 1 << 20
	cfg.WebMaxEndpoints = 50
	if err := prepareWapitiPostRequest(&req, nil); err != nil {
		t.Fatal(err)
	}
	gateway, err := NewRecordingGateway(t.Context(), req, cfg, "wapiti")
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	req.Gateway, req.GatewayURL, req.GatewayCAPath = gateway, gateway.URL, gateway.CAPath
	run := runWapitiPost(t.Context(), req, cfg, nil)
	if err = gateway.Close(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	actualPosts, actualCleanups := posts, cleanups
	original := false
	for _, body := range bodies {
		if body == req.WapitiPostBody {
			original = true
		}
	}
	mu.Unlock()
	if actualPosts == 0 || actualPosts > 3 || actualCleanups != 1 || !original {
		data, _ := os.ReadFile(run.StdoutPath)
		t.Logf("native stdout: %s", data)
		events, _ := ReadCoverageEvents(gateway.EventPath)
		t.Logf("native events: %+v", events)
		t.Fatalf("native bounded body/cleanup failed: posts=%d cleanup=%d original=%v bodies=%v run=%+v", actualPosts, actualCleanups, original, bodies, run)
	}
	entries, err := LoadWriteJournal(req.WriteJournalDir)
	if err != nil || len(entries) != 1 || entries[0].State != WriteStateCleanupDone {
		t.Fatalf("native campaign not journaled: %+v %v", entries, err)
	}
	events, err := ReadCoverageEvents(gateway.EventPath)
	if err != nil {
		t.Fatal(err)
	}
	receipt := false
	blocked := false
	for _, event := range events {
		if event.Kind == "observed" && event.Method == "POST" && len(event.EndpointIDs) == 1 && event.EndpointIDs[0] == req.InputRequests[0].EndpointID {
			receipt = true
		}
		if event.Kind == "blocked" && event.Method == "POST" {
			blocked = true
		}
	}
	if !receipt || !blocked {
		t.Fatalf("native exact-input receipt or explicit budget disposition missing: %+v", events)
	}
	repeated := runWapitiPost(t.Context(), req, cfg, nil)
	if repeated.Status != "failed" || !strings.Contains(repeated.Reason, "replay") {
		t.Fatalf("native consent replayed: %+v", repeated)
	}
}
