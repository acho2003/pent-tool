package scanner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestSupplementalZAPArtifactUsesResponseEvidenceAndBlockedDispositions(t *testing.T) {
	root := t.TempDir()
	events := filepath.Join(root, "coverage-events.jsonl")
	records := []CoverageEvent{
		{Kind: "observed", Phase: "discovery", Method: "GET", URL: "https://app.test/exact/?x=1&x=2", ResponseCode: 200},
		{Kind: "selected", Phase: "routing", Method: "GET", URL: "https://app.test/unseen"},
		{Kind: "blocked", Phase: "discovery", Method: "POST", URL: "https://app.test/write", Reason: "write denied"},
		{Kind: "blocked", Phase: "discovery", Method: "GET", URL: "https://sibling.test/", Reason: "outside scope"},
		{Kind: "observed", Phase: "active_test", Method: "GET", URL: "https://app.test/active"},
	}
	f, err := os.Create(events)
	if err != nil {
		t.Fatal(err)
	}
	encoder := json.NewEncoder(f)
	for _, event := range records {
		if err = encoder.Encode(event); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()
	req := Request{Target: "https://app.test/", ScanDir: root, TargetAuth: "Authorization: Bearer verified", AuthContextID: AuthenticationContextID("app", "reader")}
	run := Run{CoverageEventsPath: events}
	if err = saveZAPDiscoveryArtifact(req, &run, Config{WebMaxEndpoints: 20, MaxOutputBytes: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	origin, _ := assessment.ParseApprovedOrigin("app", req.Target)
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	inventory, err := ParseKatanaAttackSurfaceScoped(run.ArtifactPath, "app:app", req.Target, true, &scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Endpoints) != 3 {
		t.Fatalf("unseen requests invented: %+v", inventory.Endpoints)
	}
	for _, endpoint := range inventory.Endpoints {
		switch endpoint.URL {
		case "https://app.test/exact/?x=1&x=2":
			if endpoint.StatusCode != 200 || endpoint.ObservationKind != "observed" || endpoint.AuthContextID != req.AuthContextID {
				t.Fatalf("native evidence lost: %+v", endpoint)
			}
		case "https://app.test/write":
			if endpoint.ObservationKind != "candidate" || endpointStateDispatchable(endpoint.State) || endpoint.ObservedWithAuth {
				t.Fatalf("blocked request claimed live: %+v", endpoint)
			}
		case "https://sibling.test/":
			if endpoint.ObservationKind != "candidate" || endpointStateDispatchable(endpoint.State) {
				t.Fatalf("sibling authorized: %+v", endpoint)
			}
		}
	}
}

func TestSafeZAPSpiderSnapshotsAndRestoresDaemonSettings(t *testing.T) {
	current := map[string]string{"ProcessForm": "true", "PostForm": "true", "MaxDepth": "0", "ThreadCount": "4", "MaxDuration": "0"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/JSON/spider/action/setOption"), "/")
		if _, ok := current[name]; !ok {
			t.Errorf("unexpected policy %s", r.URL.Path)
		}
		value := r.URL.Query().Get("Boolean")
		if value == "" {
			value = r.URL.Query().Get("Integer")
		}
		current[name] = value
		json.NewEncoder(w).Encode(map[string]string{"Result": "OK"})
	}))
	defer server.Close()
	call := func(path string, q url.Values) (map[string]any, error) {
		if strings.Contains(path, "/view/") {
			name := strings.TrimSuffix(strings.TrimPrefix(path, "/JSON/spider/view/option"), "/")
			return map[string]any{name: current[name]}, nil
		}
		if err := zapPost(Config{ZAPURL: server.URL}, path, q); err != nil {
			return nil, err
		}
		return map[string]any{"Result": "OK"}, nil
	}
	restore, err := configureSafeZAPSpider(Config{ZAPURL: server.URL}, call)
	if err != nil {
		t.Fatal(err)
	}
	if current["ProcessForm"] != "false" || current["PostForm"] != "false" || current["MaxDepth"] != "5" || current["ThreadCount"] != "1" || current["MaxDuration"] != "5" {
		t.Fatalf("unbounded/unsafe spider: %+v", current)
	}
	if err = restore(); err != nil {
		t.Fatal(err)
	}
	if current["ProcessForm"] != "true" || current["PostForm"] != "true" || current["MaxDepth"] != "0" || current["ThreadCount"] != "4" {
		t.Fatalf("daemon policy not restored: %+v", current)
	}
}

func TestRecordingGatewayAppliesRenewedTargetCredential(t *testing.T) {
	expected := "Bearer renewed-fixture"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != expected {
			t.Errorf("stale credential injected: %q", r.Header.Get("Authorization"))
		}
		w.Write([]byte("ok"))
	}))
	defer target.Close()
	origin, _ := assessment.ParseApprovedOrigin("app", target.URL)
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	gateway, err := NewRecordingGateway(t.Context(), Request{Target: target.URL, AppScope: &scope, ScanDir: t.TempDir(), TargetAuth: "Authorization: Bearer stale-fixture"}, Config{}, "zap")
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	gateway.UpdateTargetAuth([]string{"Authorization: " + expected})
	proxy, _ := url.Parse(gateway.URL)
	transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport}).Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
}
