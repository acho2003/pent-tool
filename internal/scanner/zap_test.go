package scanner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeZAP answers the exact JSON API calls the runner makes, so the whole
// spider → passive → active scan → report sequence is exercised without a ZAP
// daemon or a shared filesystem.
type fakeZAP struct {
	mu         sync.Mutex
	paths      []string
	rules      map[string]bool
	report     string
	alertScope string
}

func (f *fakeZAP) record(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paths = append(f.paths, path)
}

func (f *fakeZAP) called(path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.paths {
		if p == path {
			return true
		}
	}
	return false
}

func (f *fakeZAP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.record(r.URL.Path)
	if r.URL.Query().Get("apikey") != "zap-key" {
		http.Error(w, `{"code":"bad_api_key"}`, http.StatusForbidden)
		return
	}
	body := map[string]string{"Result": "OK"}
	switch r.URL.Path {
	case "/JSON/core/view/version/":
		body = map[string]string{"version": "2.15.0"}
	case "/JSON/replacer/action/addRule/":
		f.mu.Lock()
		f.rules[r.URL.Query().Get("description")] = true
		f.mu.Unlock()
	case "/JSON/replacer/action/removeRule/":
		f.mu.Lock()
		delete(f.rules, r.URL.Query().Get("description"))
		f.mu.Unlock()
	case "/JSON/spider/action/scan/":
		body = map[string]string{"scan": "7"}
	case "/JSON/spider/view/status/":
		body = map[string]string{"status": "100"}
	case "/JSON/pscan/view/recordsToScan/":
		body = map[string]string{"recordsToScan": "0"}
	case "/JSON/ascan/action/scan/":
		body = map[string]string{"scan": "9"}
	case "/JSON/ascan/view/status/":
		body = map[string]string{"status": "100"}
	case "/JSON/core/view/alerts/":
		f.mu.Lock()
		f.alertScope = r.URL.Query().Get("baseurl")
		f.mu.Unlock()
		w.Write([]byte(f.report))
		return
	default:
		http.Error(w, `{"code":"no_implementor"}`, http.StatusBadRequest)
		return
	}
	_ = json.NewEncoder(w).Encode(body)
}

func TestZAPRunDrivesAPIAndWritesReport(t *testing.T) {
	fake := &fakeZAP{rules: map[string]bool{}, report: `{"alerts":[{"pluginId":"40012","alert":"XSS","name":"Reflected XSS","risk":"High","description":"d","cweid":"79","url":"http://example.test/q"}]}`}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	dir := t.TempDir()
	cfg := Config{ZAPURL: srv.URL, ZAPAPIKey: "zap-key", ZAPTimeout: 30 * time.Second, MaxOutputBytes: 1 << 20}
	req := Request{Target: "http://example.test", ScanDir: dir, TargetAuth: "Authorization: Bearer sekret-token"}
	run := zapRunner{}.Run(t.Context(), req, cfg, nil)

	if run.Status != "completed" {
		t.Fatalf("status = %q reason = %q", run.Status, run.Reason)
	}
	for _, path := range []string{"/JSON/spider/action/scan/", "/JSON/pscan/view/recordsToScan/", "/JSON/ascan/action/scan/", "/JSON/core/view/alerts/"} {
		if !fake.called(path) {
			t.Errorf("runner never called %s", path)
		}
	}
	if !fake.called("/JSON/replacer/action/addRule/") {
		t.Error("target auth header was not installed as a replacer rule")
	}
	fake.mu.Lock()
	leftover := len(fake.rules)
	fake.mu.Unlock()
	if leftover != 0 {
		t.Errorf("replacer rules left in the daemon: %d", leftover)
	}
	fake.mu.Lock()
	scope := fake.alertScope
	fake.mu.Unlock()
	if scope != "http://example.test" {
		t.Errorf("alerts were exported with baseurl %q, not scoped to the target", scope)
	}
	findings, err := parseZAP(run.ArtifactPath)
	if err != nil || len(findings) != 1 || findings[0].Severity != "high" || findings[0].Endpoint != "http://example.test/q" {
		t.Fatalf("parsed report = %+v err = %v", findings, err)
	}
	log, err := os.ReadFile(run.StdoutPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(log), "sekret-token") {
		t.Error("target auth secret leaked into the scanner log")
	}
}

func TestZAPRunFailsWhenAPIRejectsTheCall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"code":"does_not_exist","message":"Does Not Exist"}`, http.StatusBadRequest)
	}))
	defer srv.Close()
	run := zapRunner{}.Run(t.Context(), Request{Target: "http://example.test", ScanDir: t.TempDir()},
		Config{ZAPURL: srv.URL, ZAPAPIKey: "zap-key", ZAPTimeout: 10 * time.Second, MaxOutputBytes: 1 << 20}, nil)
	if run.Status != "failed" || !strings.Contains(run.Reason, "does_not_exist") {
		t.Fatalf("status = %q reason = %q", run.Status, run.Reason)
	}
}
