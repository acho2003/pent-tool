package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeZAP answers the exact JSON API calls the runner makes, so the whole
// spider → passive → active scan → report sequence is exercised without a ZAP
// daemon or a shared filesystem.
type fakeZAP struct {
	mu                 sync.Mutex
	paths              []string
	rules              map[string]bool
	report             string
	alertScope         string
	spiderMaxChildren  string
	spiderContext      string
	activeContext      string
	activeInScopeOnly  string
	contextRegex       string
	contextRemoved     bool
	newSessions        int
	replacerURL        string
	followRedirects    string
	accessFails        bool // accessUrl returns 500
	ascanNoTree        bool // ascan/action/scan returns url_not_found
	removeContextFails bool
	domXSSEnabled      string
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
	case "/JSON/core/action/newSession/":
		f.mu.Lock()
		f.newSessions++
		f.mu.Unlock()
	case "/JSON/context/action/newContext/":
		body = map[string]string{"contextId": "42"}
	case "/JSON/context/action/includeInContext/":
		f.mu.Lock()
		f.contextRegex = r.URL.Query().Get("regex")
		f.mu.Unlock()
	case "/JSON/context/action/setContextInScope/":
	case "/JSON/context/action/removeContext/":
		f.mu.Lock()
		f.contextRemoved = true
		f.mu.Unlock()
		if f.removeContextFails {
			http.Error(w, `{"code":"cleanup_failed"}`, http.StatusInternalServerError)
			return
		}
	case "/JSON/core/view/version/":
		body = map[string]string{"version": "2.15.0"}
	case "/JSON/replacer/action/addRule/":
		f.mu.Lock()
		f.rules[r.URL.Query().Get("description")] = true
		f.replacerURL = r.URL.Query().Get("url")
		f.mu.Unlock()
	case "/JSON/replacer/action/removeRule/":
		f.mu.Lock()
		delete(f.rules, r.URL.Query().Get("description"))
		f.mu.Unlock()
	case "/JSON/spider/action/scan/":
		f.mu.Lock()
		f.spiderMaxChildren = r.URL.Query().Get("maxChildren")
		f.spiderContext = r.URL.Query().Get("contextName")
		f.mu.Unlock()
		body = map[string]string{"scan": "7"}
	case "/JSON/spider/view/status/":
		body = map[string]string{"status": "100"}
	case "/JSON/pscan/view/recordsToScan/":
		body = map[string]string{"recordsToScan": "0"}
	case "/JSON/core/action/accessUrl/":
		f.mu.Lock()
		f.followRedirects = r.URL.Query().Get("followRedirects")
		f.mu.Unlock()
		if f.accessFails {
			http.Error(w, `{"code":"internal_error","message":"Internal Error"}`, http.StatusInternalServerError)
			return
		}
	case "/JSON/ascan/action/disableScanners/":
		f.mu.Lock()
		f.domXSSEnabled = "false"
		f.mu.Unlock()
	case "/JSON/ascan/action/enableScanners/":
		f.mu.Lock()
		f.domXSSEnabled = "true"
		f.mu.Unlock()
	case "/JSON/ascan/view/scanners/":
		f.mu.Lock()
		state := f.domXSSEnabled
		f.mu.Unlock()
		if state == "" {
			state = "false"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"scanners": []any{map[string]any{"id": zapDomXSSPluginID, "enabled": state}}})
		return
	case "/JSON/ascan/action/scan/":
		f.mu.Lock()
		f.activeContext = r.URL.Query().Get("contextId")
		f.activeInScopeOnly = r.URL.Query().Get("inScopeOnly")
		f.mu.Unlock()
		if f.ascanNoTree {
			http.Error(w, `{"code":"url_not_found","message":"URL Not Found in the Scan Tree"}`, http.StatusBadRequest)
			return
		}
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
	cfg := Config{ZAPURL: srv.URL, ZAPAPIKey: "zap-key", ZAPTimeout: 30 * time.Second, WebMaxEndpoints: 125, MaxOutputBytes: 1 << 20}
	req := Request{Target: "http://example.test", ScanDir: dir, TargetAuth: "Authorization: Bearer sekret-token"}
	run := zapRunner{}.Run(t.Context(), req, cfg, nil)

	if run.Status != "completed" {
		t.Fatalf("status = %q reason = %q", run.Status, run.Reason)
	}
	for _, path := range []string{"/JSON/spider/action/scan/", "/JSON/pscan/view/recordsToScan/", "/JSON/ascan/action/disableScanners/", "/JSON/ascan/action/scan/", "/JSON/core/view/alerts/"} {
		if !fake.called(path) {
			t.Errorf("runner never called %s", path)
		}
	}
	if !fake.called("/JSON/replacer/action/addRule/") {
		t.Error("target auth header was not installed as a replacer rule")
	}
	fake.mu.Lock()
	leftover := len(fake.rules)
	maxChildren := fake.spiderMaxChildren
	fake.mu.Unlock()
	if maxChildren != "125" {
		t.Errorf("ZAP spider maxChildren = %q, want 125", maxChildren)
	}
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

func TestZAPServiceLeaseSerializesPipelinesAndHonorsCancellation(t *testing.T) {
	release, err := acquireZAPServiceLease(context.Background(), "http://zap.example.test:8080/")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := acquireZAPServiceLease(ctx, "http://zap.example.test:8080"); err != context.DeadlineExceeded {
		t.Fatalf("queued ZAP lease error = %v, want deadline exceeded", err)
	}
	release()
	secondRelease, err := acquireZAPServiceLease(context.Background(), "http://zap.example.test:8080")
	if err != nil {
		t.Fatalf("lease was not released: %v", err)
	}
	secondRelease()
}

func TestZAPTypedAssessmentRequiresDedicatedDaemon(t *testing.T) {
	fake := &fakeZAP{rules: map[string]bool{}, report: `{"alerts":[]}`, domXSSEnabled: "true"}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	run := zapRunner{}.Run(t.Context(), Request{Target: "https://app.example.test/Portal/", ScanDir: t.TempDir(), TypedAssessment: true}, Config{ZAPURL: srv.URL, ZAPAPIKey: "zap-key"}, nil)
	if run.Status != "failed" || !strings.Contains(run.Reason, "XALGORIX_ZAP_DEDICATED") {
		t.Fatalf("typed scan on an unclaimed shared daemon = %+v", run)
	}
	if len(fake.paths) != 0 {
		t.Fatalf("runner contacted a shared daemon before refusing the typed job: %v", fake.paths)
	}
}

func TestZAPTypedAssessmentUsesFreshPathBoundContextAndCleansIt(t *testing.T) {
	fake := &fakeZAP{rules: map[string]bool{}, report: `{"alerts":[]}`, domXSSEnabled: "true"}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	target := "https://Example.test:8443/Portal/CaseSensitive/"
	req := Request{Target: target, ScanDir: t.TempDir(), Scope: "app:app", TypedAssessment: true, TargetAuth: "Authorization: Bearer scoped-secret"}
	cfg := Config{ZAPURL: srv.URL, ZAPAPIKey: "zap-key", ZAPDedicated: true, ZAPTimeout: 30 * time.Second, WebMaxEndpoints: 77, MaxOutputBytes: 1 << 20}
	run := zapRunner{}.Run(t.Context(), req, cfg, nil)
	if run.Status != "completed" {
		t.Fatalf("typed ZAP run = %+v", run)
	}
	fake.mu.Lock()
	contextRegex, spiderContext := fake.contextRegex, fake.spiderContext
	activeContext, inScopeOnly, redirect, replacerURL := fake.activeContext, fake.activeInScopeOnly, fake.followRedirects, fake.replacerURL
	removed, sessions := fake.contextRemoved, fake.newSessions
	domXSSEnabled := fake.domXSSEnabled
	fake.mu.Unlock()
	compiled, err := regexp.Compile(contextRegex)
	if err != nil {
		t.Fatalf("invalid ZAP context regex %q: %v", contextRegex, err)
	}
	for _, inScope := range []string{
		"https://example.test:8443/Portal/CaseSensitive",
		"https://example.test:8443/Portal/CaseSensitive/child",
	} {
		if !compiled.MatchString(inScope) {
			t.Errorf("context regex %q excludes in-scope URL %q", contextRegex, inScope)
		}
	}
	for _, outOfScope := range []string{
		"https://example.test:8443/Portal/CaseSensitiveOther",
		"https://example.test:9443/Portal/CaseSensitive/child",
		"https://example.test:8443/portal/CaseSensitive/child",
		"https://other.test:8443/Portal/CaseSensitive/child",
	} {
		if compiled.MatchString(outOfScope) {
			t.Errorf("context regex %q includes out-of-scope URL %q", contextRegex, outOfScope)
		}
	}
	if spiderContext == "" || activeContext != "42" || inScopeOnly != "true" {
		t.Errorf("spider/active scan not bound to the context: spider=%q context=%q inScopeOnly=%q", spiderContext, activeContext, inScopeOnly)
	}
	if redirect != "false" || replacerURL != contextRegex {
		t.Errorf("redirect/auth boundaries not enforced: followRedirects=%q replacerURL=%q", redirect, replacerURL)
	}
	if !removed || sessions < 2 || ZAPServiceQuarantined(srv.URL) {
		t.Errorf("fresh context/session did not clean up: removed=%t sessions=%d quarantined=%t", removed, sessions, ZAPServiceQuarantined(srv.URL))
	}
	if domXSSEnabled != "true" {
		t.Errorf("typed scan did not restore prior DOM XSS scanner policy: %q", domXSSEnabled)
	}
}

func TestApplicationContextRegexPreservesPathBoundaryAndDefaultPorts(t *testing.T) {
	pattern, err := applicationContextRegex("https://Example.test:443/Portal/")
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.MatchString("https://example.test/Portal/page") || compiled.MatchString("https://example.test/PortalElse") || compiled.MatchString("https://example.test:8443/Portal/page") {
		t.Fatalf("default-port/path regex has incorrect boundary: %q", pattern)
	}
}

func TestZAPCleanupFailureQuarantinesDaemon(t *testing.T) {
	fake := &fakeZAP{rules: map[string]bool{}, report: `{"alerts":[]}`, removeContextFails: true}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	cfg := Config{ZAPURL: srv.URL, ZAPAPIKey: "zap-key", ZAPDedicated: true, ZAPTimeout: 30 * time.Second, MaxOutputBytes: 1 << 20}
	req := Request{Target: "https://app.example.test/", ScanDir: t.TempDir(), Scope: "app:app", TypedAssessment: true}
	first := zapRunner{}.Run(t.Context(), req, cfg, nil)
	if first.Status != "completed" || !ZAPServiceQuarantined(srv.URL) {
		t.Fatalf("cleanup failure did not quarantine daemon: run=%+v quarantined=%t", first, ZAPServiceQuarantined(srv.URL))
	}
	fake.mu.Lock()
	requestsBeforeRetry := len(fake.paths)
	fake.mu.Unlock()
	second := zapRunner{}.Run(t.Context(), req, cfg, nil)
	if second.Status != "failed" || !strings.Contains(second.Reason, "quarantined") {
		t.Fatalf("quarantined daemon was reused: %+v", second)
	}
	fake.mu.Lock()
	requestsAfterRetry := len(fake.paths)
	fake.mu.Unlock()
	if requestsAfterRetry != requestsBeforeRetry {
		t.Fatalf("retry contacted quarantined daemon: before=%d after=%d", requestsBeforeRetry, requestsAfterRetry)
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

func TestZAPSeedsTargetBeforeSpider(t *testing.T) {
	fake := &fakeZAP{rules: map[string]bool{}, report: `{"alerts":[]}`}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	run := zapRunner{}.Run(t.Context(), Request{Target: "http://example.test", ScanDir: t.TempDir()},
		Config{ZAPURL: srv.URL, ZAPAPIKey: "zap-key", ZAPTimeout: 30 * time.Second, MaxOutputBytes: 1 << 20}, nil)
	if run.Status != "completed" {
		t.Fatalf("status = %q reason = %q", run.Status, run.Reason)
	}
	if !fake.called("/JSON/core/action/accessUrl/") {
		t.Fatal("runner must seed the target into ZAP's tree via accessUrl")
	}
	// accessUrl must precede the spider so the tree is never empty when the
	// active scan starts.
	fake.mu.Lock()
	defer fake.mu.Unlock()
	ai, si := -1, -1
	for i, p := range fake.paths {
		if p == "/JSON/core/action/accessUrl/" && ai < 0 {
			ai = i
		}
		if p == "/JSON/spider/action/scan/" && si < 0 {
			si = i
		}
	}
	if ai < 0 || si < 0 || ai > si {
		t.Errorf("accessUrl (index %d) must come before spider (index %d)", ai, si)
	}
}

func TestZAPContinuesWhenSeedFails(t *testing.T) {
	fake := &fakeZAP{rules: map[string]bool{}, report: `{"alerts":[]}`, accessFails: true}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	run := zapRunner{}.Run(t.Context(), Request{Target: "https://example.test", ScanDir: t.TempDir()},
		Config{ZAPURL: srv.URL, ZAPAPIKey: "zap-key", ZAPTimeout: 30 * time.Second, MaxOutputBytes: 1 << 20}, nil)
	if run.Status != "completed" {
		t.Fatalf("a failed pre-seed must not abort a spiderable target: status=%q reason=%q", run.Status, run.Reason)
	}
	if !fake.called("/JSON/spider/action/scan/") || !fake.called("/JSON/ascan/action/scan/") {
		t.Error("scan must proceed to spider and active scan after a seed failure")
	}
	log, _ := os.ReadFile(run.StdoutPath)
	if !strings.Contains(string(log), "could not pre-seed") {
		t.Error("a seed failure should be logged as a non-fatal warning")
	}
}

func TestZAPClearErrorWhenNoPagesFound(t *testing.T) {
	fake := &fakeZAP{rules: map[string]bool{}, report: `{"alerts":[]}`, ascanNoTree: true}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	run := zapRunner{}.Run(t.Context(), Request{Target: "https://example.test", ScanDir: t.TempDir()},
		Config{ZAPURL: srv.URL, ZAPAPIKey: "zap-key", ZAPTimeout: 30 * time.Second, MaxOutputBytes: 1 << 20}, nil)
	if run.Status != "failed" || !strings.Contains(run.Reason, "no reachable pages") {
		t.Fatalf("empty scan tree must read clearly: status=%q reason=%q", run.Status, run.Reason)
	}
}
