package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestZAPAuthMonitorRenewsAndStopsOnFailure(t *testing.T) {
	checks, replacements := 0, 0
	monitor := &zapAuthMonitor{current: []string{"Cookie: old"}, interval: time.Hour, refresh: func(ctx context.Context, current []string) ([]string, error) {
		checks++
		if checks == 1 {
			return []string{"Cookie: new"}, nil
		}
		return nil, fmt.Errorf("secret credential must not escape")
	}}
	replace := func(next []string) error { replacements++; return nil }
	if err := monitor.check(context.Background(), replace); err != nil || monitor.current[0] != "Cookie: new" || replacements != 1 {
		t.Fatalf("renewal failed: %+v, %v", monitor, err)
	}
	if err := monitor.check(context.Background(), replace); err != nil || checks != 1 {
		t.Fatalf("checked before interval: %v", err)
	}
	monitor.next = time.Time{}
	if err := monitor.check(context.Background(), replace); err == nil || strings.Contains(err.Error(), "secret") || replacements != 1 {
		t.Fatalf("expiry did not fail safely: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	monitor.next = time.Time{}
	if err := monitor.check(ctx, replace); err != context.Canceled {
		t.Fatalf("cancelled monitor returned %v", err)
	}
}

func TestSessionCookieValuesAreRedacted(t *testing.T) {
	secrets := secretValues(Request{TargetAuth: "Cookie: first=one-secret; second=two-secret"}, Config{})
	redacted := redact("evidence one-secret and two-secret", secrets)
	if strings.Contains(redacted, "one-secret") || strings.Contains(redacted, "two-secret") {
		t.Fatalf("session cookie value leaked through redaction: %s", redacted)
	}
}

func TestZAPWaitScanReportsNumericProgress(t *testing.T) {
	var got []int
	call := func(string, url.Values) (map[string]any, error) {
		return map[string]any{"status": "100"}, nil
	}
	if err := zapWaitScanChecked(context.Background(), call, "/JSON/ascan/view/status/", "1", "active scan", func(string) {}, nil, func(pct int) { got = append(got, pct) }); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []int{100}) {
		t.Fatalf("progress callback received %v, want [100]", got)
	}
	// A nil progress callback stays valid for callers that only log.
	if err := zapWaitScanChecked(context.Background(), call, "/JSON/spider/view/status/", "1", "spider", func(string) {}, nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestParseZAPPreservesEveryAffectedInstance(t *testing.T) {
	path := writeFixture(t, "zap-instances.json", `{"alerts":[{"pluginId":"10021","name":"XSS","risk":"High","confidence":"Medium","cweid":"79","solution":"Encode output","instances":[{"uri":"https://app.test/Case","method":"GET","param":"q","evidence":"<x>"},{"uri":"https://app.test/Case","method":"POST","param":"body.name","evidence":"<y>"}]}]}`)
	findings, err := parseZAP(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected both alert instances, got %+v", findings)
	}
	if findings[0].Method != "GET" || findings[0].Parameter != "q" || findings[0].Remediation != "Encode output" || findings[0].Confidence != "MEDIUM" || findings[0].NativeConfidence != "Medium" {
		t.Fatalf("first instance evidence missing: %+v", findings[0])
	}
	if findings[1].Method != "POST" || findings[1].Parameter != "body.name" || findings[0].SourceID == findings[1].SourceID {
		t.Fatalf("second instance identity missing: %+v", findings[1])
	}
}

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
	passiveUnavailable bool // pscan/view/recordsToScan returns an API error
	removeContextFails bool
	domXSSEnabled      string
	accessedURLs       []string
	contextExcludes    []string
	spiderExcludes     []string // daemon state: spider excludedFromScan
	ascanExcludes      []string // daemon state: ascan excludedFromScan
	delayInMs          string   // daemon state: ascan optionDelayInMs ("" = 0)
	threadPerHost      string   // daemon state: ascan optionThreadPerHost ("" = 2)
	delayDuringScan    string
	threadsDuringScan  string
	spiderExclDuring   []string
	ascanExclDuring    []string
	restoreDelayFails  bool
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

// called0 is called without taking the lock; the caller holds f.mu.
func (f *fakeZAP) called0(path string) bool {
	return slices.Contains(f.paths, path)
}

func (f *fakeZAP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.record(r.URL.Path)
	_ = r.ParseForm()
	if r.URL.Query().Get("apikey") != "zap-key" && r.Header.Get("X-ZAP-API-Key") != "zap-key" {
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
		f.rules[r.Form.Get("description")] = true
		f.replacerURL = r.Form.Get("url")
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
		if f.passiveUnavailable {
			http.Error(w, `{"code":"no_implementor"}`, http.StatusBadRequest)
			return
		}
		body = map[string]string{"recordsToScan": "0"}
	case "/JSON/core/action/accessUrl/":
		f.mu.Lock()
		f.followRedirects = r.URL.Query().Get("followRedirects")
		f.accessedURLs = append(f.accessedURLs, r.URL.Query().Get("url"))
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
	case "/JSON/context/action/excludeFromContext/":
		f.mu.Lock()
		f.contextExcludes = append(f.contextExcludes, r.URL.Query().Get("regex"))
		f.mu.Unlock()
	case "/JSON/spider/view/excludedFromScan/":
		f.mu.Lock()
		list := append([]string{}, f.spiderExcludes...)
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"excludedFromScan": list})
		return
	case "/JSON/spider/action/excludeFromScan/":
		f.mu.Lock()
		f.spiderExcludes = append(f.spiderExcludes, r.URL.Query().Get("regex"))
		f.mu.Unlock()
	case "/JSON/spider/action/clearExcludedFromScan/":
		f.mu.Lock()
		f.spiderExcludes = nil
		f.mu.Unlock()
	case "/JSON/ascan/view/excludedFromScan/":
		f.mu.Lock()
		list := append([]string{}, f.ascanExcludes...)
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"excludedFromScan": list})
		return
	case "/JSON/ascan/action/excludeFromScan/":
		f.mu.Lock()
		f.ascanExcludes = append(f.ascanExcludes, r.URL.Query().Get("regex"))
		f.mu.Unlock()
	case "/JSON/ascan/action/clearExcludedFromScan/":
		f.mu.Lock()
		f.ascanExcludes = nil
		f.mu.Unlock()
	case "/JSON/ascan/view/optionDelayInMs/":
		f.mu.Lock()
		value := f.delayInMs
		f.mu.Unlock()
		if value == "" {
			value = "0"
		}
		body = map[string]string{"DelayInMs": value}
	case "/JSON/ascan/view/optionThreadPerHost/":
		f.mu.Lock()
		value := f.threadPerHost
		f.mu.Unlock()
		if value == "" {
			value = "2"
		}
		body = map[string]string{"ThreadPerHost": value}
	case "/JSON/ascan/action/setOptionDelayInMs/":
		f.mu.Lock()
		restoring := f.called0("/JSON/ascan/action/scan/")
		fails := f.restoreDelayFails && restoring
		if !fails {
			f.delayInMs = r.URL.Query().Get("Integer")
		}
		f.mu.Unlock()
		if fails {
			http.Error(w, `{"code":"internal_error"}`, http.StatusInternalServerError)
			return
		}
	case "/JSON/ascan/action/setOptionThreadPerHost/":
		f.mu.Lock()
		f.threadPerHost = r.URL.Query().Get("Integer")
		f.mu.Unlock()
	case "/JSON/ascan/action/scan/":
		f.mu.Lock()
		f.activeContext = r.URL.Query().Get("contextId")
		f.activeInScopeOnly = r.URL.Query().Get("inScopeOnly")
		f.delayDuringScan, f.threadsDuringScan = f.delayInMs, f.threadPerHost
		f.spiderExclDuring = append([]string(nil), f.spiderExcludes...)
		f.ascanExclDuring = append([]string(nil), f.ascanExcludes...)
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

func TestZAPSeedsOnlyEligibleOpenAPIOperationsWithinTargetScope(t *testing.T) {
	fake := &fakeZAP{rules: map[string]bool{}, report: `{"alerts":[]}`, domXSSEnabled: "true"}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	target := "https://Example.test:8443/Portal/Case/"
	req := Request{Target: target, ScanDir: t.TempDir(), Scope: "app:app", TypedAssessment: true, APIEndpoints: []APIEndpoint{
		{Method: "GET", Path: "/users", Origin: "https://example.test:8443", RequestURL: "https://example.test:8443/Portal/Case/users?state=active", Resolved: true, Eligible: true},
		{Method: "POST", Path: "/orders", Origin: "https://example.test:8443", Resolved: true, Reason: "state-changing operation"},
		{Method: "GET", Path: "/users/{id}", Origin: "https://example.test:8443", Resolved: false, Reason: "path parameter missing"},
	}}
	cfg := Config{ZAPURL: srv.URL, ZAPAPIKey: "zap-key", ZAPDedicated: true, ZAPTimeout: 30 * time.Second, WebMaxEndpoints: 10, MaxOutputBytes: 1 << 20}
	run := zapRunner{}.Run(t.Context(), req, cfg, nil)
	if run.Status != "completed" {
		t.Fatalf("ZAP run=%+v", run)
	}
	if len(run.APIEndpointResults) != 3 || run.APIEndpointResults[0].Status != "seeded" || run.APIEndpointResults[1].Status != "skipped" || run.APIEndpointResults[2].Status != "skipped" {
		t.Fatalf("unexpected operation outcomes: %+v", run.APIEndpointResults)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	want := "https://example.test:8443/Portal/Case/users?state=active"
	if !slices.Contains(fake.accessedURLs, want) {
		t.Errorf("eligible API route %q was not seeded: %v", want, fake.accessedURLs)
	}
	if slices.Contains(fake.accessedURLs, "https://example.test:8443/Portal/Case/orders") {
		t.Error("mutating API operation was sent to ZAP")
	}
}

func TestZAPReplacerSecretsAreSentInPostBody(t *testing.T) {
	secret := "Bearer request-secret"
	var queryLeak atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, secret) {
			queryLeak.Store(true)
		}
		_ = r.ParseForm()
		if r.Form.Get("replacement") != secret {
			t.Errorf("POST body did not contain replacement")
		}
		if r.Header.Get("X-ZAP-API-Key") != "zap-key" {
			t.Errorf("API key header missing")
		}
		w.Write([]byte(`{"Result":"OK"}`))
	}))
	defer srv.Close()
	_, err := zapPostResponse(context.Background(), Config{ZAPURL: srv.URL, ZAPAPIKey: "zap-key"}, "/JSON/replacer/action/addRule/", url.Values{"replacement": {secret}})
	if err != nil {
		t.Fatal(err)
	}
	if queryLeak.Load() {
		t.Fatal("credential leaked into ZAP request URL")
	}
}

func TestZAPRunDrivesAPIAndWritesReport(t *testing.T) {
	fake := &fakeZAP{rules: map[string]bool{}, report: `{"alerts":[{"pluginId":"10020","name":"Missing Security Header","risk":"Low","url":"http://example.test/"},{"pluginId":"40012","alert":"XSS","name":"Reflected XSS","risk":"High","description":"d","cweid":"79","url":"http://example.test/q"}]}`}
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
	paths := append([]string(nil), fake.paths...)
	fake.mu.Unlock()
	spiderEnd := slices.Index(paths, "/JSON/spider/view/status/")
	firstPassive := slices.Index(paths, "/JSON/pscan/view/recordsToScan/")
	activeStart := slices.Index(paths, "/JSON/ascan/action/scan/")
	activeEnd := slices.Index(paths, "/JSON/ascan/view/status/")
	lastPassive := -1
	for i, path := range paths {
		if path == "/JSON/pscan/view/recordsToScan/" {
			lastPassive = i
		}
	}
	export := slices.Index(paths, "/JSON/core/view/alerts/")
	if !(spiderEnd >= 0 && spiderEnd < firstPassive && firstPassive < activeStart && activeStart < activeEnd && activeEnd < lastPassive && lastPassive < export) {
		t.Errorf("ZAP did not drain passive scans before and after active scanning: %v", paths)
	}
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
	if err != nil || len(findings) != 2 || findings[0].Endpoint != "http://example.test/" || findings[1].Severity != "high" || findings[1].Endpoint != "http://example.test/q" {
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

func TestZAPStructuredDispatchDoesNotRecrawlForms(t *testing.T) {
	fake := &fakeZAP{rules: map[string]bool{}, report: `{"alerts":[]}`}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	req := Request{
		Target: "https://example.test/", Scope: "app:test", ScanDir: t.TempDir(),
		TypedAssessment: true, StructuredDispatch: true,
		EndpointTargets: []string{"https://example.test/search?q=one", "https://example.test/api/users"},
	}
	cfg := Config{ZAPURL: srv.URL, ZAPAPIKey: "zap-key", ZAPDedicated: true, ZAPTimeout: 30 * time.Second, WebMaxEndpoints: 10, MaxOutputBytes: 1 << 20}
	run := zapRunner{}.Run(t.Context(), req, cfg, nil)
	if run.Status != "completed" {
		t.Fatalf("run=%+v", run)
	}
	if fake.called("/JSON/spider/action/scan/") {
		t.Fatal("structured dispatch must not spider and rediscover state-changing forms")
	}
	fake.mu.Lock()
	accessed := append([]string(nil), fake.accessedURLs...)
	fake.mu.Unlock()
	for _, endpoint := range req.EndpointTargets {
		if !slices.Contains(accessed, endpoint) {
			t.Errorf("dispatcher-approved endpoint %q was not seeded: %v", endpoint, accessed)
		}
	}
}

func TestZAPFailsWhenPassiveScanningCannotBeConfirmed(t *testing.T) {
	fake := &fakeZAP{rules: map[string]bool{}, report: `{"alerts":[]}`, passiveUnavailable: true}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	run := zapRunner{}.Run(t.Context(), Request{Target: "http://example.test", ScanDir: t.TempDir()},
		Config{ZAPURL: srv.URL, ZAPAPIKey: "zap-key", ZAPTimeout: 30 * time.Second, MaxOutputBytes: 1 << 20}, nil)
	if run.Status != "failed" || !strings.Contains(run.Reason, "passive scan") {
		t.Fatalf("unavailable passive scan = %+v", run)
	}
	if fake.called("/JSON/ascan/action/scan/") || fake.called("/JSON/core/view/alerts/") {
		t.Fatal("ZAP must not report complete coverage when passive scanning is unavailable")
	}
}

func TestZAPThoroughHasNoOverallDeadline(t *testing.T) {
	fake := &fakeZAP{rules: map[string]bool{}, report: `{"alerts":[]}`}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	run := zapRunner{}.Run(t.Context(), Request{Target: "http://example.test", ScanDir: t.TempDir(), Profile: ProfileThorough},
		Config{ZAPURL: srv.URL, ZAPAPIKey: "zap-key", ZAPTimeout: time.Nanosecond, WebBudget: time.Nanosecond, MaxOutputBytes: 1 << 20}, nil)
	if run.Status != "completed" {
		t.Fatalf("thorough ZAP retained an overall deadline: %+v", run)
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
	req := Request{Target: target, ScanDir: t.TempDir(), Scope: "app:app", TypedAssessment: true, TargetAuth: "Authorization: Bearer scoped-secret", AuthRefresh: func(ctx context.Context, current []string) ([]string, error) { return current, nil }}
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

func TestZAPTypedSessionRefreshUpdatesScopedRuleOrStops(t *testing.T) {
	fake := &fakeZAP{rules: map[string]bool{}, report: `{"alerts":[]}`, domXSSEnabled: "true"}
	var replacements []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/JSON/replacer/action/addRule/" {
			_ = r.ParseForm()
			replacements = append(replacements, r.Form.Get("replacement"))
		}
		fake.ServeHTTP(w, r)
	}))
	defer srv.Close()
	cfg := Config{ZAPURL: srv.URL, ZAPAPIKey: "zap-key", ZAPDedicated: true, ZAPTimeout: 30 * time.Second, MaxOutputBytes: 1 << 20}
	req := Request{Target: "https://example.test/app/", ScanDir: t.TempDir(), Scope: "app:one", TypedAssessment: true, TargetAuth: "Cookie: old-secret", AuthKind: "form login", AuthRefresh: func(ctx context.Context, current []string) ([]string, error) {
		return []string{"Cookie: new-secret"}, nil
	}}
	run := runAttempt(t.Context(), zapRunner{}, req, cfg, nil)
	if run.Status != "completed" || !slices.Equal(replacements, []string{"old-secret", "new-secret"}) {
		t.Fatalf("renewed ZAP session was not installed: status=%s replacements=%v reason=%s", run.Status, replacements, run.Reason)
	}
	log, err := os.ReadFile(run.StdoutPath)
	if err != nil || !strings.Contains(string(log), "Authentication verified: form login") || !strings.Contains(string(log), "form session renewed after re-login") || strings.Contains(string(log), "old-secret") || strings.Contains(string(log), "new-secret") {
		t.Fatalf("form login status was not safely recorded: %q, err=%v", log, err)
	}
	terminal, err := os.ReadFile(run.TranscriptPath)
	if err != nil || !strings.Contains(string(terminal), "Authentication verified: form login") || strings.Contains(string(terminal), "new-secret") {
		t.Fatalf("form login terminal transcript is missing or unsafe: %q, err=%v", terminal, err)
	}
	req.ScanDir = t.TempDir()
	req.AuthRefresh = func(ctx context.Context, current []string) ([]string, error) {
		return nil, fmt.Errorf("private-password")
	}
	failed := runAttempt(t.Context(), zapRunner{}, req, cfg, nil)
	if failed.Status != "failed" || !strings.Contains(failed.Reason, "authenticated session") || strings.Contains(failed.Reason, "private-password") {
		t.Fatalf("failed session check was not safe: %+v", failed)
	}
	failedLog, err := os.ReadFile(failed.StdoutPath)
	if err != nil || !strings.Contains(string(failedLog), "Authentication error:") || strings.Contains(string(failedLog), "private-password") {
		t.Fatalf("form login error was not safely recorded: %q, err=%v", failedLog, err)
	}
}

func TestZAPTypedAuthenticationRequiresRuntimeVerifier(t *testing.T) {
	req := Request{Target: "https://example.test/app/", ScanDir: t.TempDir(), TypedAssessment: true, TargetAuth: "Cookie: private"}
	run := zapRunner{}.Run(t.Context(), req, Config{ZAPURL: "http://127.0.0.1:1", ZAPDedicated: true}, nil)
	if run.Status != "failed" || !strings.Contains(run.Reason, "session verifier") || strings.Contains(run.Reason, "private") {
		t.Fatalf("unmonitored authenticated job was not rejected: %+v", run)
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

func TestZAPContextRegexNormalizesDefaultPort(t *testing.T) {
	cases := []struct {
		target string
		match  []string
		reject []string
	}{
		{"https://Example.test/Portal/", []string{"https://example.test/Portal", "https://example.test:443/Portal/page", "https://example.test/Portal/page?q=1"}, []string{"https://example.test:8443/Portal/page", "http://example.test/Portal/page", "https://example.test/PortalElse", "https://example.test:4430/Portal/page"}},
		{"https://example.test:443/", []string{"https://example.test/", "https://example.test:443/any", "https://example.test"}, []string{"https://example.test:8443/any", "https://example.test.evil/any"}},
		{"http://example.test:80/app", []string{"http://example.test/app/x", "http://example.test:80/app"}, []string{"http://example.test:8080/app", "https://example.test/app"}},
		{"https://[::1]:8443/api", []string{"https://[::1]:8443/api/v1"}, []string{"https://[::1]/api/v1", "https://[::1]:443/api/v1"}},
	}
	for _, tc := range cases {
		pattern, err := applicationContextRegex(tc.target)
		if err != nil {
			t.Fatalf("%s: %v", tc.target, err)
		}
		compiled := regexp.MustCompile(pattern)
		for _, u := range tc.match {
			if !compiled.MatchString(u) {
				t.Errorf("%s: regex %q rejects in-scope %q", tc.target, pattern, u)
			}
		}
		for _, u := range tc.reject {
			if compiled.MatchString(u) {
				t.Errorf("%s: regex %q accepts out-of-scope %q", tc.target, pattern, u)
			}
		}
	}
	for _, bad := range []string{"ftp://example.test/", "https://user:pw@example.test/", "https://example.test/#frag", "/relative"} {
		if _, err := applicationContextRegex(bad); err == nil {
			t.Errorf("invalid application URL %q accepted", bad)
		}
	}
	// The typed run installs the same port-normalized regex as its context.
	fake := &fakeZAP{rules: map[string]bool{}, report: `{"alerts":[]}`, domXSSEnabled: "true"}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	cfg := Config{ZAPURL: srv.URL, ZAPAPIKey: "zap-key", ZAPDedicated: true, ZAPTimeout: 30 * time.Second, MaxOutputBytes: 1 << 20}
	run := zapRunner{}.Run(t.Context(), Request{Target: "https://app.example.test/", ScanDir: t.TempDir(), Scope: "app:app", TypedAssessment: true}, cfg, nil)
	if run.Status != "completed" {
		t.Fatalf("typed run = %+v", run)
	}
	fake.mu.Lock()
	contextRegex := fake.contextRegex
	fake.mu.Unlock()
	if re := regexp.MustCompile(contextRegex); !re.MatchString("https://app.example.test:443/login") || !re.MatchString("https://app.example.test/login") {
		t.Fatalf("ZAP context regex %q does not normalize the default port", contextRegex)
	}
}

func zapTestScope(t *testing.T, target string, exclusions ...assessment.Exclusion) *assessment.AppScope {
	t.Helper()
	origin, err := assessment.ParseApprovedOrigin("app", target)
	if err != nil {
		t.Fatal(err)
	}
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin}, exclusions...)
	return &scope
}

func anyRegexMatches(t *testing.T, patterns []string, u string) bool {
	t.Helper()
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			t.Fatalf("invalid ZAP exclusion regex %q: %v", p, err)
		}
		if re.MatchString(u) {
			return true
		}
	}
	return false
}

func TestZAPExclusionsAppliedToContextSpiderAndScan(t *testing.T) {
	exclusions := []assessment.Exclusion{
		{PathPattern: "/Portal/admin", Reason: "operator: admin console"},
		{PathPattern: "/Portal/logout*"},
		{Method: "DELETE", PathPattern: "/Portal/api/users"},
		{Origin: "https://other.example.test", PathPattern: "/Portal/billing"},
	}
	check := func(t *testing.T, label string, patterns []string) {
		t.Helper()
		for _, excluded := range []string{
			"https://app.example.test/Portal/admin",
			"https://app.example.test:443/Portal/ADMIN/users?x=1",
			"https://app.example.test/Portal/logout-now",
			"https://app.example.test/Portal/api/users",
		} {
			if !anyRegexMatches(t, patterns, excluded) {
				t.Errorf("%s exclusions %q do not cover %q", label, patterns, excluded)
			}
		}
		for _, allowed := range []string{
			"https://app.example.test/Portal/administrator",
			"https://app.example.test/Portal/",
			"https://app.example.test/Portal/billing",
			"https://app.example.test/Portal/search?next=/Portal/admin",
		} {
			if anyRegexMatches(t, patterns, allowed) {
				t.Errorf("%s exclusions %q wrongly cover %q", label, patterns, allowed)
			}
		}
	}

	t.Run("typed", func(t *testing.T) {
		fake := &fakeZAP{rules: map[string]bool{}, report: `{"alerts":[]}`, domXSSEnabled: "true"}
		srv := httptest.NewServer(fake)
		defer srv.Close()
		target := "https://app.example.test/Portal/"
		req := Request{Target: target, ScanDir: t.TempDir(), Scope: "app:app", TypedAssessment: true, AppScope: zapTestScope(t, target, exclusions...),
			EndpointTargets: []string{"https://app.example.test/Portal/admin/panel", "https://app.example.test/Portal/search?q=1"}}
		cfg := Config{ZAPURL: srv.URL, ZAPAPIKey: "zap-key", ZAPDedicated: true, ZAPTimeout: 30 * time.Second, WebMaxEndpoints: 10, MaxOutputBytes: 1 << 20}
		run := zapRunner{}.Run(t.Context(), req, cfg, nil)
		if run.Status != "completed" {
			t.Fatalf("typed run = %+v", run)
		}
		fake.mu.Lock()
		contextExcludes := append([]string(nil), fake.contextExcludes...)
		spiderDuring, ascanDuring := fake.spiderExclDuring, fake.ascanExclDuring
		spiderAfter, ascanAfter := fake.spiderExcludes, fake.ascanExcludes
		accessed := append([]string(nil), fake.accessedURLs...)
		fake.mu.Unlock()
		check(t, "context", contextExcludes)
		check(t, "spider", spiderDuring)
		check(t, "active scan", ascanDuring)
		if len(spiderAfter) != 0 || len(ascanAfter) != 0 {
			t.Errorf("daemon-global exclusions were left behind: spider=%v ascan=%v", spiderAfter, ascanAfter)
		}
		if slices.Contains(accessed, "https://app.example.test/Portal/admin/panel") {
			t.Errorf("excluded endpoint was seeded into ZAP: %v", accessed)
		}
		if !slices.Contains(accessed, "https://app.example.test/Portal/search?q=1") {
			t.Errorf("allowed endpoint was not seeded: %v", accessed)
		}
	})

	t.Run("legacy", func(t *testing.T) {
		fake := &fakeZAP{rules: map[string]bool{}, report: `{"alerts":[]}`, spiderExcludes: []string{"^prior-spider$"}, ascanExcludes: []string{"^prior-ascan$"}}
		srv := httptest.NewServer(fake)
		defer srv.Close()
		target := "https://app.example.test/Portal/"
		req := Request{Target: target, ScanDir: t.TempDir(), AppScope: zapTestScope(t, target, exclusions...)}
		cfg := Config{ZAPURL: srv.URL, ZAPAPIKey: "zap-key", ZAPTimeout: 30 * time.Second, MaxOutputBytes: 1 << 20}
		run := zapRunner{}.Run(t.Context(), req, cfg, nil)
		if run.Status != "completed" {
			t.Fatalf("legacy run = %+v", run)
		}
		fake.mu.Lock()
		spiderDuring, ascanDuring := fake.spiderExclDuring, fake.ascanExclDuring
		spiderAfter, ascanAfter := fake.spiderExcludes, fake.ascanExcludes
		fake.mu.Unlock()
		check(t, "spider", spiderDuring)
		check(t, "active scan", ascanDuring)
		if !slices.Contains(spiderDuring, "^prior-spider$") || !slices.Contains(ascanDuring, "^prior-ascan$") {
			t.Errorf("existing daemon exclusions were dropped during the scan: spider=%v ascan=%v", spiderDuring, ascanDuring)
		}
		if !slices.Equal(spiderAfter, []string{"^prior-spider$"}) || !slices.Equal(ascanAfter, []string{"^prior-ascan$"}) {
			t.Errorf("daemon exclusions not restored: spider=%v ascan=%v", spiderAfter, ascanAfter)
		}
	})

	t.Run("no exclusions leaves daemon lists alone", func(t *testing.T) {
		fake := &fakeZAP{rules: map[string]bool{}, report: `{"alerts":[]}`}
		srv := httptest.NewServer(fake)
		defer srv.Close()
		run := zapRunner{}.Run(t.Context(), Request{Target: "http://example.test", ScanDir: t.TempDir()}, Config{ZAPURL: srv.URL, ZAPAPIKey: "zap-key", ZAPTimeout: 30 * time.Second, MaxOutputBytes: 1 << 20}, nil)
		if run.Status != "completed" || fake.called("/JSON/spider/action/clearExcludedFromScan/") || fake.called("/JSON/ascan/action/excludeFromScan/") {
			t.Fatalf("scan without exclusions touched daemon exclusion state: %+v %v", run, fake.paths)
		}
	})
}

func TestZAPRateDelayFromRateRPSRestored(t *testing.T) {
	for _, tc := range []struct {
		rps   int
		delay string
	}{{4, "250"}, {3, "334"}, {150, "7"}, {2000, "1"}} {
		fake := &fakeZAP{rules: map[string]bool{}, report: `{"alerts":[]}`, domXSSEnabled: "true", delayInMs: "15", threadPerHost: "4"}
		srv := httptest.NewServer(fake)
		cfg := Config{ZAPURL: srv.URL, ZAPAPIKey: "zap-key", ZAPDedicated: true, ZAPTimeout: 30 * time.Second, RateRPS: tc.rps, MaxOutputBytes: 1 << 20}
		run := zapRunner{}.Run(t.Context(), Request{Target: "https://app.example.test/", ScanDir: t.TempDir(), Scope: "app:app", TypedAssessment: true}, cfg, nil)
		fake.mu.Lock()
		during, threads, after, threadsAfter := fake.delayDuringScan, fake.threadsDuringScan, fake.delayInMs, fake.threadPerHost
		fake.mu.Unlock()
		srv.Close()
		if run.Status != "completed" {
			t.Fatalf("rps=%d run = %+v", tc.rps, run)
		}
		if during != tc.delay || threads != "1" {
			t.Errorf("rps=%d: active scan ran with delay=%q threadPerHost=%q, want %s/1", tc.rps, during, threads, tc.delay)
		}
		if after != "15" || threadsAfter != "4" {
			t.Errorf("rps=%d: daemon rate options not restored: delay=%q threadPerHost=%q", tc.rps, after, threadsAfter)
		}
	}

	// RateRPS unset keeps the daemon's options untouched.
	fake := &fakeZAP{rules: map[string]bool{}, report: `{"alerts":[]}`}
	srv := httptest.NewServer(fake)
	run := zapRunner{}.Run(t.Context(), Request{Target: "http://example.test", ScanDir: t.TempDir()}, Config{ZAPURL: srv.URL, ZAPAPIKey: "zap-key", ZAPTimeout: 30 * time.Second, MaxOutputBytes: 1 << 20}, nil)
	srv.Close()
	if run.Status != "completed" || fake.called("/JSON/ascan/action/setOptionDelayInMs/") {
		t.Fatalf("rate options changed without a configured rate: %+v", run)
	}

	// A failed restore of daemon-global options quarantines a dedicated daemon.
	fake = &fakeZAP{rules: map[string]bool{}, report: `{"alerts":[]}`, domXSSEnabled: "true", restoreDelayFails: true}
	srv = httptest.NewServer(fake)
	defer srv.Close()
	cfg := Config{ZAPURL: srv.URL, ZAPAPIKey: "zap-key", ZAPDedicated: true, ZAPTimeout: 30 * time.Second, RateRPS: 5, MaxOutputBytes: 1 << 20}
	run = zapRunner{}.Run(t.Context(), Request{Target: "https://app.example.test/", ScanDir: t.TempDir(), Scope: "app:app", TypedAssessment: true}, cfg, nil)
	if run.Status != "completed" || !ZAPServiceQuarantined(srv.URL) {
		t.Fatalf("rate restore failure did not quarantine the daemon: run=%+v quarantined=%t", run, ZAPServiceQuarantined(srv.URL))
	}
}

func TestZAPSessionLossRecordsAuthExpiredStructurally(t *testing.T) {
	previous := zapAuthInterval
	zapAuthInterval = 0
	t.Cleanup(func() { zapAuthInterval = previous })
	newRun := func(t *testing.T, refresh func(context.Context, []string) ([]string, error)) Run {
		t.Helper()
		fake := &fakeZAP{rules: map[string]bool{}, report: `{"alerts":[]}`, domXSSEnabled: "true"}
		srv := httptest.NewServer(fake)
		defer srv.Close()
		cfg := Config{ZAPURL: srv.URL, ZAPAPIKey: "zap-key", ZAPDedicated: true, ZAPTimeout: 30 * time.Second, MaxOutputBytes: 1 << 20}
		req := Request{Target: "https://example.test/app/", ScanDir: t.TempDir(), Scope: "app:one", TypedAssessment: true, TargetAuth: "Cookie: session-secret", AuthKind: "form login", AuthRefresh: refresh}
		return runAttempt(t.Context(), zapRunner{}, req, cfg, nil)
	}

	checks := 0
	expired := newRun(t, func(ctx context.Context, current []string) ([]string, error) {
		checks++
		if checks > 2 {
			return nil, fmt.Errorf("private-password rejected")
		}
		return current, nil
	})
	if expired.Status != "failed" || expired.AuthState != assessment.StateExpired || expired.GapKind != GapAuthExpired {
		t.Fatalf("mid-scan session loss not recorded structurally: status=%s auth=%q gap=%q reason=%q", expired.Status, expired.AuthState, expired.GapKind, expired.Reason)
	}
	if _, err := time.Parse(time.RFC3339, expired.AuthCheckedAt); err != nil {
		t.Errorf("AuthCheckedAt %q is not RFC 3339: %v", expired.AuthCheckedAt, err)
	}
	if !strings.Contains(expired.Reason, "authenticated session") || strings.Contains(expired.Reason, "private-password") {
		t.Errorf("expiry reason unsafe or missing legacy wording: %q", expired.Reason)
	}

	rejected := newRun(t, func(ctx context.Context, current []string) ([]string, error) {
		return nil, fmt.Errorf("rejected")
	})
	if rejected.Status != "failed" || rejected.AuthState != assessment.StateFailed || rejected.GapKind != GapAuthFailed {
		t.Fatalf("initial verification failure must be auth failed, not expired: auth=%q gap=%q", rejected.AuthState, rejected.GapKind)
	}

	verified := newRun(t, func(ctx context.Context, current []string) ([]string, error) { return current, nil })
	if verified.Status != "completed" || verified.AuthState != assessment.StateVerified || verified.GapKind != "" || verified.AuthCheckedAt == "" {
		t.Fatalf("active session not recorded as verified: status=%s auth=%q gap=%q checked=%q", verified.Status, verified.AuthState, verified.GapKind, verified.AuthCheckedAt)
	}
}

func TestZAPApprovedContextAndExportCoverMultipleOrigins(t *testing.T) {
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{{Scheme: "https", Host: "app.test", Port: 443, PathPrefix: "/app"}, {Scheme: "https", Host: "api.test", Port: 8443, PathPrefix: "/v1"}})
	pattern, err := zapApprovedContextRegex(scope)
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(pattern)
	for _, raw := range []string{"https://app.test/app/a", "https://api.test:8443/v1/users"} {
		if !re.MatchString(raw) {
			t.Fatal(raw)
		}
	}
	if re.MatchString("https://api.test:8443/admin") {
		t.Fatal("path scope widened")
	}
	out, err := filterZAPScopeAlerts([]byte(`{"alerts":[{"url":"https://app.test/app/a"},{"url":"https://api.test:8443/v1/users"},{"url":"https://outside.test/"}]}`), scope)
	if err != nil || strings.Contains(string(out), "outside.test") || !strings.Contains(string(out), "api.test") {
		t.Fatalf("%s %v", out, err)
	}
}
