package scanner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestBuildFindingsSnapshotHostAndParameterCorrelation(t *testing.T) {
	runs := make([]Run, 0, 50)
	for i := 0; i < 50; i++ {
		path := fmt.Sprintf("https://target.test/path/%d", i)
		artifact := writeFixture(t, fmt.Sprintf("zap-%d.json", i), fmt.Sprintf(`{"alerts":[{"pluginId":"10038","name":"Content Security Policy (CSP) Header Not Set","riskdesc":"Medium","cweid":"693","instances":[{"uri":%q,"method":"GET"}]}]}`, path))
		runs = append(runs, Run{Scanner: "zap", Scope: "host:target.test", Status: "completed", ArtifactPath: artifact, FinishedAt: "2026-01-01T00:00:00Z"})
	}
	snapshot, errs := BuildFindingsSnapshot(runs, nil)
	if len(errs) != 0 {
		t.Fatalf("errors = %v", errs)
	}
	if snapshot.Summary.RawObservations != 50 || snapshot.Summary.UniqueFindings != 1 {
		t.Fatalf("summary = %+v", snapshot.Summary)
	}
	if got := snapshot.UniqueFindings[0].AffectedEndpointCount; got != 50 {
		t.Fatalf("endpoints = %d", got)
	}
}

func TestBuildFindingsSnapshotParameterValuesShareFinding(t *testing.T) {
	legacy := []Finding{
		{SourceID: "zap:1", Scanner: "zap", Title: "SQL Injection", Severity: "high", Target: "target.test", Endpoint: "https://target.test/product?id=1", Method: "GET", Parameter: "id"},
		{SourceID: "zap:2", Scanner: "zap", Title: "SQL Injection", Severity: "high", Target: "target.test", Endpoint: "https://target.test/product?id=2", Method: "GET", Parameter: "id"},
		{SourceID: "zap:3", Scanner: "zap", Title: "SQL Injection", Severity: "high", Target: "target.test", Endpoint: "https://target.test/product?id=3", Method: "GET", Parameter: "id"},
	}
	snapshot, errs := BuildFindingsSnapshot(nil, legacy)
	if len(errs) != 0 || len(snapshot.UniqueFindings) != 1 {
		t.Fatalf("snapshot = %#v errors=%v", snapshot, errs)
	}
	if snapshot.UniqueFindings[0].ObservationCount != 3 {
		t.Fatalf("observations = %d", snapshot.UniqueFindings[0].ObservationCount)
	}
}

func TestBuildFindingsSnapshotTechnologyIsObservation(t *testing.T) {
	snapshot, errs := BuildFindingsSnapshot(nil, []Finding{{SourceID: "nuclei:tech", Scanner: "nuclei", Title: "Wappalyzer Technology Detection", Severity: "info", Target: "target.test", Endpoint: "https://target.test/"}})
	if len(errs) != 0 || len(snapshot.UniqueFindings) != 1 {
		t.Fatalf("snapshot = %#v errors=%v", snapshot, errs)
	}
	if snapshot.UniqueFindings[0].Status != StatusObservation || snapshot.Summary.ActiveSecurityFindings != 0 {
		t.Fatalf("finding = %#v summary=%+v", snapshot.UniqueFindings[0], snapshot.Summary)
	}
}

func TestValidateSPAFallbackMatchesCanary(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body>single app shell</body></html>"))
	}))
	defer server.Close()
	snapshot, _ := BuildFindingsSnapshot(nil, []Finding{{SourceID: "nikto:1", Scanner: "nikto", Title: "Exposed .env file", Severity: "medium", Endpoint: server.URL + "/.env", Target: "127.0.0.1"}})
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{mustOrigin(t, server.URL)})
	results := ValidateSPAFallback(t.Context(), snapshot, FallbackValidationOptions{Scope: scope})
	if len(results) != 1 || results[0].Reason != FallbackReasonMatched || !results[0].Matched() {
		t.Fatalf("results = %#v", results)
	}
	dir := t.TempDir()
	if err := SaveFallbackValidations(dir, results); err != nil {
		t.Fatal(err)
	}
	loaded, ok := LoadFallbackValidations(dir)
	if !ok || len(loaded) != 1 || loaded[0].Fingerprint != results[0].Fingerprint {
		t.Fatalf("loaded = %#v ok=%v", loaded, ok)
	}
	if changed := ApplyFallbackValidations(snapshot, loaded); changed != 1 || snapshot.UniqueFindings[0].Status != StatusLikelyFalsePositive || snapshot.UniqueFindings[0].ValidationReason != FallbackReasonMatched {
		t.Fatalf("changed=%d finding=%#v", changed, snapshot.UniqueFindings[0])
	}
}

func mustOrigin(t *testing.T, raw string) assessment.ApprovedOrigin {
	t.Helper()
	o, err := assessment.ParseApprovedOrigin("app", raw)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestSPAFallbackValidationRespectsScopeExclusionsAndBudget(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	shell := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.Host+r.URL.Path]++
		mu.Unlock()
		if r.URL.Path == "/debug/redirect" {
			http.Redirect(w, r, "/redirected", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>app shell</html>"))
	}
	inScope := httptest.NewServer(http.HandlerFunc(shell))
	defer inScope.Close()
	outside := httptest.NewServer(http.HandlerFunc(shell))
	defer outside.Close()
	count := func(server *httptest.Server) int {
		mu.Lock()
		defer mu.Unlock()
		host := strings.TrimPrefix(server.URL, "http://")
		n := 0
		for k, v := range hits {
			if strings.HasPrefix(k, host+"/") {
				n += v
			}
		}
		return n
	}
	snapshot, _ := BuildFindingsSnapshot(nil, []Finding{
		{SourceID: "nikto:env", Scanner: "nikto", Title: "Exposed .env file", Severity: "medium", Endpoint: inScope.URL + "/.env", Target: "127.0.0.1"},
		{SourceID: "nikto:backup", Scanner: "nikto", Title: "Backup archive", Severity: "medium", Endpoint: inScope.URL + "/backup.zip", Target: "127.0.0.1"},
		{SourceID: "nikto:guard", Scanner: "nikto", Title: "Actuator exposed", Severity: "medium", Endpoint: inScope.URL + "/actuator/env", Target: "127.0.0.1"},
		{SourceID: "nikto:redirect", Scanner: "nikto", Title: "Debug console", Severity: "medium", Endpoint: inScope.URL + "/debug/redirect", Target: "127.0.0.1"},
		{SourceID: "nikto:outside", Scanner: "nikto", Title: "Exposed .htaccess", Severity: "medium", Endpoint: outside.URL + "/.htaccess", Target: "127.0.0.1"},
	})
	origin := mustOrigin(t, inScope.URL)
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin}, assessment.Exclusion{TargetID: "app", PathPattern: "/backup.zip", Reason: "operator excluded"})
	guard := func(raw string, _ []string) (bool, string) {
		if strings.Contains(raw, "/actuator") {
			return true, "guarded"
		}
		return false, ""
	}
	results := ValidateSPAFallback(t.Context(), snapshot, FallbackValidationOptions{Scope: scope, Budget: NewAssessmentBudget(1000, 0, time.Minute), ScopeGuard: guard})
	reasons := map[string]string{}
	for _, r := range results {
		reasons[r.Endpoint] = r.Reason
	}
	want := map[string]string{
		inScope.URL + "/.env":           FallbackReasonMatched,
		inScope.URL + "/backup.zip":     FallbackReasonExcluded,
		inScope.URL + "/actuator/env":   FallbackReasonScopeGuard,
		inScope.URL + "/debug/redirect": FallbackReasonDiffered,
		outside.URL + "/.htaccess":      FallbackReasonOutOfScope,
	}
	for endpoint, reason := range want {
		if reasons[endpoint] != reason {
			t.Errorf("%s reason = %q, want %q (all %#v)", endpoint, reasons[endpoint], reason, reasons)
		}
	}
	if n := count(outside); n != 0 {
		t.Fatalf("out-of-scope origin received %d requests", n)
	}
	mu.Lock()
	backupHits, guardHits, redirectedHits := hits[strings.TrimPrefix(inScope.URL, "http://")+"/backup.zip"], hits[strings.TrimPrefix(inScope.URL, "http://")+"/actuator/env"], hits[strings.TrimPrefix(inScope.URL, "http://")+"/redirected"]
	mu.Unlock()
	if backupHits != 0 || guardHits != 0 {
		t.Fatalf("excluded=%d guarded=%d requests, want none", backupHits, guardHits)
	}
	if redirectedHits != 0 {
		t.Fatalf("redirect was followed %d times", redirectedHits)
	}

	before := count(inScope)
	exhausted := NewAssessmentBudget(1000, 0, time.Nanosecond)
	time.Sleep(time.Millisecond)
	results = ValidateSPAFallback(t.Context(), snapshot, FallbackValidationOptions{Scope: scope, Budget: exhausted})
	if n := count(inScope) - before; n != 0 {
		t.Fatalf("exhausted budget still sent %d requests", n)
	}
	for _, r := range results {
		if r.Endpoint == inScope.URL+"/.env" && r.Reason != FallbackReasonBudgetExhausted {
			t.Fatalf("exhausted result = %#v", r)
		}
	}

	if results := ValidateSPAFallback(t.Context(), snapshot, FallbackValidationOptions{}); count(inScope)-before != 0 {
		t.Fatalf("zero scope sent requests; results=%#v", results)
	}
}
