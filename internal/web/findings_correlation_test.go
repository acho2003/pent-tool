package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

func fallbackTestRecord(target, endpoint string) *ScanRecord {
	return &ScanRecord{SchemaVersion: scanner.SchemaVersion, ID: "fallback-validation", Target: target, StartedAt: "2026-10-02T00:00:00Z", FinishedAt: "2026-10-02T00:01:00Z", Status: "finished", Events: []WSEvent{}, Vulns: []VulnSummary{{ID: "nikto:env", Title: "Exposed .env file", Severity: "medium", Target: target, Endpoint: endpoint, Method: "GET", Scanners: []string{"nikto"}}}}
}

func TestFindingsRebuildOutsideScanMakesNoNetworkRequests(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body>single app shell</body></html>"))
	}))
	defer target.Close()
	s := newTestServer(t, nil)
	dir := t.TempDir()
	rec := fallbackTestRecord(target.URL, target.URL+"/.env")

	snapshot, errs := rebuildFindingsSnapshot(rec, dir, true)
	if len(errs) != 0 || snapshot == nil || len(snapshot.UniqueFindings) != 1 {
		t.Fatalf("snapshot = %#v errs=%v", snapshot, errs)
	}
	if snapshot.UniqueFindings[0].Status != scanner.StatusPotential {
		t.Fatalf("status without stored validation = %s", snapshot.UniqueFindings[0].Status)
	}
	if path := s.generateScannerReport(rec, dir, ""); path == "" {
		t.Fatal("expected report")
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("rebuild/report outside a scan sent %d requests", n)
	}
	if _, ok := scanner.LoadFallbackValidations(dir); ok {
		t.Fatal("rebuild must not create validation results")
	}

	// Scan finalisation is the only step that contacts the target.
	if err := validateScanFallback(t.Context(), rec, dir, scanner.NewAssessmentBudget(100, 0, time.Minute), nil); err != nil {
		t.Fatal(err)
	}
	if hits.Load() == 0 {
		t.Fatal("finalisation validation sent no requests")
	}
	if _, err := os.Stat(scanner.FallbackValidationPath(dir)); err != nil {
		t.Fatalf("validation results not persisted: %v", err)
	}

	hits.Store(0)
	snapshot, _ = rebuildFindingsSnapshot(rec, dir, true)
	if snapshot.UniqueFindings[0].Status != scanner.StatusLikelyFalsePositive || snapshot.UniqueFindings[0].ValidationReason != scanner.FallbackReasonMatched {
		t.Fatalf("stored validation not reused: %#v", snapshot.UniqueFindings[0])
	}
	if snapshot.Summary.ActiveSecurityFindings != 0 {
		t.Fatalf("summary = %+v", snapshot.Summary)
	}
	if path := s.generateScannerReport(rec, dir, ""); path == "" {
		t.Fatal("expected regenerated report")
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("rebuild/report reusing stored results sent %d requests", n)
	}
}

func TestScanFallbackValidationStaysInsideTypedAssessmentScope(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>shell</html>"))
	}))
	defer target.Close()
	dir := t.TempDir()
	rec := fallbackTestRecord(target.URL, target.URL+"/.env")
	// The typed assessment approves a different origin, so the legacy-looking
	// record target must not widen the validation boundary.
	rec.Assessment = &assessment.AssessmentConfig{Targets: []assessment.Target{{ID: "web", Kind: assessment.KindURL, Value: "https://app.example.test/"}}}
	if err := validateScanFallback(t.Context(), rec, dir, nil, nil); err != nil {
		t.Fatal(err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("out-of-scope validation sent %d requests", n)
	}
	results, ok := scanner.LoadFallbackValidations(dir)
	if !ok || len(results) != 1 || results[0].Reason != scanner.FallbackReasonOutOfScope {
		t.Fatalf("results = %#v ok=%v", results, ok)
	}
}
