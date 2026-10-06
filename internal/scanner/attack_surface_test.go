package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseKatanaAttackSurfaceNormalizesAndClassifies(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "results.jsonl")
	data := `{"timestamp":"2026-09-29T00:00:00Z","request":{"method":"GET","endpoint":"HTTP://Example.COM:80/product/?id=1","source":"http://example.com/"},"response":{"status_code":200,"headers":{"content_type":"text/html"}}}
{"timestamp":"2026-09-29T00:00:01Z","request":{"method":"GET","endpoint":"http://example.com/product?id=100","source":"http://example.com/app.js"},"response":{"status_code":200}}
{"request":{"method":"GET","endpoint":"http://example.com/#/login","source":"katana"},"response":{"status_code":200}}
{"request":{"method":"GET","endpoint":"http://example.com/assets/app.js","source":"katana"},"response":{"status_code":200,"headers":{"content-type":"application/javascript"}}}
{"request":{"method":"GET","endpoint":"http://example.com/api/private","tag":"script","attribute":"jsluice-fetch","source":"http://example.com/assets/app.js"},"response":{"status_code":401,"headers":{"content-type":"application/json"}}}
{"request":{"method":"POST","endpoint":"http://example.com/login","tag":"form","body":"username=a&csrf=b","headers":{"content-type":"application/x-www-form-urlencoded"},"source":"http://example.com/"},"response":{"status_code":200}}
not-json
`
	if err := os.WriteFile(artifact, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	surface, err := ParseKatanaAttackSurface(artifact, "app:test", "http://example.com", true)
	if err != nil {
		t.Fatal(err)
	}
	if surface.RawCount != 7 || len(surface.Endpoints) != 6 {
		t.Fatalf("raw=%d endpoints=%d: %+v", surface.RawCount, len(surface.Endpoints), surface.Endpoints)
	}
	var product, spa, js, api, form *AttackSurfaceEndpoint
	for i := range surface.Endpoints {
		ep := &surface.Endpoints[i]
		switch ep.Path {
		case "/product":
			product = ep
		case "/":
			spa = ep
		case "/assets/app.js":
			js = ep
		case "/api/private":
			api = ep
		case "/login":
			form = ep
		}
	}
	if product == nil || product.CanonicalURL != "http://example.com/product?id={value}" || len(product.Parameters) != 1 || len(product.Sources) != 1 {
		t.Fatalf("product normalization failed: %+v", product)
	}
	if spa == nil || len(spa.SPARoutes) != 1 || spa.SPARoutes[0] != "/login" || spa.CanonicalURL != "http://example.com/" {
		t.Fatalf("SPA fragment normalization failed: %+v", spa)
	}
	if js == nil || js.Kind != "static" {
		t.Fatalf("JS classification failed: %+v", js)
	}
	if api == nil || api.Kind != "api" || api.RequiresAuth == nil || !*api.RequiresAuth || !api.ObservedWithAuth {
		t.Fatalf("API/auth classification failed: %+v", api)
	}
	if form == nil || !form.HasForm || form.Method != "POST" || len(form.Parameters) != 2 || form.Parameters[0].Location != "form" {
		t.Fatalf("form extraction failed: %+v", form)
	}
}

func TestAttackSurfaceDispatchMatrix(t *testing.T) {
	surface := NewSeedAttackSurface("app:test", "https://example.test/")
	rows := []struct {
		url, method, contentType string
		hasForm                  bool
	}{
		{"https://example.test/search?q=one", "GET", "text/html", false},
		{"https://example.test/api/users", "GET", "application/json", false},
		{"https://example.test/assets/app.js", "GET", "application/javascript", false},
		{"https://example.test/login", "POST", "text/html", true},
	}
	byID := map[string]int{}
	for i := range surface.Endpoints {
		byID[surface.Endpoints[i].ID] = i
	}
	for _, row := range rows {
		ep, ok := normalizeAttackSurfaceEndpoint(row.url, row.method, "test", "", 200, row.contentType, endpointParameters(row.url), row.hasForm, false)
		if !ok {
			t.Fatalf("could not normalize %s", row.url)
		}
		mergeSurfaceEndpoint(surface, byID, ep)
	}
	if got := DispatchTargets(surface, "nuclei", 100); len(got) != 3 { // root, search, API
		t.Fatalf("nuclei targets = %v", got)
	}
	if got := DispatchTargets(surface, "zap", 100); len(got) != 2 {
		t.Fatalf("zap targets = %v", got)
	}
	if got := DispatchTargets(surface, "wapiti", 100); len(got) != 1 || got[0] != "https://example.test/search?q=one" {
		t.Fatalf("wapiti targets = %v", got)
	}
	if got := DispatchTargets(surface, "dalfox", 100); len(got) != 1 {
		t.Fatalf("dalfox targets = %v", got)
	}
}

func TestAttackSurfaceSnapshotChecksum(t *testing.T) {
	dir := t.TempDir()
	raw := filepath.Join(dir, "results.jsonl")
	if err := os.WriteFile(raw, []byte(`{"request":{"endpoint":"https://example.test/"}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	surface, err := ParseKatanaAttackSurface(raw, "app:test", "https://example.test", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveAttackSurface(dir, surface); err != nil {
		t.Fatal(err)
	}
	if _, ok := LoadAttackSurface(dir, "app:test", raw); !ok {
		t.Fatal("valid snapshot was not reused")
	}
	if err := os.WriteFile(raw, []byte(`{"request":{"endpoint":"https://example.test/changed"}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := LoadAttackSurface(dir, "app:test", raw); ok {
		t.Fatal("snapshot with stale source checksum was reused")
	}
}

func TestCompleteEndpointCoverageRecordsBatchCompletedForBatchAdapters(t *testing.T) {
	surface := NewSeedAttackSurface("app:test", "https://example.test/")
	byID := map[string]int{}
	for i := range surface.Endpoints {
		byID[surface.Endpoints[i].ID] = i
	}
	ep, _ := normalizeAttackSurfaceEndpoint("https://example.test/api/items?q=1", "GET", "katana", "", 200, "application/json", endpointParameters("https://example.test/api/items?q=1"), false, false)
	mergeSurfaceEndpoint(surface, byID, ep)
	for _, name := range []string{"nuclei", "wapiti", "dalfox", "zap"} {
		if len(DispatchTargets(surface, name, 100)) == 0 {
			t.Fatalf("%s dispatched nothing", name)
		}
		CompleteEndpointCoverage(surface, name, Run{Scanner: name, Status: "completed", FinishedAt: "2026-10-02T00:00:00Z"})
	}
	want := map[string]string{"nuclei": EndpointCoverageBatchCompleted, "wapiti": EndpointCoverageBatchCompleted, "dalfox": EndpointCoverageBatchCompleted, "zap": EndpointCoverageBatchCompleted}
	api := surface.Endpoints[byID[ep.ID]]
	for name, status := range want {
		var got string
		for _, c := range api.ScannerCoverage {
			if c.Scanner == name {
				got = c.Status
			}
		}
		if got != status {
			t.Errorf("%s coverage status = %q, want %q", name, got, status)
		}
	}
	// A failed batch run is still recorded as failed, not batch_completed.
	DispatchTargets(surface, "nuclei", 100)
	CompleteEndpointCoverage(surface, "nuclei", Run{Scanner: "nuclei", Status: "failed", Reason: "exit 1"})
	for _, c := range surface.Endpoints[byID[ep.ID]].ScannerCoverage {
		if c.Scanner == "nuclei" && c.Status != "failed" {
			t.Fatalf("failed nuclei run recorded %q", c.Status)
		}
	}
}

func TestClassifierVersionBumpReparsesCachedSnapshot(t *testing.T) {
	if AttackSurfaceClassifierVersion != 6 {
		t.Fatalf("classifier version = %d, want 6", AttackSurfaceClassifierVersion)
	}
	dir := t.TempDir()
	raw := filepath.Join(dir, "results.jsonl")
	if err := os.WriteFile(raw, []byte(`{"request":{"endpoint":"https://example.test/users/%7Bid%7D"}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	surface, err := ParseKatanaAttackSurface(raw, "app:test", "https://example.test", false)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a snapshot cached by the previous classifier with the same
	// source checksum: it must not be reused, so the caller re-parses the raw
	// JSONL (no network) under the new eligibility semantics.
	surface.ClassifierVersion = 5
	if err := SaveAttackSurface(dir, surface); err != nil {
		t.Fatal(err)
	}
	if _, ok := LoadAttackSurface(dir, "app:test", raw); ok {
		t.Fatal("classifier v4 snapshot was reused")
	}
	reparsed, err := ParseKatanaAttackSurface(raw, "app:test", "https://example.test", false)
	if err != nil || reparsed.ClassifierVersion != AttackSurfaceClassifierVersion {
		t.Fatalf("reparse = %+v, %v", reparsed, err)
	}
	if err := SaveAttackSurface(dir, reparsed); err != nil {
		t.Fatal(err)
	}
	if _, ok := LoadAttackSurface(dir, "app:test", raw); !ok {
		t.Fatal("re-parsed snapshot was not reused")
	}
	if got := DispatchTargets(reparsed, "nuclei", 100); len(got) != 0 {
		t.Fatalf("re-parsed placeholder endpoint dispatched: %v", got)
	}
}
