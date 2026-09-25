package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

func TestScannerStatusListsCatalog(t *testing.T) {
	s := newTestServer(t, nil)
	rr := httptest.NewRecorder()
	s.handleScannerStatus(rr, httptest.NewRequest(http.MethodGet, "/api/scanners/status", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	var body struct {
		Scanners []struct {
			Name       string `json:"name"`
			Phase      string `json:"phase"`
			Selectable bool   `json:"selectable"`
			Summary    string `json:"summary"`
			Available  *bool  `json:"available"`
		} `json:"scanners"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, sc := range body.Scanners {
		names = append(names, sc.Name)
		if sc.Phase == "" || sc.Summary == "" || sc.Available == nil {
			t.Errorf("%s missing phase/summary/available: %+v", sc.Name, sc)
		}
	}
	want := []string{"subfinder", "httpx", "nmap", "nuclei", "zap", "testssl", "openvas", "vuls", "trivy", "semgrep", "gitleaks", "osv"}
	if !slices.Equal(names, want) {
		t.Fatalf("names = %v, want %v", names, want)
	}
	if body.Scanners[0].Selectable || !body.Scanners[3].Selectable {
		t.Fatalf("recon must not be selectable, nuclei must be: %+v", body.Scanners[:4])
	}
}

// saveScannerScan writes a schema-v2 scan record under s.dataDir so
// findScanByID finds it, returning its scan dir.
func saveScannerScan(t *testing.T, s *Server, id string, runs func(dir string) []scanner.Run) string {
	t.Helper()
	dir := filepath.Join(s.dataDir, "example.test", "2026-09-25", id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	rec := &ScanRecord{SchemaVersion: scanner.SchemaVersion, ID: id, Target: "example.test", Status: "finished", ScannerRuns: runs(dir), Events: []WSEvent{}, Vulns: []VulnSummary{}}
	s.saveScanRecordTo(rec, dir)
	return dir
}

func writeFile(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScannerOutputSelectsRunByScope(t *testing.T) {
	s := newTestServer(t, nil)
	saveScannerScan(t, s, "scope-out", func(dir string) []scanner.Run {
		return []scanner.Run{
			{Scanner: "nuclei", Scope: "host:a.test", Target: "a.test", Status: "completed", StdoutPath: writeFile(t, filepath.Join(dir, "hosts", "a.test", "nuclei.out"), "output for A")},
			{Scanner: "nuclei", Scope: "host:b.test", Target: "b.test", Status: "completed", StdoutPath: writeFile(t, filepath.Join(dir, "hosts", "b.test", "nuclei.out"), "output for B")},
		}
	})
	get := func(url string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		s.handleScannerOutput(rr, httptest.NewRequest(http.MethodGet, url, nil))
		return rr
	}
	if rr := get("/api/scans/scope-out/output/nuclei/stdout?scope=host:b.test"); rr.Code != 200 || rr.Body.String() != "output for B" {
		t.Fatalf("scoped: %d %q", rr.Code, rr.Body.String())
	}
	if rr := get("/api/scans/scope-out/output/nuclei/stdout"); rr.Code != 200 || rr.Body.String() != "output for A" {
		t.Fatalf("unscoped must keep first-run behaviour: %d %q", rr.Code, rr.Body.String())
	}
	if rr := get("/api/scans/scope-out/output/nuclei/stdout?scope=host:nope"); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown scope: %d", rr.Code)
	}
}

// TestScannerOutputMatchesLegacyRunByHostScope locks in that a pre-scope
// (Increment-1) run with an empty Scope still answers a ?scope=host:<target>
// request, via scanner.FindingScope's empty-Scope fold to the target's host
// scope.
func TestScannerOutputMatchesLegacyRunByHostScope(t *testing.T) {
	s := newTestServer(t, nil)
	saveScannerScan(t, s, "legacy-scope", func(dir string) []scanner.Run {
		return []scanner.Run{
			{Scanner: "nuclei", Scope: "", Target: "legacy.test", Status: "completed", StdoutPath: writeFile(t, filepath.Join(dir, "nuclei.out"), "legacy output")},
		}
	})
	rr := httptest.NewRecorder()
	s.handleScannerOutput(rr, httptest.NewRequest(http.MethodGet, "/api/scans/legacy-scope/output/nuclei/stdout?scope=host:legacy.test", nil))
	if rr.Code != 200 || rr.Body.String() != "legacy output" {
		t.Fatalf("legacy run by host scope: %d %q", rr.Code, rr.Body.String())
	}
}

// TestScannerOutputMatchesPerHostReconRunByHostScope locks in that a per-host
// recon run (Scope "recon:<target>:<host>") answers a ?scope=host:<host>
// request, folding via scanner.FindingScope the same way the report's Scan
// Coverage section groups it under its host.
func TestScannerOutputMatchesPerHostReconRunByHostScope(t *testing.T) {
	s := newTestServer(t, nil)
	saveScannerScan(t, s, "recon-scope", func(dir string) []scanner.Run {
		return []scanner.Run{
			{Scanner: "nmap", Scope: "recon:example.test:a.example.test", Target: "example.test", Status: "completed", StdoutPath: writeFile(t, filepath.Join(dir, "nmap.out"), "nmap for a")},
		}
	})
	rr := httptest.NewRecorder()
	s.handleScannerOutput(rr, httptest.NewRequest(http.MethodGet, "/api/scans/recon-scope/output/nmap/stdout?scope=host:a.example.test", nil))
	if rr.Code != 200 || rr.Body.String() != "nmap for a" {
		t.Fatalf("per-host recon run by host scope: %d %q", rr.Code, rr.Body.String())
	}
}

// TestScannerArtifactSelectsRunByScope mirrors
// TestScannerOutputSelectsRunByScope for the artifact endpoint: ?scope=
// picks one host's artifact file, and without it the first run by name wins.
func TestScannerArtifactSelectsRunByScope(t *testing.T) {
	s := newTestServer(t, nil)
	saveScannerScan(t, s, "artifact-scope", func(dir string) []scanner.Run {
		return []scanner.Run{
			{Scanner: "nuclei", Scope: "host:a.test", Target: "a.test", Status: "completed", ArtifactPath: writeFile(t, filepath.Join(dir, "hosts", "a.test", "nuclei.jsonl"), "artifact for A")},
			{Scanner: "nuclei", Scope: "host:b.test", Target: "b.test", Status: "completed", ArtifactPath: writeFile(t, filepath.Join(dir, "hosts", "b.test", "nuclei.jsonl"), "artifact for B")},
		}
	})
	get := func(url string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		s.handleScannerOutput(rr, httptest.NewRequest(http.MethodGet, url, nil))
		return rr
	}
	if rr := get("/api/scans/artifact-scope/nuclei/artifact?scope=host:b.test"); rr.Code != 200 || rr.Body.String() != "artifact for B" {
		t.Fatalf("scoped artifact: %d %q", rr.Code, rr.Body.String())
	}
	if rr := get("/api/scans/artifact-scope/nuclei/artifact"); rr.Code != 200 || rr.Body.String() != "artifact for A" {
		t.Fatalf("unscoped artifact must keep first-run behaviour: %d %q", rr.Code, rr.Body.String())
	}
}

func TestScanScopesEndpoint(t *testing.T) {
	s := newTestServer(t, nil)
	saveScannerScan(t, s, "scopes-1", func(dir string) []scanner.Run {
		return []scanner.Run{
			{Scanner: "subfinder", Scope: "recon:example.test", Target: "example.test", Status: "completed"},
			{Scanner: "nmap", Scope: "recon:example.test:a.example.test", Target: "example.test", Status: "completed"},
			{Scanner: "nuclei", Scope: "host:a.example.test", Target: "a.example.test", Status: "completed", ArtifactPath: writeFile(t, filepath.Join(dir, "n.jsonl"), "{}\n"), Truncated: true},
			{Scanner: "trivy", Scope: "source:main", Target: "", Status: "not_applicable", Reason: "no source"},
		}
	})
	rr := httptest.NewRecorder()
	s.handleScanScopes(rr, httptest.NewRequest(http.MethodGet, "/api/scans/scopes-1/scopes", nil))
	if rr.Code != 200 {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Recon  []reportScopeRun `json:"recon"`
		Scopes []reportScope    `json:"scopes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Recon) != 1 || body.Recon[0].Scanner != "subfinder" || body.Recon[0].Scope != "recon:example.test" {
		t.Fatalf("recon = %+v (per-host nmap belongs to its host)", body.Recon)
	}
	if len(body.Scopes) != 2 || body.Scopes[0].ID != "host:a.example.test" || body.Scopes[1].ID != "source:main" {
		t.Fatalf("scopes = %+v", body.Scopes)
	}
	host := body.Scopes[0]
	if len(host.Runs) != 2 || host.Runs[0].Scanner != "nmap" || host.Runs[0].Scope != "recon:example.test:a.example.test" {
		t.Fatalf("host runs = %+v", host.Runs)
	}
	if n := host.Runs[1]; n.Scanner != "nuclei" || !n.HasArtifact || !n.Truncated || n.Scope != "host:a.example.test" {
		t.Fatalf("nuclei run = %+v", n)
	}
	legacy := httptest.NewRecorder()
	legacyDir := filepath.Join(s.dataDir, "old.test", "2026-01-01", "legacy-1")
	_ = os.MkdirAll(legacyDir, 0o700)
	s.saveScanRecordTo(&ScanRecord{SchemaVersion: 1, ID: "legacy-1", Target: "old.test", Status: "finished", Events: []WSEvent{}, Vulns: []VulnSummary{}}, legacyDir)
	s.handleScanScopes(legacy, httptest.NewRequest(http.MethodGet, "/api/scans/legacy-1/scopes", nil))
	if legacy.Code != 200 || legacy.Body.String() != "{\"recon\":[],\"scopes\":[]}\n" {
		t.Fatalf("legacy: %d %q", legacy.Code, legacy.Body.String())
	}
	missing := httptest.NewRecorder()
	s.handleScanScopes(missing, httptest.NewRequest(http.MethodGet, "/api/scans/nope/scopes", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing scan: %d", missing.Code)
	}
}

func TestIsScanScopesPath(t *testing.T) {
	cases := map[string]bool{
		"/api/scans/abc/scopes":       true,
		"/api/scans/abc/vulns/scopes": false,
		"/api/scans//scopes":          false,
		"/api/scans/abc/scopes/x":     false,
		"/api/scans/scopes":           false,
	}
	for path, want := range cases {
		if got := isScanScopesPath(path); got != want {
			t.Errorf("isScanScopesPath(%q) = %v, want %v", path, got, want)
		}
	}
}
