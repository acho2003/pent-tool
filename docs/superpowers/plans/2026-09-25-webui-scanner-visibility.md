# Web UI Scanner Visibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show every tool the scanning pipeline runs in the web UI. The tool list comes from the backend, the scan detail page groups runs by scope (recon / each host / source code), and each run's output can be viewed per host.

**Architecture:** The backend gains:
- a tool catalog (`scanner.Catalog()`, built from runner descriptors that now carry a `Summary`);
- a 12-tool `/api/scanners/status`;
- a `/api/scans/{id}/scopes` endpoint that returns the same scope grouping the PDF uses (`buildReportScopes`), plus the recon runs;
- an optional `?scope=` on the output and artifact endpoints.

The React UI renders from those endpoints. No grouping logic lives in TypeScript.

**Tech Stack:** Go 1.26 (`internal/scanner`, `internal/web`); React + TypeScript + Vite + TanStack Query (`webui/`).

**Spec:** docs/superpowers/specs/2026-09-25-webui-scanner-visibility-design.md

## Global Constraints

- **Go:** run go with `CGO_ENABLED=0` (CGO segfaults on this macOS host). NEVER use `go test -race`.
- **No Claude attribution:** commit messages must NOT contain a `Co-Authored-By: Claude` trailer or any Claude/AI attribution line.
- **NEVER run `npm run build` or a plain `vite build` in the working tree.**
  - `vite.config` writes to `internal/web/static` with `emptyOutDir: true`, which deletes the 4 committed files there.
  - To verify a frontend build, use: `cd webui && npm run typecheck && npx vite build --outDir "$TMPDIR/xalgorix-webui-dist" --emptyOutDir`.
  - `git status` must never show changes under `internal/web/static/`.
- **Additive API only:** existing fields and parameterless URLs keep their current behaviour.
- **Selectable tools are unchanged:** `scanners` still accepts exactly `scanner.OrderedNames`; recon tools always run.
- **Legacy scans:** schema < 2 records keep the legacy scan-detail view. Runs with empty `scope` fold to `host:<target>` via `scanner.FindingScope`.
- **Gate every task:**
  - Go tasks: `gofmt -l` on touched packages prints nothing (internal/agent/hooks*.go has pre-existing drift; out of scope), `CGO_ENABLED=0 go vet` is clean, and `CGO_ENABLED=0 go test` passes on touched packages.
  - Frontend tasks: `npm run typecheck` passes, and the scratch-dir vite build above succeeds.
- `internal/reporting` is an unused duplicate; do not modify it.

---

## File Structure

- `internal/scanner/descriptor.go`: `Descriptor.Summary`; `ToolInfo`; `Catalog()`.
- `internal/scanner/pipeline.go`, `zap.go`, `openvas.go`, `vuls.go`, `recon.go`: a `Summary` on every descriptor.
- `internal/scanner/descriptor_test.go`: `TestCatalog`.
- `internal/web/scanner_handlers.go`: catalog-driven `handleScannerStatus`; scope-aware `handleScannerOutput`; new `handleScanScopes`.
- `internal/web/report_scopes.go`: `reportScopeRun` gains `Scope`/`Truncated`/`HasArtifact`, a `scopeRunOf` helper, and `reconRuns`.
- `internal/web/server.go`: `/scopes` route branch.
- `internal/web/scanner_handlers_test.go` (Create): handler tests. `internal/web/report_scopes_test.go`: update one struct-equality assertion.
- `webui/src/types/api.ts`, `webui/src/api/client.ts`: types and client calls.
- `webui/src/pages/new-scan.tsx`, `instances.tsx`, `overview.tsx`, `integrations.tsx`, `login.tsx`, `webui/src/components/new-scan-dialog.tsx`: catalog-driven UI and copy.
- `webui/src/pages/scan-detail.tsx`: grouped `DeterministicScanDetail`.

---

### Task 1: Tool summaries and the catalog

**Files:**
- Modify: `internal/scanner/descriptor.go`; the descriptor literals in `internal/scanner/pipeline.go` (NewPipeline, ~lines 35-44), `zap.go:28`, `openvas.go:20`, `vuls.go:21`, `recon.go` (subfinder/httpx/nmap `Descriptor()` methods)
- Test: `internal/scanner/descriptor_test.go`

**Interfaces:**
- Produces: `Descriptor.Summary string`; `type ToolInfo struct{ Name string; Phase Phase; Selectable bool; Summary string }` with json tags `name, phase, selectable, summary`; `func Catalog() []ToolInfo`. Task 2 consumes `Catalog()`.

- [ ] **Step 1: Failing test.** Append to `internal/scanner/descriptor_test.go` (add `"slices"` to imports if missing):

```go
func TestCatalog(t *testing.T) {
	got := Catalog()
	var names []string
	for _, ti := range got {
		names = append(names, ti.Name)
		if strings.TrimSpace(ti.Summary) == "" {
			t.Errorf("%s has no summary", ti.Name)
		}
		if ti.Selectable != slices.Contains(OrderedNames, ti.Name) {
			t.Errorf("%s selectable=%v, want %v", ti.Name, ti.Selectable, !ti.Selectable)
		}
	}
	want := []string{"subfinder", "httpx", "nmap", "nuclei", "zap", "testssl", "openvas", "vuls", "trivy", "semgrep", "gitleaks", "osv"}
	if !slices.Equal(names, want) {
		t.Fatalf("catalog order = %v, want %v", names, want)
	}
	for _, name := range OrderedNames {
		if n := slices.Index(names, name); n < 0 {
			t.Errorf("selectable scanner %s missing from catalog", name)
		}
	}
	phases := map[string]Phase{"subfinder": PhaseRecon, "nmap": PhaseRecon, "nuclei": PhaseWeb, "testssl": PhaseWeb, "openvas": PhaseServer, "vuls": PhaseServer, "semgrep": PhaseSAST, "osv": PhaseSAST}
	for _, ti := range got {
		if want, ok := phases[ti.Name]; ok && ti.Phase != want {
			t.Errorf("%s phase = %s, want %s", ti.Name, ti.Phase, want)
		}
	}
}
```

(Add `"strings"` to imports if missing.)

- [ ] **Step 2: Verify failure:** `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/scanner/ -run TestCatalog -v`. Expected: build FAIL (`undefined: Catalog`).

- [ ] **Step 3: Implement.** In `descriptor.go`, add `Summary string` to `Descriptor` (after `Name`), with the comment `// Summary is a one-line description of what the tool does and needs, shown in the UI.`. Append:

```go
// ToolInfo describes one pipeline tool for the UI's tool catalog.
type ToolInfo struct {
	Name       string `json:"name"`
	Phase      Phase  `json:"phase"`
	Selectable bool   `json:"selectable"`
	Summary    string `json:"summary"`
}

// Catalog lists every tool a scan runs: the recon tools, which always run, then
// the scan runners in pipeline order (grouped by phase). It is derived from the
// runners' own descriptors so the UI never needs its own tool list. Selectable
// tools are exactly those a scan may deselect (OrderedNames).
func Catalog() []ToolInfo {
	runners := append([]Runner{subfinderRunner{}, httpxRunner{}, nmapRunner{}}, NewPipeline(Config{}).Runners...)
	out := make([]ToolInfo, 0, len(runners))
	for _, r := range runners {
		d := r.Descriptor()
		out = append(out, ToolInfo{Name: d.Name, Phase: d.Phase, Selectable: slices.Contains(OrderedNames, d.Name), Summary: d.Summary})
	}
	return out
}
```

(Add `"slices"` to descriptor.go imports.) Set `Summary` in each descriptor literal, using exactly these strings:

| name | Summary |
|---|---|
| subfinder | `Subdomain enumeration of the submitted domain` |
| httpx | `Live-host and HTTP/TLS probing of discovered hosts` |
| nmap | `Port and service detection per live host` |
| nuclei | `Template scan of each web host` |
| zap | `Spider and active scan of each HTTP/HTTPS host` |
| testssl | `TLS and certificate checks of each TLS host` |
| openvas | `Greenbone network scan of each server host` |
| vuls | `Host CVE audit — needs an SSH alias` |
| trivy | `Dependency, misconfiguration and secret scan of the source` |
| semgrep | `Static code analysis of the source` |
| gitleaks | `Secret detection in the source repository` |
| osv | `Known-vulnerability check of dependency lockfiles` |

- [ ] **Step 4: Verify:** `CGO_ENABLED=0 go test ./internal/scanner/...`. Expected: PASS.

- [ ] **Step 5: Gate + commit.** Run `gofmt -l internal/scanner/` and `CGO_ENABLED=0 go vet ./internal/scanner/...`. Then `git add internal/scanner/ && git commit -m "feat(scanner): describe every tool and expose a tool catalog"`.

---

### Task 2: Catalog-driven `/api/scanners/status`

**Files:**
- Modify: `internal/web/scanner_handlers.go` (`handleScannerStatus`, lines ~19-55)
- Create: `internal/web/scanner_handlers_test.go`

**Interfaces:**
- Consumes: `scanner.Catalog()`.
- Produces: the JSON `{"scanners":[{"name","phase","selectable","summary","available","path"?,"endpoint_configured"?}]}` in catalog order. Task 4's TypeScript `ToolInfo` mirrors this shape.

- [ ] **Step 1: Failing test.** Create `internal/web/scanner_handlers_test.go`:

```go
package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
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
```

- [ ] **Step 2: Verify failure:** `CGO_ENABLED=0 go test ./internal/web/ -run TestScannerStatusListsCatalog -v`. Expected: FAIL (5 names).

- [ ] **Step 3: Implement.** Replace the final `json.NewEncoder(w).Encode(...)` in `handleScannerStatus` with the code below. Keep the ZAP/GVM health computation above it unchanged.

```go
	paths := map[string]string{
		"subfinder": s.cfg.SubfinderPath, "httpx": s.cfg.HttpxPath, "nmap": s.cfg.NmapPath,
		"nuclei": s.cfg.NucleiPath, "testssl": s.cfg.TestsslPath, "vuls": s.cfg.VulsPath,
		"trivy": s.cfg.TrivyPath, "semgrep": s.cfg.SemgrepPath, "gitleaks": s.cfg.GitleaksPath, "osv": s.cfg.OsvPath,
	}
	entries := make([]map[string]any, 0, len(scanner.Catalog()))
	for _, tool := range scanner.Catalog() {
		e := map[string]any{"name": tool.Name, "phase": tool.Phase, "selectable": tool.Selectable, "summary": tool.Summary}
		switch tool.Name {
		case "zap":
			e["available"], e["endpoint_configured"] = zapHealthy, zapConfigured
		case "openvas":
			e["available"], e["endpoint_configured"] = gvmHealthy, gvmConfigured
		default:
			e["available"], e["path"] = available(paths[tool.Name]), paths[tool.Name]
		}
		entries = append(entries, e)
	}
	json.NewEncoder(w).Encode(map[string]any{"scanners": entries})
```

Confirm the `config.Config` field names (`SubfinderPath`, `HttpxPath`, `NmapPath`, `TestsslPath`, `SemgrepPath`, `GitleaksPath`, `OsvPath`) against internal/config/config.go. Import `internal/scanner` if the file does not already.

- [ ] **Step 4: Verify:** `CGO_ENABLED=0 go test ./internal/web/...`. Expected: PASS.

- [ ] **Step 5: Gate + commit.** Run `gofmt -l internal/web/` and `go vet`. Then `git add internal/web/scanner_handlers.go internal/web/scanner_handlers_test.go && git commit -m "feat(web): list every pipeline tool in the scanner status endpoint"`.

---

### Task 3: `/api/scans/{id}/scopes` and scope-aware output

**Files:**
- Modify: `internal/web/report_scopes.go` (`reportScopeRun`; the append at ~line 107), `internal/web/scanner_handlers.go` (`handleScannerOutput` run selection; new `handleScanScopes`), `internal/web/server.go` (`/api/scans/` dispatcher ~line 987)
- Test: `internal/web/scanner_handlers_test.go`, `internal/web/report_scopes_test.go` (line ~52 assertion)

**Interfaces:**
- Produces:
  - `reportScopeRun{Scanner, Status, Reason, Scope, Truncated, HasArtifact}` with json `scanner, status, reason?, scope?, truncated?, has_artifact?`;
  - `func scopeRunOf(run scanner.Run, id string) reportScopeRun`;
  - `func reconRuns(runs []scanner.Run) []reportScopeRun`;
  - `GET /api/scans/{id}/scopes` → `{"recon":[reportScopeRun], "scopes":[reportScope]}`;
  - `?scope=` on the output and artifact endpoints.
- Tasks 4–5 mirror these in TypeScript.

- [ ] **Step 1: Failing tests.** Append to `internal/web/scanner_handlers_test.go` (add imports `os`, `path/filepath`, `github.com/xalgord/xalgorix/v4/internal/scanner`):

```go
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
```

- [ ] **Step 2: Verify failure:** `CGO_ENABLED=0 go test ./internal/web/ -run 'TestScannerOutputSelectsRunByScope|TestScanScopesEndpoint' -v`. Expected: build FAIL (`handleScanScopes` undefined; unknown fields).

- [ ] **Step 3: Extend `reportScopeRun`** (report_scopes.go):

```go
type reportScopeRun struct {
	Scanner     string `json:"scanner"`
	Status      string `json:"status"`
	Reason      string `json:"reason,omitempty"`
	// Scope is the run's own scope key (a per-host nmap run keeps its
	// "recon:<t>:<h>" key), so a UI can fetch exactly this run's output.
	Scope       string `json:"scope,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
	HasArtifact bool   `json:"has_artifact,omitempty"`
}

// scopeRunOf is one run's coverage row within the scope id it is grouped under.
func scopeRunOf(run scanner.Run, id string) reportScopeRun {
	return reportScopeRun{
		Scanner: run.Scanner, Status: run.Status, Reason: run.Reason,
		Scope:       firstNonBlank(run.Scope, id),
		Truncated:   run.Truncated,
		HasArtifact: run.Status == "completed" && run.ArtifactPath != "",
	}
}

// reconRuns lists the recon-phase runs that belong to no host (subfinder,
// httpx), in run order. Per-host nmap runs are grouped under their host.
func reconRuns(runs []scanner.Run) []reportScopeRun {
	out := []reportScopeRun{}
	for _, run := range runs {
		if id := scanner.FindingScope(run); strings.HasPrefix(id, "recon:") {
			out = append(out, scopeRunOf(run, id))
		}
	}
	return out
}
```

In `buildReportScopes`, replace `out[i].Runs = append(out[i].Runs, reportScopeRun{Scanner: run.Scanner, Status: run.Status, Reason: run.Reason})` with `out[i].Runs = append(out[i].Runs, scopeRunOf(run, id))`. Run gofmt afterwards to align the struct fields.

In `internal/web/report_scopes_test.go` `TestBuildReportScopes`, update the struct-equality assertion to the new shape. The run's own scope is now included:
`a.Runs[1] != (reportScopeRun{Scanner: "vuls", Status: "skipped", Reason: "not selected for this scan", Scope: "host:a.test"})`

- [ ] **Step 4: `handleScanScopes`** (scanner_handlers.go):

```go
// handleScanScopes serves GET /api/scans/{id}/scopes: the scan's runs grouped
// by scope exactly as the report's Scan Coverage section groups them, plus the
// host-less recon runs. Legacy (schema < 2) scans have no scopes.
func (s *Server) handleScanScopes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/scans/"), "/scopes")
	scanDir, rec := s.findScanByID(id)
	if rec == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	resp := struct {
		Recon  []reportScopeRun `json:"recon"`
		Scopes []reportScope    `json:"scopes"`
	}{Recon: []reportScopeRun{}, Scopes: []reportScope{}}
	if rec.SchemaVersion >= scanner.SchemaVersion {
		resp.Recon = reconRuns(rec.ScannerRuns)
		if scopes := buildReportScopes(scanDir, rec.ScannerRuns); scopes != nil {
			resp.Scopes = scopes
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
```

- [ ] **Step 5: Scope-aware run selection** in `handleScannerOutput`. Replace the loop that finds `run` with:

```go
	// ?scope= picks the run on one scope (a scan has one run per tool per
	// host). Without it the first run by name is served, as before. A legacy
	// run with empty Scope, or a per-host nmap run, also matches its folded
	// report scope.
	scope := r.URL.Query().Get("scope")
	var run *scanner.Run
	for i := range rec.ScannerRuns {
		candidate := &rec.ScannerRuns[i]
		if candidate.Scanner != name {
			continue
		}
		if scope != "" && candidate.Scope != scope && scanner.FindingScope(*candidate) != scope {
			continue
		}
		run = candidate
		break
	}
```

- [ ] **Step 6: Route.** In server.go's `/api/scans/` handler, add as its first branch:

```go
		if strings.HasSuffix(r.URL.Path, "/scopes") {
			s.handleScanScopes(w, r)
			return
		}
```

- [ ] **Step 7: Verify:** `CGO_ENABLED=0 go test ./internal/web/...`. Expected: PASS, including `TestBuildReportScopes` with its updated assertion and `TestScannerReportGroupsByScopeAndMergesCVE`.

- [ ] **Step 8: Gate + commit.** Run gofmt and vet. Then `git add internal/web/ && git commit -m "feat(web): serve scan runs grouped by scope and per-scope scanner output"`.

---

### Task 4: Types, client, catalog-driven New scan, progress and copy

**Files:**
- Modify: `webui/src/types/api.ts`, `webui/src/api/client.ts`, `webui/src/pages/new-scan.tsx`, `webui/src/pages/instances.tsx` (~line 316), `webui/src/pages/overview.tsx`, `webui/src/pages/integrations.tsx`, `webui/src/pages/login.tsx` (~lines 94-107), `webui/src/components/new-scan-dialog.tsx`

**Interfaces:**
- Consumes: the Task 2 and Task 3 JSON shapes.
- Produces (TypeScript, for Task 5):
  - `ToolInfo`, `ScopeRun`, `ReportScope`, `ScanScopes` types;
  - `api.scannerStatus(): Promise<{scanners: ToolInfo[]}>`;
  - `api.scanScopes(id): Promise<ScanScopes>`;
  - `api.scannerOutput(id, scanner, stream, scope?)`;
  - `api.scannerArtifactUrl(id, scanner, scope?)`.

- [ ] **Step 1: Types** (`webui/src/types/api.ts`).
- Delete the `SCANNER_ORDER` constant and its comment block (lines ~56-59).
- In `ScannerRun`, change `scanner: "nuclei" | "zap" | "openvas" | "trivy" | "vuls" | string;` to `scanner: string;` and add `scope?: string;` after it.
- Update the comment at ~line 253 to `// Restrict the run to these scanners (the selectable tools from /api/scanners/status). Omitted or`.
- Add after `ScannerRun`:

```ts
// One pipeline tool, from GET /api/scanners/status (backend scanner.Catalog).
export interface ToolInfo {
  name: string;
  phase: "recon" | "web" | "server" | "sast" | string;
  selectable: boolean;
  summary: string;
  available: boolean;
  path?: string;
  endpoint_configured?: boolean;
}

// One run within a scope, from GET /api/scans/{id}/scopes.
export interface ScopeRun {
  scanner: string;
  status: string;
  reason?: string;
  scope?: string;
  truncated?: boolean;
  has_artifact?: boolean;
}

export interface ReportScope {
  id: string;
  kind: "host" | "source" | string;
  target?: string;
  origin?: string;
  tracks?: string[];
  open_ports?: string[];
  services?: string[];
  live_urls?: string[];
  runs: ScopeRun[];
}

export interface ScanScopes {
  recon: ScopeRun[];
  scopes: ReportScope[];
}
```

- [ ] **Step 2: Client** (`webui/src/api/client.ts`). Add `ScanScopes` and `ToolInfo` to the type import list. Above the exported `api` object, add:

```ts
const scopeQuery = (scope?: string) => (scope ? `?scope=${encodeURIComponent(scope)}` : "");
```

Replace the `scannerOutput`, `scannerArtifactUrl` and `scannerStatus` entries with:

```ts
	scannerOutput: (scanId: string, scanner: string, stream: "stdout" | "stderr", scope?: string) =>
		http<string>(`/api/scans/${scanId}/output/${scanner}/${stream}${scopeQuery(scope)}`),
	scannerArtifactUrl: (scanId: string, scanner: string, scope?: string) => `/api/scans/${scanId}/${scanner}/artifact${scopeQuery(scope)}`,
	scanScopes: (scanId: string) => http<ScanScopes>(`/api/scans/${scanId}/scopes`),
	scannerStatus: () => http<{ scanners: ToolInfo[] }>("/api/scanners/status"),
```

- [ ] **Step 3: New scan page** (`webui/src/pages/new-scan.tsx`).
- Remove the `SCANNER_ORDER` import and the `SCANNER_SCOPE` map.
- Add `import type { ToolInfo } from "@/types/api";`.
- Replace the `scanners` state line and the `availability` memo with:

```tsx
  const health = useQuery({ queryKey: ["scanner-status"], queryFn: api.scannerStatus, refetchInterval: 30000 });
  const tools: ToolInfo[] = health.data?.scanners ?? [];
  const selectable = useMemo(() => tools.filter((t) => t.selectable), [tools]);
  const recon = useMemo(() => tools.filter((t) => !t.selectable), [tools]);
  // null = default (every selectable tool); a list once the operator changes it.
  const [picked, setPicked] = useState<string[] | null>(null);
  const scanners = picked ?? selectable.map((t) => t.name);
```

(Keep the existing `health` line only once: delete the old one.) Replace `toggleScanner`:

```tsx
  function toggleScanner(name: string) {
    setPicked((prev) => {
      const cur = prev ?? selectable.map((t) => t.name);
      return cur.includes(name) ? cur.filter((s) => s !== name) : [...cur, name];
    });
  }
```

In `submit`, replace the `scanners:` line and its comment with:

```tsx
        // Every selectable tool (or an unchanged default) sends nothing, so the
        // scan is not pinned to today's pipeline membership.
        scanners: picked === null || picked.length === selectable.length ? undefined : picked,
```

Change the `if (!scanners.length)` guard to `if (picked !== null && !picked.length)`.

Header paragraph text: `Recon, then per-host web and server scanners, then source-code analysis. Report AI runs only after scanning is complete.`

Targets hint text: `One per line. Recon discovers live hosts; each host is scanned on its web and/or server track.`

Replace the whole Scanners `<Card>` with:

```tsx
      <Card><CardHeader><CardTitle>Scanners</CardTitle></CardHeader><CardContent className="space-y-4">
        {health.isLoading && <p className="text-xs text-muted-foreground">Loading scanners…</p>}
        {health.isError && <p className="text-xs text-destructive">Could not load the scanner list. The scan will run every scanner.</p>}
        {recon.length > 0 && <p className="text-xs text-muted-foreground">Always runs: {recon.map((t) => t.name).join(", ")} (recon).</p>}
        {([["web", "Web"], ["server", "Server"], ["sast", "Source code"]] as const).map(([phase, label]) => {
          const group = selectable.filter((t) => t.phase === phase);
          if (!group.length) return null;
          return <div key={phase} className="space-y-2">
            <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">{label}</p>
            <div className="grid gap-2 sm:grid-cols-2">{group.map((t) => <label key={t.name} className="flex items-start gap-2 rounded-lg border p-3 text-sm">
              <input type="checkbox" checked={scanners.includes(t.name)} onChange={() => toggleScanner(t.name)} className="mt-0.5 h-3.5 w-3.5 rounded border-border" />
              <span className="min-w-0">
                <span className="flex items-center gap-2"><span className="font-medium capitalize">{t.name}</span>{t.available ? <span className="text-xs text-emerald-400">installed</span> : <span className="text-xs text-red-400">not found</span>}</span>
                <span className="mt-0.5 block text-xs text-muted-foreground">{t.summary}</span>
              </span>
            </label>)}</div>
          </div>;
        })}
        <p className="text-xs text-muted-foreground">Deselected scanners are recorded as <span className="font-mono">skipped</span> on every scope, so the report still shows what was not attempted. Scanners that do not apply to a scope are recorded <span className="font-mono">not applicable</span>.</p>
      </CardContent></Card>
```

If `useMemo` stops being used anywhere else in the file, it is still used here. Check that nothing else in the file referenced `availability`.

- [ ] **Step 4: Instances progress** (`webui/src/pages/instances.tsx`).
- Remove `SCANNER_ORDER` from the import at line ~27, keeping the other named imports.
- Replace the third `Stat` (label `REMAINING`) with:

```tsx
		  <Stat
			icon={<Layers className="h-3 w-3" />}
			label="RUNNING"
			value={String((instance.scanner_runs ?? []).filter((r) => !["completed", "failed", "cancelled", "not_applicable", "skipped"].includes(r.status)).length)}
		  />
```

- [ ] **Step 5: Overview and Integrations.**
- In `overview.tsx`:
  - Change the subtitle `Fixed-order scanning with report-only AI.` to `Recon, per-host web and server scanning, and source-code analysis, with report-only AI.`
  - Change the scanner health grid class `lg:grid-cols-5` to `lg:grid-cols-4`.
  - Under the name `<p>`, add `<p className="mt-0.5 text-[10px] uppercase tracking-wider text-muted-foreground">{s.phase === "sast" ? "source code" : s.phase}</p>`.
- In `integrations.tsx`, inside each card's `CardContent`, add after the availability `<p>`: `<p className="mt-1 text-xs text-muted-foreground">{s.summary}</p>`.
- Both pages already iterate `health.data?.scanners`, so all 12 tools appear.

- [ ] **Step 6: Copy.**
- In `new-scan-dialog.tsx`, change the `DialogDescription` text to `Runs recon, per-host web and server scanners, and source-code analysis.`
- In `login.tsx`:
  - Change the paragraph text `Nuclei, ZAP, OpenVAS, Trivy, and Vuls in a fixed pipeline, with optional report-only AI — managed from a single` to `Recon, per-host web and server scanners, and source-code analysis in a deterministic pipeline, with optional report-only AI — managed from a single`.
  - Change `grid-cols-3` on the `<dl>` to `grid-cols-4`.
  - Replace the five `Stat` lines with:

```tsx
            <Stat label="Recon" value="01" />
            <Stat label="Web" value="02" />
            <Stat label="Server" value="03" />
            <Stat label="Source code" value="04" />
```

- [ ] **Step 7: Verify:** `cd /Users/acho/Desktop/cyber/xalgorix/webui && npm run typecheck && npx vite build --outDir "$TMPDIR/xalgorix-webui-dist" --emptyOutDir && cd .. && git status --short internal/web/static`. Expected: typecheck and build succeed, and `git status` prints nothing for `internal/web/static`. A typecheck error in scan-detail.tsx caused by the removed `SCANNER_ORDER` or the changed `scannerOutput` signature is expected only if scan-detail used them. It uses neither: it has its own `SCANNER_NAMES` and a 3-argument call that stays valid. Fix any other error here.

- [ ] **Step 8: Commit:** `git add webui/src && git commit -m "feat(webui): catalog-driven scanner selection, run progress, and pipeline copy"`.

---

### Task 5: Scan detail grouped by scope

**Files:**
- Modify: `webui/src/pages/scan-detail.tsx`. Replace the `SCANNER_NAMES` constant, `DeterministicScanDetail`, and `ScannerStatusCard` (~lines 367-398); adjust imports.

**Interfaces:**
- Consumes: `api.scanScopes`, `api.scannerOutput(…, scope)`, `api.scannerArtifactUrl(…, scope)`, and the `ScopeRun`/`ReportScope` types (Task 4).

- [ ] **Step 1: Imports.**
- Add `import { useQuery } from "@tanstack/react-query";`.
- Add `ChevronDown` and `ChevronRight` to the lucide-react import list, next to `ChevronLeft`.
- In the `@/types/api` type import, replace `ScannerRun` with `ReportScope, ScopeRun`. If `ScannerRun` is still used elsewhere in the file, keep it as well; typecheck will tell you.

- [ ] **Step 2: Replace the three definitions** (`SCANNER_NAMES`, `DeterministicScanDetail`, `ScannerStatusCard`) with:

```tsx
type RunKey = { scanner: string; scope: string };
const sameKey = (a: RunKey | null, b: RunKey) => !!a && a.scanner === b.scanner && a.scope === b.scope;
const keyOf = (r: ScopeRun, fallbackScope: string): RunKey => ({ scanner: r.scanner, scope: r.scope || fallbackScope });
const ATTENTION = new Set(["failed", "running", "cancelled"]);

function scopeHeading(sc: ReportScope): string {
	if (sc.kind === "source") return `SOURCE CODE  ${sc.origin || sc.target || "none provided"}`;
	return `HOST  ${sc.target || sc.id.replace(/^host:/, "")}`;
}

function DeterministicScanDetail({ scan, onRefresh }: { scan: ScanRecord; onRefresh: () => void }) {
	const [stream, setStream] = useState<"stdout" | "stderr">("stdout");
	const [output, setOutput] = useState("");
	const [loading, setLoading] = useState(false);
	const [regenerating, setRegenerating] = useState(false);
	const [picked, setPicked] = useState<RunKey | null>(null);
	const [openState, setOpenState] = useState<Record<string, boolean>>({});
	// Refetch the grouping whenever any run is added or changes status.
	const runsSignature = useMemo(() => (scan.scanner_runs ?? []).map((r) => `${r.scope ?? ""}|${r.scanner}|${r.status}`).join(","), [scan.scanner_runs]);
	const scopesQuery = useQuery({ queryKey: ["scan-scopes", scan.id, runsSignature], queryFn: () => api.scanScopes(scan.id) });
	const recon = scopesQuery.data?.recon ?? [];
	const scopes = scopesQuery.data?.scopes ?? [];
	const hostCount = scopes.filter((s) => s.kind !== "source").length;
	const firstKey = useMemo<RunKey | null>(() => {
		if (recon[0]) return keyOf(recon[0], "");
		const sc = scopes.find((s) => s.runs.length);
		return sc ? keyOf(sc.runs[0], sc.id) : null;
	}, [recon, scopes]);
	const selected = picked ?? firstKey;
	const located = useMemo(() => {
		if (!selected) return null;
		const r = recon.find((x) => sameKey(selected, keyOf(x, "")));
		if (r) return { run: r, label: "recon" };
		for (const sc of scopes) {
			const hit = sc.runs.find((x) => sameKey(selected, keyOf(x, sc.id)));
			if (hit) return { run: hit, label: scopeHeading(sc).replace(/\s+/g, " ").toLowerCase() };
		}
		return null;
	}, [selected, recon, scopes]);
	useEffect(() => {
		if (!selected) { setOutput(""); return; }
		let active = true;
		setLoading(true);
		api.scannerOutput(scan.id, selected.scanner, stream, selected.scope || undefined)
			.then((text) => { if (active) setOutput(text); })
			.catch((e) => { if (active) setOutput(e instanceof Error ? e.message : "Output unavailable"); })
			.finally(() => { if (active) setLoading(false); });
		return () => { active = false; };
	}, [scan.id, selected?.scanner, selected?.scope, stream, runsSignature]);
	async function regenerate() {
		setRegenerating(true);
		try { await api.regenerateReport(scan.id); onRefresh(); } finally { setRegenerating(false); }
	}
	const isOpen = (sc: ReportScope) => openState[sc.id] ?? (sc.kind === "source" || hostCount <= 3 || sc.runs.some((r) => ATTENTION.has(r.status)));
	const grid = (runs: ScopeRun[], fallbackScope: string) => <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">{runs.map((r) => {
		const k = keyOf(r, fallbackScope);
		return <ScannerStatusCard key={`${k.scope}|${k.scanner}`} name={r.scanner} run={r} active={sameKey(selected, k)} onClick={() => setPicked(k)} />;
	})}</div>;
	return <div className="space-y-6">
		<Link to="/scans" className="inline-flex items-center text-xs text-muted-foreground hover:text-foreground"><ChevronLeft className="mr-1 h-3 w-3" /> All scans</Link>
		<header className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between"><div><h1 className="font-mono text-2xl font-semibold">{scan.target}</h1><div className="mt-2 flex flex-wrap gap-2 text-xs text-muted-foreground"><span>{scan.id}</span><span>·</span><span>{formatDuration(scan.started_at, scan.finished_at)}</span><Badge variant="outline">schema v2</Badge></div></div><div className="flex gap-2"><ScanStatusPill status={scan.status} /><Button variant="outline" size="sm" asChild><a href={api.reportUrl(scan.id)} target="_blank" rel="noreferrer"><Download className="mr-1 h-4 w-4" /> Report</a></Button><Button variant="outline" size="sm" onClick={() => void regenerate()} disabled={regenerating}>{regenerating ? <Loader2 className="mr-1 h-4 w-4 animate-spin" /> : <Sparkles className="mr-1 h-4 w-4" />} Regenerate report</Button></div></header>
		{scopesQuery.isError && <Card><CardContent className="flex items-center justify-between gap-3 p-4 text-sm"><span className="text-destructive">Could not load scanner runs.</span><Button size="sm" variant="outline" onClick={() => void scopesQuery.refetch()}>Retry</Button></CardContent></Card>}
		{scopesQuery.isSuccess && !recon.length && !scopes.length && <p className="text-sm text-muted-foreground">No scanner runs yet.</p>}
		{recon.length > 0 && <section className="space-y-2"><h2 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Recon</h2>{grid(recon, "")}</section>}
		{scopes.map((sc) => {
			const open = isOpen(sc);
			return <section key={sc.id} className="space-y-2">
				<button type="button" onClick={() => setOpenState((prev) => ({ ...prev, [sc.id]: !open }))} className="flex w-full flex-wrap items-center gap-2 text-left">
					{open ? <ChevronDown className="h-3 w-3 text-muted-foreground" /> : <ChevronRight className="h-3 w-3 text-muted-foreground" />}
					<span className="font-mono text-xs font-medium uppercase tracking-wider">{scopeHeading(sc)}</span>
					{(sc.tracks ?? []).map((t) => <Badge key={t} variant="outline" className="text-[10px]">{t}</Badge>)}
					{sc.kind !== "source" && <span className="text-[11px] text-muted-foreground">{(sc.open_ports ?? []).length} open port{(sc.open_ports ?? []).length === 1 ? "" : "s"}</span>}
				</button>
				{open && grid(sc.runs, sc.id)}
			</section>;
		})}
		{selected && <Card><CardHeader><div className="flex flex-wrap items-center justify-between gap-3"><div><CardTitle><span className="capitalize">{selected.scanner}</span>{located && <span className="font-normal text-muted-foreground"> @ {located.label}</span>}</CardTitle><CardDescription>Native scanner output only. AI is not used in scan execution or this view.</CardDescription></div><div className="flex gap-2"><Button size="sm" variant={stream === "stdout" ? "default" : "outline"} onClick={() => setStream("stdout")}>stdout</Button><Button size="sm" variant={stream === "stderr" ? "default" : "outline"} onClick={() => setStream("stderr")}>stderr</Button>{located?.run.has_artifact && <Button size="sm" variant="outline" asChild><a href={api.scannerArtifactUrl(scan.id, selected.scanner, selected.scope || undefined)}><Download className="mr-1 h-4 w-4" /> Artifact</a></Button>}</div></div></CardHeader><CardContent><pre className="max-h-[32rem] min-h-48 overflow-auto whitespace-pre-wrap rounded-md bg-black/40 p-4 text-xs text-neutral-200">{loading ? "Loading…" : output || "No output recorded."}</pre></CardContent></Card>}
		<Card><CardHeader><CardTitle>Report state</CardTitle></CardHeader><CardContent className="text-sm"><div className="grid gap-2 sm:grid-cols-3"><div><span className="text-muted-foreground">Mode</span><p className="font-medium">{scan.report_mode || "pending"}</p></div><div><span className="text-muted-foreground">Generated</span><p>{scan.report_generated_at ? formatTime(scan.report_generated_at) : "—"}</p></div><div><span className="text-muted-foreground">Artifact</span><p>{scan.artifact ? `${scan.artifact.kind}: ${scan.artifact.ref}` : "Not supplied"}</p></div></div></CardContent></Card>
	</div>;
}

function ScannerStatusCard({ name, run, active, onClick }: { name: string; run?: { status: string; reason?: string; truncated?: boolean }; active: boolean; onClick: () => void }) {
	const status = run?.status ?? "pending";
	return <button type="button" onClick={onClick} className={cn("rounded-lg border p-4 text-left transition-colors hover:bg-muted/30", active && "border-primary bg-muted/30")}><p className="font-medium capitalize">{name}</p><p className={cn("mt-2 text-xs capitalize", status === "completed" && "text-emerald-400", status === "failed" && "text-red-400", status === "not_applicable" && "text-muted-foreground", status === "skipped" && "text-muted-foreground", status === "cancelled" && "text-amber-400")}>{status.replaceAll("_", " ")}</p>{run?.reason && <p className="mt-2 line-clamp-2 text-[11px] text-muted-foreground" title={run.reason}>{run.reason}</p>}{run?.truncated && <Badge variant="outline" className="mt-2">truncated</Badge>}</button>;
}
```

The header, report-state card and `ScannerStatusCard` markup are carried over from the current code unchanged, apart from the card's `run` prop type.

- [ ] **Step 3: Verify:** `cd /Users/acho/Desktop/cyber/xalgorix/webui && npm run typecheck && npx vite build --outDir "$TMPDIR/xalgorix-webui-dist" --emptyOutDir && cd .. && git status --short internal/web/static`. Expected: success, and nothing printed for `internal/web/static`. If typecheck reports an unused import (for example `ScannerRun`), remove it.

- [ ] **Step 4: Commit:** `git add webui/src/pages/scan-detail.tsx && git commit -m "feat(webui): group scan detail runs by scope with per-host output"`.

---

### Task 6: Whole-tree verification and real-app check

**Files:** none expected.

- [ ] **Step 1: Go:** `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go build ./... && gofmt -l internal/ cmd/ && CGO_ENABLED=0 go vet ./internal/... ./cmd/...`. Then `CGO_ENABLED=0 go list ./... | grep -vE '/internal/(sandbox|tools/fileedit|tools/notes|tools/terminal|resources|tools/browser|tools/python)$' | CGO_ENABLED=0 xargs go test -timeout 300s -count=1; echo EXIT=$?`. Expected: gofmt reports only the pre-existing hooks*.go drift, and `EXIT=0`.
- [ ] **Step 2: Frontend:** `cd webui && npm run typecheck && npx vite build --outDir "$TMPDIR/xalgorix-webui-dist" --emptyOutDir`. Then `git status --short` in the repo root: clean.
- [ ] **Step 3: Real app (controller, with the `run` skill):** build and start the Docker stack (`docker compose up -d --build`), open the UI, and confirm:
  - New scan shows the Web / Server / Source code groups plus the recon line.
  - A multi-host scan's detail page shows the Recon, per-host and Source code sections, and selecting the same tool on two hosts shows different output.
  - The Instances card shows RUNNING.
  - An older single-target scan still renders.
- [ ] **Step 4: Commit any fixups**, with no attribution line.

---

## Self-Review

**Spec coverage:**
- §4.1–4.2: Task 1. §4.3: Task 2. §4.4–4.5: Task 3.
- §5.1–5.2, §5.4–5.6: Task 4. §5.3: Task 5.
- §6: Task 4 Step 3 (catalog error) and Task 5 (scopes error/Retry, output 404 text kept). §7: tests in Tasks 1–3, plus Task 6.

**Placeholder scan:** every code step has complete code. Copy strings are exact.

**Type consistency:**
- Go `reportScopeRun` json (`scanner, status, reason, scope, truncated, has_artifact`) ↔ TS `ScopeRun`.
- Go `reportScope` json (`id, kind, target, origin, tracks, open_ports, services, live_urls, runs`) ↔ TS `ReportScope`.
- Status entries ↔ TS `ToolInfo`.
- `api.scannerOutput`'s 4th `scope` argument is optional, so any other caller keeps working.

**Risks:**
- (a) `npm run build` would wipe committed static files; every verify step uses a scratch outDir and checks `git status`.
- (b) `TestBuildReportScopes` needs the one assertion update in Task 3 Step 3; any other struct-equality check on `reportScopeRun` needs `Scope` added the same way. Never weaken it.
- (c) The scan-detail page's `useScan` polls every 2s while running. `runsSignature` makes the scopes query refetch only when runs change.
