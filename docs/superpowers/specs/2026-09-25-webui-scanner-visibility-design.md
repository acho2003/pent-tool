# Web UI Scanner Visibility — Design Spec

- **Date:** 2026-09-25
- **Status:** Approved in chat; awaiting spec review
- **Author:** c.wangdi@21.tech.bt (with Claude)
- **Builds on:** docs/superpowers/specs/2026-09-24-scanning-dag-pipeline-design.md (the scanning DAG; §7 contract, §8 report changes)

## 1. Problem

The scanning DAG pipeline runs up to 12 tools across several scopes: recon, one scope per host, and one source-code scope. The web UI still hard-codes the original five scanners (Nuclei, ZAP, OpenVAS, Trivy, Vuls):

- `webui/src/types/api.ts` `SCANNER_ORDER` lists five names. The New scan page offers only those five checkboxes, even though the backend accepts nine names in `scanners`.
- `webui/src/pages/scan-detail.tsx` renders five fixed status cards and indexes runs by scanner name only. On a multi-host scan each card silently shows the last host's run, and recon and source-code tools never appear.
- `webui/src/pages/instances.tsx` computes "pending" as `5 − runs`, which is wrong when the run count varies.
- The login page, New scan page and new-scan dialog all say "runs Nuclei, ZAP, OpenVAS, Trivy, and Vuls in fixed order".
- Backend `GET /api/scanners/status` (internal/web/scanner_handlers.go) returns five entries. It feeds the Overview, Integrations and New scan pages.
- Backend `GET /api/scans/{id}/output/{scanner}/{stream}` and `/api/scans/{id}/{scanner}/artifact` pick the first run whose scanner name matches, so only the first host's output is ever viewable.

The PDF report is correct; it is built server-side from scopes.

## 2. Goals / non-goals

**Goals**
- Every tool the pipeline runs is visible in the UI, with its status on every scope and its raw output per run.
- The UI's tool list comes from the backend, so a tool added later needs no frontend change.
- The scan detail page groups runs by scope exactly like the PDF's Scan Coverage section.
- Progress counts are correct for variable run counts.
- Old scans (single implicit host, runs without `scope`) still render correctly.

**Non-goals (YAGNI)**
- No frontend test runner is introduced. Grouping logic lives in Go, which is tested; the UI only renders.
- No change to which tools are selectable: `scanners` still accepts the nine `scanner.OrderedNames`, and recon always runs.
- No live per-line output streaming changes; the existing fetch-on-select behaviour stays.
- No redesign of the legacy (agent-mode, schema < 2) scan detail view.

## 3. Decisions

1. **Scan detail layout: grouped by scope (user-chosen).** A Recon section, then one collapsible section per host (with its web/server tracks), then Source code. Each section is a grid of tool status cards, and clicking a card shows that run's output.
2. **Tool catalog from the backend (approach A).** Chosen over mirroring the list in TypeScript, which is the kind of hard-coding that caused this gap.
3. **Grouping computed server-side.** This refines the in-chat design, which grouped in the UI. The backend exposes the scope grouping it already builds for the PDF (`buildReportScopes`), so the page and the PDF can never disagree, and the logic is covered by existing Go tests.

## 4. Backend changes

### 4.1 Tool summaries on descriptors
`scanner.Descriptor` gains `Summary string`: a one-line description of what the tool does and what it needs. Every runner descriptor sets it:

| Tool | Phase | Summary |
|---|---|---|
| subfinder | recon | Subdomain enumeration of the submitted domain |
| httpx | recon | Live-host and HTTP/TLS probing of discovered hosts |
| nmap | recon | Port and service detection per live host |
| nuclei | web | Template scan of each web host |
| zap | web | Spider and active scan of each HTTP/HTTPS host |
| testssl | web | TLS and certificate checks of each TLS host |
| openvas | server | Greenbone network scan of each server host |
| vuls | server | Host CVE audit — needs an SSH alias |
| trivy | sast | Dependency, misconfiguration and secret scan of the source |
| semgrep | sast | Static code analysis of the source |
| gitleaks | sast | Secret detection in the source repository |
| osv | sast | Known-vulnerability check of dependency lockfiles |

### 4.2 `scanner.Catalog()`
A new exported function returns the full ordered tool list:

```go
type ToolInfo struct {
    Name       string `json:"name"`
    Phase      Phase  `json:"phase"`
    Selectable bool   `json:"selectable"`
    Summary    string `json:"summary"`
}
func Catalog() []ToolInfo
```

The order is recon tools (subfinder, httpx, nmap), then the `NewPipeline` runners in `OrderedNames` order. `Selectable` is true exactly for names in `OrderedNames`. The catalog is derived from the recon runner descriptors and `NewPipeline(Config{}).Runners` descriptors, so there is no parallel list. A test asserts every `OrderedNames` entry appears exactly once, every entry has a non-empty Summary, and the recon tools are not selectable.

### 4.3 `GET /api/scanners/status`
Returns one entry per `Catalog()` tool: `{name, phase, selectable, summary, available, path?, endpoint_configured?}`.
- `available`: for binary tools, `exec.LookPath` on the configured path (config fields `SubfinderPath`, `HttpxPath`, `NmapPath`, `TestsslPath`, `SemgrepPath`, `GitleaksPath`, `OsvPath`, plus the existing three). ZAP and OpenVAS keep their existing health checks.
- Entry order follows `Catalog()`. Existing consumers read `name`/`available`/`path`/`endpoint_configured`, which are unchanged.

### 4.4 `GET /api/scans/{id}/scopes`
Returns the scan's coverage grouped by scope:

```json
{
  "recon": [{"scanner":"subfinder","scope":"recon:example.com","status":"completed","reason":"", "truncated":false, "has_artifact":true}],
  "scopes": [ /* reportScope objects, as in report.json "scopes" */ ]
}
```

- `scopes` is `buildReportScopes(scanDir, rec.ScannerRuns)`: host scopes in discovery order with tracks, ports and services, then the source scope with its origin. Each `reportScope.Runs` entry gains `scope`, `truncated`, and `has_artifact` (all `omitempty`), so a card knows which run it is and whether an artifact download exists. `has_artifact` is true when the run is `completed` and `ArtifactPath` is non-empty.
- `recon` lists the runs whose `scanner.FindingScope(run)` still has the `recon:` prefix (subfinder, httpx), in run order, with the same fields. Per-host nmap runs already appear inside their host scope, so they are excluded here.
- Works while a scan is running: it reads the persisted record and `recon-scopes.json` / `source-scope.json` at request time. Sections and cards appear as runs are recorded: skipped and not-applicable runs are recorded when the scan phase starts, and executable ones when they start running. A tool that has not started on a host yet has no card; there is no synthetic "pending" card.
- Schema < 2 records (agent mode) return `{"recon":[],"scopes":[]}`; the UI keeps its legacy view for those.
- Route: the `/api/scans/` dispatcher in server.go gains a branch for the `/scopes` suffix (GET only), placed before the generic `handleGetScan`.

### 4.5 Scope-aware output and artifact endpoints
`/api/scans/{id}/output/{scanner}/{stream}` and `/api/scans/{id}/{scanner}/artifact` accept an optional `?scope=<scope id>` query parameter.
- When present, select the run with `Scanner == name && Scope == scope`. For legacy runs with empty `Scope`, match `scanner.FindingScope(run) == scope`, so `host:<target>` works for pre-scope records. Per-host nmap runs match their `host:<h>` scope as well as their raw `recon:<t>:<h>` scope.
- When absent, behaviour is unchanged (first run by name), so old links keep working.
- A scope that matches no run returns 404 "scanner run not found", exactly as today.
- `safeScannerPath` confinement is unchanged.

## 5. Frontend changes

### 5.1 Types and client (`webui/src/types/api.ts`, `webui/src/api/client.ts`)
- `ScannerRun` gains `scope?: string`.
- `ScannerRun.scanner`'s literal union and the `SCANNER_ORDER` constant are removed. Tool names come from the catalog. `SCANNER_ORDER` usages are replaced (§5.2, §5.4).
- New types: `ToolInfo` (`name, phase, selectable, summary, available, path?, endpoint_configured?`), `ScopeRun`, `ReportScope`, `ScanScopes`.
- `api.scannerStatus()` returns `ToolInfo[]` inside `{scanners}`. New `api.scanScopes(scanId)`. `api.scannerOutput(scanId, scanner, stream, scope?)` and `api.scannerArtifactUrl(scanId, scanner, scope?)` append `?scope=` when given.

### 5.2 New scan page (`webui/src/pages/new-scan.tsx`)
- Load tools from `api.scannerStatus()`. Render the selectable ones as checkboxes grouped **Web** (phase `web`), **Server** (`server`) and **Source code** (`sast`), each showing its summary and an "installed" / "not found" badge (`available`).
- Recon (non-selectable) is a read-only line: "Always runs: Subfinder, httpx, Nmap".
- Default selection is all selectable tools. `scanners` is sent only when the selection is a strict subset (current behaviour, now compared against the catalog's selectable count).
- While the catalog is loading, or if the request fails, the scanner section shows a loading line or an inline error, and Start scan still works with the default (all tools, `scanners` omitted).
- Header copy: "Recon, then per-host web and server scanners, then source-code analysis. Report AI runs only after scanning is complete." The per-field hint below the targets textarea is updated to match.

### 5.3 Scan detail page (`webui/src/pages/scan-detail.tsx`, `DeterministicScanDetail`)
- Fetch `api.scanScopes(scan.id)` alongside the record, and refetch whenever `scan.scanner_runs` changes (the page already re-renders on record refresh).
- Remove `SCANNER_NAMES` and the `byName` map.
- **Sections:**
  - **Recon:** cards for the `recon` runs.
  - **One section per host scope:** header `HOST <target>` with track badges (web/server) and a port count, then its cards.
  - **Source code:** header `SOURCE CODE <origin || target || "none provided">`, then its cards.
- Host sections are collapsible. They start expanded when the scan has at most 3 host scopes, or when that section contains a run with status `failed`, `running` or `cancelled`. Otherwise they start collapsed.
- `ScannerStatusCard` is reused unchanged in appearance. The selection key becomes `{scanner, scope}`, and the default selection is the first card of the first non-empty section.
- The output card title reads `<scanner> @ <scope label>` and fetches with the selected scope. The Artifact button shows when `has_artifact`.
- Empty state: when `scopes` and `recon` are both empty (e.g. a scan that has not started), show "No scanner runs yet".

### 5.4 Instances page (`webui/src/pages/instances.tsx`)
"Pending" becomes the count of runs whose status is not terminal (`running`, or any status outside completed/failed/cancelled/not_applicable/skipped). "Finished" and "failed" keep their current definitions. The `SCANNER_ORDER` import is removed.

### 5.5 Overview and Integrations (`webui/src/pages/overview.tsx`, `integrations.tsx`)
Both render whatever `api.scannerStatus()` returns. Any hard-coded five-name assumption in those pages, such as a fixed grid column count or name-to-label map, is replaced so all 12 tools render. Tools are grouped by phase where the page already groups, otherwise listed in catalog order.

### 5.6 Copy
- `webui/src/pages/login.tsx`: replace the five-scanner sentence and the five numbered `Stat` tiles with a description of the phases and four tiles: Recon, Web, Server, Source code.
- `webui/src/components/new-scan-dialog.tsx`: description becomes "Runs recon, per-host web and server scanners, and source-code analysis."

## 6. Error handling
- Catalog fetch failure (§5.2) degrades to all-tools-selected. Scan starting never depends on it.
- A `scopes` fetch failure on scan detail shows an inline error card with a Retry button. The report and other cards still render.
- The output endpoint 404 for a missing run keeps showing the existing "Output unavailable" text in the output panel.

## 7. Testing
- **Go (internal/scanner):** `TestCatalog` (coverage of `OrderedNames`, order, selectable flags, non-empty summaries).
- **Go (internal/web):**
  - `/api/scanners/status` returns 12 entries in catalog order, with `phase`/`selectable`/`summary`.
  - `/api/scans/{id}/scopes` on a multi-host fixture (reusing the report_ai_test fixtures) returns recon runs, host scopes in order with tracks, and the source scope with origin. Per-host nmap is inside its host, not in `recon`. Schema < 2 returns empty lists.
  - The output endpoint with `?scope=` returns the second host's stdout, not the first. Without `scope`, the old behaviour is kept. An unknown scope returns 404.
- **Frontend:** `npm run typecheck` and `npm run build` in `webui/` must pass. No unit test runner is added (§2).
- **Real app:** build the Docker image and use the `run` skill to open the UI.
  - Start a multi-host scan and confirm the New scan groups, the scan detail sections with correct per-host outputs, and instances progress.
  - Also open an old single-target scan and confirm it still renders.

## 8. Rollout / compatibility
- All API changes are additive. Existing fields and parameterless URLs behave as before.
- The UI ships inside the same binary: the webui is built into `internal/web/static` in the Docker build, so a rebuild is needed to see it.
