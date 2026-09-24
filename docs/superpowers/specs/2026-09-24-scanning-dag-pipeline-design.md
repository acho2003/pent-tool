# Scanning DAG Pipeline — Design Spec

- **Date:** 2026-09-24
- **Status:** Approved for planning
- **Author:** c.wangdi@21.tech.bt (with Claude)

## 1. Summary

Replace the current fixed, linear five-scanner pipeline (Nuclei → ZAP →
OpenVAS → Trivy → Vuls, run in stable order over one target) with a phased
DAG:

```
TARGET → Subfinder → httpx → Nmap → classify ─┬─ WEB (Nuclei, ZAP, testssl)
                                               └─ SERVER (OpenVAS, Vuls, Nmap)
                                                        │
                                              SOURCE CODE (Semgrep, Gitleaks, OSV, Trivy)
                                                        │
                        Normalize → Deduplicate → CVSS + evidence → AI analysis → REPORT
```

The pipeline gains a recon phase, a deterministic target classifier that
branches hosts into WEB/SERVER tracks, a source-code (SAST) phase, three new
tools (testssl, Semgrep, OSV; Gitleaks binary already present), and a
bounded-parallel scheduler. AI stays strictly post-scan.

### Decisions locked during brainstorming

1. Build the **full DAG** as one spec, implemented in ordered increments.
2. Recon **fans out per live host**: Subfinder enumerates, httpx keeps live
   hosts, and the full classify→scan DAG runs once per discovered live host.
   A bare URL/host (e.g. `localhost:3000`) degrades to a single host because
   Subfinder finds nothing to expand.
3. Classifier is **evidence-based, both tracks allowed**: a host with both web
   and non-web services runs both tracks; tools run only where they apply.
4. SAST **auto-fetches source when possible**: git URL → clone; else provided
   `--source`/artifact; else the whole SAST phase records `not_applicable`.
   Runs once per scan, not per host.
5. Execution is **bounded parallelism**: a configurable worker pool, with
   heavy tools (ZAP, OpenVAS) capped to one at a time via an exclusive lock.

## 2. Current architecture (baseline)

- `internal/scanner/pipeline.go` — `Pipeline{Config, Runners []Runner}`.
  `NewPipeline` hardcodes the five runners in order. `Run` loops them
  sequentially, reusing terminal runs keyed by `Scanner` name for resume.
- `internal/scanner/types.go` — `Runner` interface (`Name() string`,
  `Run(ctx, Request, Config, EmitFunc) Run`); `Request{Target, Scanners,
  ScanDir, Artifact, VulsSSHHost, TargetAuth}`; `Run` record with terminal
  statuses `completed|failed|cancelled|not_applicable|skipped`;
  `OrderedNames = [nuclei, zap, openvas, trivy, vuls]`.
- `internal/scanner/parse.go` — one parser per scanner, each emitting a
  `Finding{SourceID, Scanner, ...}` with a scanner-prefixed `SourceID`
  (`nuclei:…`, `zap:…`, `trivy:…`, `openvas:…`, `vuls:…`); `dedupFindings`
  keys on `scanner|sourceid|target|endpoint`.
- `internal/reporting/generate.go` — normalizes parsed findings, dedups,
  applies CVSS/mappings, runs AI (report-only), and **rejects findings whose
  source ID is unknown**.
- Tools present in `xalgorix:local`: subfinder, httpx, nmap, nuclei, gitleaks,
  trivy, vuls (+ naabu, katana). ZAP is a separate container reached over its
  HTTP API. **Absent, must be added:** `testssl.sh`, `semgrep`, `osv-scanner`.

## 3. Data model changes

### 3.1 Scope

Introduce `scanner.Scope`, the unit of work that replaces a bare target
string:

```go
type ScopeKind string // "host" | "source"

type Scope struct {
    ID       string        // stable key, e.g. "host:api.example.com" / "source:repo"
    Kind     ScopeKind
    Target   string        // host/URL for host scopes; local path for source scopes
    Evidence HostEvidence  // populated by recon for host scopes
    Source   SourceRef     // populated for source scopes (path + provenance)
    Tracks   []Track       // populated by the classifier for host scopes
}

type HostEvidence struct {
    ResolvedIPs []string
    OpenPorts   []Port        // port, protocol, service, product/version (from nmap)
    LiveURLs    []string      // from httpx
    TLS         bool
}

type Track string // "web" | "server"
```

`Request.Target` remains the entry point. Recon expands it into `[]Scope`.

### 3.2 Run record

`Run` gains a `Scope string` field alongside `Scanner`. Terminal-run reuse
(resume) keys on the pair `(Scope, Scanner)` rather than `Scanner` alone.
Existing single-target scans map to a single implicit host scope, preserving
backward-compatible record shapes where possible (migration note in §7).

### 3.3 Tool descriptor / registry

Replace the hardcoded slice + `OrderedNames` with a registry. Each runner
exposes a descriptor:

```go
type Phase string // "recon" | "web" | "server" | "sast" | "finalize"
type Weight string // "light" | "heavy"

type Descriptor struct {
    Name    string
    Phase   Phase
    Tracks  []Track          // which tracks this tool belongs to (scan phase)
    Weight  Weight           // heavy tools take the exclusive lock
    Applies func(Scope) bool // does this scope have what the tool needs?
}

type Runner interface {
    Name() string
    Descriptor() Descriptor
    Run(context.Context, Task, Config, EmitFunc) Run
}
```

`Task` carries the resolved `Scope` plus request-level config. The current
`Runner.Run(ctx, Request, ...)` signature is adapted to take a `Task`; the
five existing runners become registry entries with descriptors (Phase=web or
server, appropriate Weight).

## 4. Execution model: phase scheduler

`Pipeline.Run` is rewritten as an ordered phase pipeline. Phases run
sequentially; concurrency lives inside the scan phase.

1. **Recon** (host scopes). Runs subfinder → httpx → nmap, in that internal
   order because each feeds the next. Output: the live-host scope set with
   `HostEvidence`. Deterministic; no AI.
   - Subfinder: enumerate subdomains of an apex domain input; a bare host/URL
     yields just itself.
   - httpx: probe candidates, keep live ones, record `LiveURLs`/`TLS`.
   - nmap: port/service scan each live host, populate `OpenPorts`.

2. **Classify** (pure function). `Classify(HostEvidence) []Track`. No I/O
   beyond already-gathered evidence. See §5.

3. **Scan** (bounded parallel). Expand every host scope × its classified
   tracks × the track's tools into `(scope, tool)` tasks, filtered by
   `Descriptor.Applies`. Dispatch through a worker pool of size
   `XALGORIX_MAX_WORKERS` (default 3). A single process-wide **heavy lock**
   ensures at most one `Weight=heavy` tool (ZAP, OpenVAS) runs at any time,
   independent of worker count.

4. **SAST** (source scope). Resolve source: if the target is a git URL, clone
   it to the scan dir; else use provided `--source`/artifact; else the whole
   phase records `not_applicable`. Run Semgrep, Gitleaks, OSV, Trivy over the
   single source scope. Runs once per scan regardless of host fan-out.

5. **Finalize**. Normalize → dedup → CVSS+evidence → AI → report. Largely the
   existing `internal/reporting` path, adjusted for scopes (§8).

### 4.1 Cancellation & resume

- Cancellation stops in-flight tasks and marks remaining tasks `cancelled`,
  matching current semantics but across the DAG.
- Resume reuses terminal `(scope, tool)` runs and their checksums; restart
  continues at the first incomplete task in phase/scope/tool order.

## 5. Classifier rules (deterministic)

Pure, unit-tested function in a dedicated file with a documented table:

- **WEB track** when evidence shows an HTTP(S) service: any open port in
  `{80, 443, 8080, 8443}` **or** an httpx-confirmed live URL. Tools: nuclei,
  zap, testssl.
- **SERVER track** when any non-web service port is open, e.g.
  `{22, 21, 23, 25, 53, 110, 139, 445, 3306, 3389, 5432, 6379, 27017, …}`.
  Tools: openvas, vuls, nmap script findings.
- **Both** tracks when both conditions hold.
- **Neither**: host is live but exposes nothing useful → each candidate tool
  records `not_applicable` for that scope.

The exact port/service table is captured in code as a single source of truth
with a test asserting representative classifications.

## 6. New tools, parsers, source IDs

Add per-tool parsers to `parse.go`, each emitting a prefixed `SourceID` that
the reporter must whitelist (extend the unknown-source-ID rejection list so
nothing is silently dropped):

| Tool      | Role        | SourceID format                | Findings? |
|-----------|-------------|--------------------------------|-----------|
| subfinder | recon       | — (evidence only)              | No        |
| httpx     | recon       | — (evidence only)              | No        |
| nmap      | recon/server| `nmap:host:port`               | Yes (services/port findings) |
| testssl   | web         | `testssl:host:port:id`         | Yes (TLS/cert) |
| semgrep   | sast        | `semgrep:rule:file:line`       | Yes |
| gitleaks  | sast        | `gitleaks:rule:file:commit`    | Yes |
| osv       | sast        | `osv:pkg:vulnID`               | Yes |

Existing five keep their current `SourceID` formats.

## 7. Determinism & resume contract (README + docs change)

The README's "**every target receives exactly five scanner statuses**"
guarantee is replaced with:

> Every applicable tool records exactly one terminal status per scope. Every
> scope×tool the classifier deemed inapplicable is recorded `not_applicable`
> or `skipped`, so the report still accounts for all of them. Recon, target
> classification, tool selection, and command construction are deterministic;
> AI runs only after all scanning completes.

Backward compatibility: a single-target scan with no discoverable subdomains
produces one host scope, so existing single-target behavior and record shapes
are preserved except for the added `Scope` field. A migration note documents
the `(scope, scanner)` resume keying for any persisted queue state.

## 8. Report changes

- `generate.go` groups findings by scope (host / source), showing the
  classifier's track labels and a recon summary (hosts discovered, open ports,
  detected services).
- Dedup extended to cross-scope collapse: the same CVE on the same host
  reported by both openvas and nuclei becomes one finding with both sources.
- CVSS + evidence step unchanged in spirit; new source IDs flow through the
  existing mappings.

## 9. Tooling / Docker / config

- Dockerfile: add `testssl.sh` (git clone + wrapper on PATH), `semgrep` (pip,
  `--break-system-packages`), `osv-scanner` (`go install`, reusing the split
  layer + `-p 4` pattern from the build-memory fix).
- New env vars: `XALGORIX_MAX_WORKERS` (default 3), `XALGORIX_SUBFINDER_PATH`,
  `XALGORIX_HTTPX_PATH`, `XALGORIX_NMAP_PATH`, `XALGORIX_TESTSSL_PATH`,
  `XALGORIX_SEMGREP_PATH`, `XALGORIX_OSV_PATH`, plus a per-tool timeout for
  each new tool (mirroring the existing `*Timeout` config fields).
- CLI/web: scanner-selection surface extends to the new tool names and phase
  grouping; `--scanners` accepts the new names; unknown names still rejected.

## 10. Phased implementation plan

Each increment is independently testable and shippable behind the existing
scanner-selection mechanism. Tests must be green before advancing.

1. **Scaffolding** — Scope model, tool registry/descriptors, resume re-keyed
   to `(scope, tool)`. No behavior change; the existing five tools become
   registry entries mapped to a single implicit host scope.
2. **Recon phase** — subfinder/httpx/nmap runners, `HostEvidence`, per-live-
   host fan-out.
3. **Classifier + tracks** — deterministic branching with the §5 table.
4. **Scheduler** — bounded worker pool + heavy-tool exclusive lock.
5. **New scanners** — testssl (web), then semgrep/gitleaks/osv (SAST) with
   source auto-fetch. Includes Docker + parser + source-ID work.
6. **Report + docs** — scope grouping, recon summary, cross-scope dedup,
   README determinism-contract update.

## 11. Testing strategy

- Unit: classifier table; each new parser against captured tool output
  fixtures; descriptor `Applies` predicates; resume keying.
- Scheduler: worker-pool bound and heavy-lock exclusivity under concurrency
  (deterministic via fake runners).
- Integration: recon fan-out from a domain input; single-URL degrade path;
  SAST auto-fetch clone path and no-source `not_applicable` path.
- Regression: existing single-target five-scanner behavior unchanged.
- Darwin note: run with `CGO_ENABLED=0`; see auto-memory on macOS test
  gotchas.

## 12. Out of scope / YAGNI

- No general graph engine (fixed phases suffice).
- No AI involvement in recon, classification, tool selection, or commands.
- No per-host source mapping (source analysis is once-per-scan).
- No new authenticated-scan flows beyond existing `TargetAuth`.
