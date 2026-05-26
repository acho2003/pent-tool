# Implementation Plan: Xalgorix Stability and Workspace Isolation

## Overview

Convert the feature design into a series of prompts for a code-generation LLM that will implement each step with incremental progress. Each prompt builds on previous prompts and ends with wiring things together. There is no hanging or orphaned code that isn't integrated into a previous step.

The plan is sequenced **foundations → resource bounds → workspace isolation → tools compliance → web/server hardening → tests → docs**. Property tests use [`pgregory.net/rapid`](https://pkg.go.dev/pgregory.net/rapid); each property invocation runs **at least 100 iterations** (`rapid.Check` default of 100, raised to 200 via the `-rapid.checks=200` flag where called out).

> **Breaking change.** Task 3 changes `cfg.Workspace` from `$CWD` to `Data_Dir` (`~/.xalgorix/data/` by default). The Migration_Warning emitted by 3.3 is the user-facing migration aid. Tasks 15.1 and 15.2 document the change.

## Task Dependency Graph (Mermaid)

```mermaid
flowchart LR
    subgraph W0[Wave 0 — Foundations skeleton]
        T11[1.1 safe pkg]
        T21[2.1 sandbox.Policy]
        T22[2.2 PathRejectError]
        T31[3.1 Config fields]
        T71[7.1 iolimit pkg]
        T41[4.1 LLM semaphore]
    end
    subgraph W1[Wave 1]
        T23[2.3 wire IncPathReject]
        T32[3.2 resolveDataDir]
        T72[7.2 python uses iolimit]
        T73[7.3 terminal uses iolimit]
        T121[12.1 scheduler tick recover]
        T131[13.1 scanctx.Close defer]
    end
    subgraph W2[Wave 2]
        T33[3.3 Migration_Warning]
        T81[8.1 fileedit]
        T82[8.2 reporting]
        T83[8.3 notes]
        T84[8.4 skills]
        T122[12.2 per-schedule recover]
        T132[13.2 KillAll guarantees]
    end
    subgraph W3[Wave 3]
        T34[3.4 Validate DataDir]
        T85[8.5 browser path policy]
        T101[10.1 browser lease acquire]
        T133[13.3 lease release order]
    end
    subgraph W4[Wave 4]
        T35[3.5 WorkspacePath]
        T61[6.1 hardTimeoutFor]
        T91[9.1 prepPython workspace]
        T93[9.3 prepCmd workspace]
        T102[10.2 ApplyProcessLimits browser]
    end
    subgraph W5[Wave 5]
        T36[3.6 web initDataDir]
        T62[6.2 executeToolAsync recover]
        T92[9.2 python env vars]
        T94[9.4 terminal env vars]
        T103[10.3 browser lease release]
        T111[11.1 HTTPMiddleware]
        T113[11.3 admission refusal log]
    end
    subgraph W6[Wave 6]
        T63[6.3 safe.Go goroutines]
        T112[11.2 admissionWake chan]
    end
    subgraph W7[Wave 7]
        T64[6.4 watchdog counter+log]
        T114[11.4 handleStatus counters]
    end
    subgraph W8[Wave 8]
        T65[6.5 message pruning]
        T51[5.1 doChat wrap]
        T52[5.2 ChatStream goroutine]
        T53[5.3 RateLimit confirm]
    end
    subgraph W9[Wave 9 — Property tests]
        TP1[14.1 P1]
        TP2[14.2 P2]
        TP3[14.3 P3]
        TP4[14.4 P4]
        TP5[14.5 P5]
        TP6[14.6 P6]
        TP7[14.7 P7]
        TP8[14.8 P8]
        TP9[14.9 P9]
        TP10[14.10 P10]
        TP11[14.11 P11]
        TP12[14.12 P12]
    end
    subgraph W10[Wave 10 — Docs]
        TD1[15.1 README]
        TD2[15.2 CHANGELOG]
    end

    W0 --> W1 --> W2 --> W3 --> W4 --> W5 --> W6 --> W7 --> W8 --> W9 --> W10
```

## Tasks

- [x] 1. Foundations — `internal/safe` package (recovery + counters)
  - [x] 1.1 Create `internal/safe/safe.go`
    - Define `Counters{PanicsRecovered, PathRejections, WatchdogKills, AdmissionRefusals uint64}` with `atomic.AddUint64` mutators (`IncPanic`, `IncPathReject`, `IncWatchdogKill`, `IncAdmissionRefusal`) and `Snapshot()` reader.
    - Implement `Recover(component, scanID string, errp ...*error)` that captures the panic value, increments `PanicsRecovered`, calls a single `log.Printf("[recover] component=%s scan=%s panic=%v\n%s", ...)` with `runtime/debug.Stack()`, and (when `errp` is provided and `*errp == nil`) sets `*errp = fmt.Errorf("panic in %s: %v", component, v)`.
    - Implement `Go(component, scanID string, fn func())` that runs `fn` in a goroutine guarded by `defer Recover(component, scanID)`.
    - Implement `HTTPMiddleware(next http.Handler) http.Handler` that wraps the handler, on panic writes `http.StatusInternalServerError` (500) and emits the recovery log + counter.
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 9.4_

  - [ ]* 1.2 Unit tests for `safe.Recover` error promotion and counter monotonicity
    - _Validates: Property 1, Property 12_

- [x] 2. Foundations — `internal/sandbox` package (Path_Policy)
  - [x] 2.1 Create `internal/sandbox/policy.go` with `Policy`, `New`, `Default` (lazy singleton from `cfg.DataDir`, `cfg.HomeDir`, `/tmp`), `Resolve`, `Check`, `CheckResolve`, and `Roots`
    - `Resolve` resolves relative paths against `sc.ScanDir` if non-nil, else `cfg.WorkspaceRoot`; canonicalizes via `filepath.EvalSymlinks` when the path exists, else `filepath.EvalSymlinks(parent)` joined with `filepath.Base`, falling back to `filepath.Clean(filepath.Abs(...))`.
    - `Check` verifies the canonical path equals one of the deduped longest-first roots or has it as a `string(filepath.Separator)` prefix.
    - Roots are sorted longest-first for deterministic matching.
    - _Requirements: 5.1, 5.2, 5.4, 5.5, 6.6, 8.10_

  - [x] 2.2 Define `PathRejectError` type and `ErrPathReject` sentinel in the same package
    - Fields: `Tool`, `Path`, `Roots`, `ScanCtxID`. Implement `Error()` and `Is(target error) bool` so `errors.Is(err, sandbox.ErrPathReject)` works.
    - _Requirements: 5.3, 8.3_

  - [x] 2.3 Wire `safe.IncPathReject()` and the WARN-level structured log (`tool`, `path`, `roots`, `scan_id`) into `Policy.CheckResolve` reject branch
    - _Requirements: 5.6, 9.1_

- [x] 3. Foundations — `internal/config` Data_Dir + Migration_Warning **[BREAKING CHANGE]**
  - [x] 3.1 Add `DataDir`, `WorkspaceRoot string` fields and unexported `legacyCWD string` to `Config`; make `Workspace` mirror `DataDir` instead of `$CWD`
    - _Requirements: 6.4, 7.1_

  - [x] 3.2 Implement `resolveDataDir(home string) (string, error)`
    - Reads `XALGORIX_DATA_DIR`; defaults to `filepath.Join(home, ".xalgorix", "data")`. Canonicalizes via `filepath.Abs` + `filepath.Clean`. `os.MkdirAll(abs, 0o700)`. `os.Chmod(abs, 0o700)` to tighten existing dirs.
    - _Requirements: 6.1, 6.2, 6.3, 6.7_

  - [x] 3.3 Implement `maybeEmitMigrationWarning(cwd, dataDir string)` and call it from `load()` (memoized via existing `configOnce`)
    - Suppress when `XALGORIX_DATA_DIR` is set or `cwd == dataDir`. Detect legacy markers `notes.json`, `_schedules`, `vulnerabilities.json`, plus glob `20??-??-??/scan-*`. WARN log with detected path, active Data_Dir, change announcement, and the `XALGORIX_DATA_DIR=$(pwd)` opt-out one-liner.
    - Never read, copy, modify, or delete legacy files.
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

  - [x] 3.4 Add `Validate()` guard `if c.DataDir == ""` returning a startup error so the binary refuses to start with an unresolved Data_Dir
    - _Requirements: 6.5_

  - [x] 3.5 Update `WorkspacePath` to resolve relative inputs against `cfg.WorkspaceRoot` (= `DataDir`)
    - _Requirements: 6.6_

  - [x] 3.6 Migration step — refactor `Web_Server.initDataDir` (and any peer that re-derives a data root) to a thin wrapper around `cfg.DataDir`; remove every `$CWD`-derived workspace assumption from `internal/web` and `cmd/`
    - _Requirements: 6.4, 6.6_

- [x] 4. Resource bounds — LLM in-flight semaphore
  - [x] 4.1 Create `internal/resources/llm.go` with `AcquireLLMSlot(ctx) (release func(), err error)` and `LLMInFlightCap() int`
    - Use `golang.org/x/sync/semaphore`. Cap from `XALGORIX_LLM_MAX_INFLIGHT`, defaulting to `4 * EffectiveMaxInstances()` (minimum 1) on first use. `sync.Once` initialization. Return `ctx.Err()` on cancellation without consuming a slot.
    - _Requirements: 3.3, 3.4_

- [x] 5. LLM client — plug in semaphore + recovery wrappers
  - [x] 5.1 In `internal/llm/client.go::doChat`, acquire `resources.AcquireLLMSlot(ctx)` before issuing the HTTP request, release in `defer`, and wrap the function body with `defer safe.Recover("llm.doChat", scanID, &err)`
    - _Requirements: 1.5, 3.3, 3.4_

  - [x] 5.2 In `internal/llm/client.go::ChatStream`, replace the spawned goroutine with `safe.Go("llm.stream", scanID, func(){ ... })`
    - _Requirements: 1.2, 1.5_

  - [x] 5.3 Confirm and harden `RateLimitRPS`/`RateLimitBurst` behavior — the token bucket MUST block (not drop) and MUST honor `ctx.Done()` so cancellation propagates
    - _Requirements: 3.5, 3.4_

- [x] 6. Agent — panic boundaries, hard-timeout map, watchdog counter
  - [x] 6.1 Add `toolHardTimeout` map (`terminal_execute=65m`, `browser_action=10m`, default `15m`) and `hardTimeoutFor(tool string) time.Duration` to `internal/agent/agent.go`
    - _Requirements: 2.1_

  - [x] 6.2 Wrap `executeToolAsync` body in `defer safe.Recover("agent.tool_exec", a.scanCtx.ID, &returnErr)` and wrap the tool invocation in `context.WithTimeout(parent, hardTimeoutFor(name) + 30*time.Second)`
    - On timeout, emit `tools.Result{Error: "[TIMEOUT exceeded <X>s]"}` and trigger subprocess cleanup hooks for terminal/python/browser.
    - _Requirements: 1.1, 2.1_

  - [x] 6.3 Replace every bare `go fn()` in `agent.go` (heartbeat, watchdog spawner, streaming callback) with `safe.Go("agent.<role>", scanID, fn)`
    - _Requirements: 1.2_

  - [x] 6.4 Extend `startWatchdog` to call `safe.IncWatchdogKill()` on each kill and emit a structured WARN log with `command`, `duration`, `scan_id` fields
    - _Requirements: 2.2, 9.3_

  - [x] 6.5 Implement message-buffer pruning step invoked immediately before the next outbound LLM call so the serialized buffer stays below the configured pruning threshold
    - _Requirements: 2.3_

- [x] 7. Shared bounded I/O — `internal/tools/iolimit`
  - [x] 7.1 Create `internal/tools/iolimit/buffer.go` exposing `NewLimited(stdoutMax, stderrMax int)` factory and `LimitedBuffer` with `Write`, `Bytes`, `Truncated() bool`. The truncation flag flips at the **exact** limit byte
    - _Requirements: 2.4, 2.5_

  - [x] 7.2 Update `internal/tools/python/python.go` to import `iolimit` and construct stdout (1 MB) / stderr (512 KB) buffers
    - _Requirements: 2.5_

  - [x] 7.3 Update `internal/tools/terminal/terminal.go::runShellInternal` to construct `iolimit` buffers (1 MB stdout, 512 KB stderr) and surface `Truncated()` in result metadata
    - _Requirements: 2.4_

- [x] 8. Per-tool Path_Policy compliance
  - [x] 8.1 Route every `fileedit` create / replace / insert / delete operation through `sandbox.Default().CheckResolve(sc, "fileedit.<op>", path)`
    - _Requirements: 8.1, 5.3_

  - [x] 8.2 Route every `reporting` write through `sandbox.Default().CheckResolve(sc, "reporting", path)`
    - _Requirements: 8.2_

  - [x] 8.3 Route every `notes` tool persistence write (including `NoteStore`) through `sandbox.Default().CheckResolve(sc, "notes", path)`
    - _Requirements: 8.3_

  - [x] 8.4 Route every `skills` tool cache write through `sandbox.Default().CheckResolve(sc, "skills", path)`
    - _Requirements: 8.4_

  - [x] 8.5 Route every browser cache, extension extraction, and session persistence write through `sandbox.Default().CheckResolve(sc, "browser", path)` and place caches under `~/.xalgorix/browser/`
    - _Requirements: 8.5_

- [x] 9. Fix python and terminal workspace leaks
  - [x] 9.1 Refactor `preparePythonWorkspace` so `.tmp/`, `.cache/`, `.config/`, `.local/share/` are created **only** under `sc.ScanDir`; never under `$CWD`. When `sc == nil` fall back to `cfg.WorkspaceRoot` (Data_Dir)
    - _Requirements: 8.7, 8.10_

  - [x] 9.2 Set `HOME`, `TMPDIR`, `XDG_CACHE_HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME` for the python child process to paths within `sc.ScanDir` (or `cfg.WorkspaceRoot` when no Scan_Context)
    - _Requirements: 8.8, 8.10_

  - [x] 9.3 Refactor `prepareCommandWorkspace` so `.tmp/`, `.cache/`, `.config/`, `.local/share/` are created **only** under `sc.ScanDir`; never under `$CWD`. When `sc == nil` fall back to `cfg.WorkspaceRoot`
    - _Requirements: 8.6, 8.10_

  - [x] 9.4 Set `HOME`, `TMPDIR`, `XDG_*` for the terminal child process to paths within `sc.ScanDir` (or `cfg.WorkspaceRoot` when no Scan_Context)
    - _Requirements: 8.9, 8.10_

  - [x] 9.5 Verify (and add a defensive guard) that any other tool relying on `os.Getwd()` for resolution now uses `sandbox.Resolve` instead; remove `$CWD` reads from the filesystem-tool paths
    - _Requirements: 8.10, 5.5_

- [x] 10. Browser tool — lease + `ApplyProcessLimitsWithLimit`
  - [x] 10.1 In `internal/tools/browser`, call `resources.AcquireToolLeaseContext(ctx, false /* isHeavy */, "browser_action")` before creating the first browser context for a Scan_Context; cache the lease on `BrowserState`
    - _Requirements: 4.3, 4.7_

  - [x] 10.2 Apply `terminal.ApplyProcessLimitsWithLimit(cmd, true, lease.MemoryLimitBytes())` to the spawned browser process tree immediately after `cmd.Start()`
    - _Requirements: 4.4_

  - [x] 10.3 Release the cached lease exactly once in `BrowserState.Close` (idempotent via `sync.Once`)
    - _Requirements: 4.5_

- [x] 11. Web server hardening
  - [x] 11.1 Wrap the HTTP mux with `safe.HTTPMiddleware` in `internal/web/server.go::Start` so any handler panic returns 500 and is recorded
    - _Requirements: 1.3_

  - [x] 11.2 Add `s.admissionWake chan struct{}` (buffered len=1); replace the busy-poll in `runMultiScan` with a select on `admissionWake` or a 2-second ticker; signal `admissionWake` non-blockingly in `executeScanSession`'s defer cleanup so exactly one waiter wakes per terminate
    - _Requirements: 3.2, 3.3, 3.6_

  - [x] 11.3 On admission refusal, call `safe.IncAdmissionRefusal()` and emit a structured INFO log with `level`, `reason`, `ceiling`
    - _Requirements: 3.1, 3.2, 9.2_

  - [x] 11.4 Extend `handleStatus` to expose `panics_recovered`, `path_rejections`, `watchdog_kills`, `admission_refusals`, `llm_inflight_cap`, `data_dir`, and `allow_list`
    - _Requirements: 9.5_

- [x] 12. Scheduler hardening
  - [x] 12.1 In `internal/web/scheduler.go::checkAndRunSchedules`, add `defer safe.Recover("scheduler.tick", "")` at function entry
    - _Requirements: 1.4_

  - [x] 12.2 Inside the per-schedule loop, wrap each iteration with `defer safe.Recover("scheduler."+sch.ID, "")` so one failing schedule cannot kill the tick
    - _Requirements: 1.4_

- [x] 13. ScanContext close hardening
  - [x] 13.1 Add `defer safe.Recover("scanctx.close", sc.ID)` to `internal/scanctx/context.go::Close`
    - _Requirements: 1.2_

  - [x] 13.2 Ensure `Terminal.KillAll()` and `Browser.Close()` both run during `Close` even if one of them panics; wrap each in its own recovered closure
    - _Requirements: 4.6, 4.2 (orphan reaping)_

  - [x] 13.3 Release every Tool_Lease cached on the Scan_Context exactly once during `Close` (lease conservation under panic)
    - _Requirements: 4.1, 4.5_

- [ ] 14. Property tests — `pgregory.net/rapid`, ≥100 iterations each
  - [ ]* 14.1 Property 1 — universal panic containment in `internal/safe/recover_property_test.go`
    - **Property 1: Universal panic containment**
    - Generate `(component, scanID, panicValue)` triples; assert `safe.Recover` (a) increments `PanicsRecovered` exactly once, (b) emits exactly one `[recover]` log line containing `component` and a stack trace, (c) when `errp` provided sets `*errp` to a typed error.
    - **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 9.4**

  - [ ]* 14.2 Property 2 — tool hard-timeout monotonicity in `internal/agent/timeout_property_test.go`
    - **Property 2: Tool hard-timeout monotonicity**
    - Stub a tool that ignores context cancellation; generate timeouts in `[1ms, 50ms]`; assert wall-clock return ≤ timeout + 30s grace and result is a typed timeout error.
    - **Validates: Requirements 2.1, 2.2**

  - [ ]* 14.3 Property 3 — captured-output bound in `internal/tools/iolimit/buffer_property_test.go`
    - **Property 3: Captured-output bound**
    - Generate write sequences of arbitrary chunk sizes; assert `len(Bytes()) ≤ limit` and `Truncated()` is true iff total writes exceeded the limit.
    - **Validates: Requirements 2.4, 2.5**

  - [ ]* 14.4 Property 4 — bounded message history in `internal/agent/history_property_test.go`
    - **Property 4: Bounded message history before LLM calls**
    - Generate sequences of fake assistant/user messages; assert that immediately before each simulated LLM call the serialized buffer is below the threshold.
    - **Validates: Requirements 2.3**

  - [ ]* 14.5 Property 5 — admission and slot conservation in `internal/web/admission_property_test.go`
    - **Property 5: Admission and slot conservation**
    - Generate admit/terminate event sequences with random ceilings C; assert active count never exceeds C, every freed slot wakes exactly one waiter in bounded time, and cancelled waiters return `ctx.Err()` without consuming a slot.
    - **Validates: Requirements 3.1, 3.2, 3.4, 3.6, 2.6**

  - [ ]* 14.6 Property 6 — LLM in-flight cap in `internal/resources/llm_property_test.go`
    - **Property 6: LLM in-flight cap**
    - Generate concurrent acquire patterns with random caps C in `[1, 16]`; assert simultaneous in-flight count ≤ C; cancelled waiters never consume a slot.
    - **Validates: Requirements 3.3, 3.4, 3.5**

  - [ ]* 14.7 Property 7 — lease conservation across tool families in `internal/resources/lease_property_test.go`
    - **Property 7: Lease conservation across tool families**
    - Generate randomized terminal/python/browser launch+exit sequences (with injected panics); assert every successful acquire pairs with exactly one release, `ApplyProcessLimitsWithLimit` is invoked with the lease's memory limit, and on Scan_Context close tracked-child count returns to zero.
    - **Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7**

  - [ ]* 14.8 Property 8 — Path_Policy boundary in `internal/sandbox/policy_property_test.go`
    - **Property 8: Path_Policy boundary check**
    - Generate `(roots, target)` pairs including symlinks, `..`-bearing relatives, absolute and relative variants; assert `Check` admits iff canonical-form is contained in some root, rejects produce `*PathRejectError`, no filesystem mutation occurs, and equivalent canonical forms produce identical decisions.
    - **Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 8.1, 8.2, 8.3, 8.4, 8.5, 8.3, 9.1**

  - [ ]* 14.9 Property 9 — Data_Dir resolution in `internal/config/datadir_property_test.go`
    - **Property 9: Data_Dir resolution**
    - Generate random home dirs and random `XALGORIX_DATA_DIR` values (both unset and well-formed paths); assert resolved `DataDir` matches `filepath.Clean(filepath.Abs(...))`, mode is `0o700`, and repeated loads are idempotent.
    - **Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.6**

  - [ ]* 14.10 Property 10 — Migration_Warning emission rules in `internal/config/migration_property_test.go`
    - **Property 10: Migration_Warning emission rules**
    - Generate combinations of `$CWD` contents (with/without legacy markers) and `XALGORIX_DATA_DIR` (set/unset); assert warning fires iff env unset AND `$CWD != DataDir` AND a marker exists; assert at most one emission per process; assert `$CWD` contents are unchanged by detection.
    - **Validates: Requirements 7.1, 7.2, 7.3, 7.4, 7.5**

  - [ ]* 14.11 Property 11 — workspace-leak prevention across python and terminal tools
    - File: `internal/tools/python/python_isolation_property_test.go` and `internal/tools/terminal/terminal_isolation_property_test.go`.
    - **Property 11: Workspace-leak prevention**
    - Generate random scan-context configurations and command/script invocations; assert no `.tmp/`, `.cache/`, `.config/`, `.local/` directory exists under `$CWD` post-run that did not exist pre-run; assert `HOME`, `TMPDIR`, `XDG_*` exported to children are descendants of `sc.ScanDir`.
    - **Validates: Requirements 8.6, 8.7, 8.8, 8.9, 8.10**

  - [ ]* 14.12 Property 12 — health-endpoint counter monotonicity in `internal/web/counters_property_test.go`
    - **Property 12: Health endpoint counter monotonicity**
    - Generate event sequences (panics, path rejects, watchdog kills, admission refusals); assert each counter increases by exactly the count of events of its type since the last snapshot and never decreases.
    - **Validates: Requirements 9.1, 9.2, 9.5**

- [x] 15. Documentation and migration notes **[BREAKING CHANGE]**
  - [x] 15.1 Add an "Upgrading from previous versions" section to `README.md` describing:
    - The default change of `Workspace` from `$CWD` to `~/.xalgorix/data/`.
    - The `XALGORIX_DATA_DIR=$(pwd)` opt-out.
    - The `XALGORIX_LLM_MAX_INFLIGHT` env var.
    - The new health endpoint counters.
    - _Requirements: 7.2, 6.1, 6.2_

  - [x] 15.2 Add a `CHANGELOG.md` (or equivalent) entry titled "Breaking change: default workspace moved to `~/.xalgorix/data/`" with the migration one-liner and links to the relevant requirement sections
    - _Requirements: 7.2_

- [x] 16. Final checkpoint — Ensure all tests pass
  - Run `go vet ./...`, `go build ./...`, and `go test ./... -race -count=1` locally; for property suites use `-rapid.checks=200` where called out. Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional property-test sub-tasks. Property tests use `pgregory.net/rapid` and run **at least 100 iterations** per property by default; `-rapid.checks=200` raises that ceiling for the larger state-machine tests (5, 7).
- Each task references the specific requirement sub-clauses it implements and (for test tasks) the property number it validates.
- Checkpoints are intentionally light because the dependency graph already ensures incremental validation — every implementation wave is followed by tasks that exercise the new surface.
- Tasks 3 and 15 carry the **breaking change** marker. The migration is announced via the Migration_Warning emitted at startup (Task 3.3) and documented in the README/CHANGELOG (Tasks 15.1, 15.2). No automatic data migration is performed (Requirement 7.5).
- Files touched by multiple sub-tasks (`internal/config/config.go`, `internal/agent/agent.go`, `internal/web/server.go`, `internal/tools/python/python.go`, `internal/tools/terminal/terminal.go`, `internal/tools/browser/*.go`, `internal/scanctx/context.go`) are split across waves to avoid concurrent-edit conflicts.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "2.1", "2.2", "3.1", "4.1", "7.1"] },
    { "id": 1, "tasks": ["1.2", "2.3", "3.2", "7.2", "7.3", "12.1", "13.1"] },
    { "id": 2, "tasks": ["3.3", "8.1", "8.2", "8.3", "8.4", "12.2", "13.2"] },
    { "id": 3, "tasks": ["3.4", "8.5", "10.1", "13.3"] },
    { "id": 4, "tasks": ["3.5", "6.1", "9.1", "9.3", "10.2"] },
    { "id": 5, "tasks": ["3.6", "6.2", "9.2", "9.4", "10.3", "11.1", "11.3"] },
    { "id": 6, "tasks": ["6.3", "9.5", "11.2"] },
    { "id": 7, "tasks": ["6.4", "11.4"] },
    { "id": 8, "tasks": ["5.1", "5.2", "5.3", "6.5"] },
    { "id": 9, "tasks": ["14.1", "14.2", "14.3", "14.4", "14.5", "14.6", "14.7", "14.8", "14.9", "14.10", "14.11", "14.12"] },
    { "id": 10, "tasks": ["15.1", "15.2"] }
  ]
}
```
