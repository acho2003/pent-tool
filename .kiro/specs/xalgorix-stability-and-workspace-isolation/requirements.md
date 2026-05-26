# Requirements Document

## Introduction

Xalgorix currently exhibits three classes of operational defects that are blocking confident long-running and multi-tenant use:

1. **Server crashes** — unrecovered panics in tool goroutines, scheduler tasks, and web handlers, plus hangs and OOM kills during long scans, take the whole binary down instead of failing one request.
2. **Resource overloading** — concurrent agents, LLM calls, and child processes (browser, python, terminal) are spawned faster than the host can sustain. Memory grows unboundedly across long scans and stacked instances.
3. **Workspace bleed** — filesystem-touching tools resolve relative paths against `Workspace = $CWD`, so when the binary is launched from the source tree (or any unrelated directory) artifacts (`.cache`, `.config`, `.local`, `.tmp`, scan output, notes) are written wherever the user happened to be, not into a predictable location. The Python tool's `preparePythonWorkspace` is the most visible case, dropping `.tmp/`, `.cache/`, `.config/`, `.local/` into the repo root.

This spec specifies the corrective behavior in three thematic areas: crash resilience (A), resource and concurrency bounds (B), and workspace isolation (C). It defines an allow-list workspace boundary and a default data directory under `~/.xalgorix/data/`, replacing the legacy `Workspace = $CWD` default. The change is intentionally breaking, and a migration warning is part of the contract.

## Glossary

- **Agent_Loop**: The per-scan loop in `internal/agent/agent.go` that orchestrates LLM calls and tool execution.
- **Allow_List**: The set of root prefixes a filesystem-touching tool is permitted to write into. For Xalgorix the Allow_List is exactly: the active Data_Dir, `~/.xalgorix/`, and `/tmp/`.
- **Browser_Tool**: The browser tool family in `internal/tools/browser`.
- **Config_Loader**: The `config.Get()` / `config.load()` path in `internal/config/config.go`.
- **Data_Dir**: The active per-installation data root. Defaults to `~/.xalgorix/data/`. Overridable via the `XALGORIX_DATA_DIR` environment variable.
- **Filesystem_Tool**: Any tool in `internal/tools/{fileedit, reporting, terminal, python, notes, browser, skills}` that creates, writes, or modifies files on disk.
- **LLM_Client**: The LLM client in `internal/llm` invoked by the Agent_Loop.
- **Migration_Warning**: A single, prominent log message emitted at startup when a pre-existing legacy workspace layout is detected (notes/reports/cache present in `$CWD` rather than under Data_Dir).
- **Path_Policy**: The boundary check that confines Filesystem_Tool writes to the Allow_List.
- **Python_Tool**: The Python execution tool in `internal/tools/python`.
- **Resource_Governor**: The admission and lease layer in `internal/resources` (`EffectiveMaxInstances`, `AcquireToolLeaseContext`, `ApplyProcessLimits*`).
- **Scan_Context**: The per-session state container in `internal/scanctx` (`Vulns`, `Notes`, `Terminal`, `Browser`).
- **Scheduler**: The dashboard scheduler in `internal/web/scheduler.go`.
- **System**: Xalgorix as a whole binary, comprising the CLI, the dashboard web server, and the scan workers.
- **Terminal_Tool**: The terminal execution tool in `internal/tools/terminal`.
- **Tool_Lease**: The CPU/RAM reservation acquired from the Resource_Governor before launching a heavy subprocess.
- **Watchdog**: The per-Agent_Loop monitor in `agent.startWatchdog` that enforces process timeouts and reaps stale state.
- **Web_Server**: The dashboard HTTP server in `internal/web/server.go`.
- **Workspace_Root**: The root directory used by Filesystem_Tool path resolution when no Scan_Context is present. Equals Data_Dir.

## Requirements

### Requirement 1: Crash resilience — panic isolation

**User Story:** As an operator running long autonomous scans, I want a panic in any single tool, agent, or HTTP handler to be contained, so that one bad request never takes the whole Xalgorix server down.

#### Acceptance Criteria

1. WHEN a Filesystem_Tool, Terminal_Tool, Python_Tool, or Browser_Tool panics during execution, THE Agent_Loop SHALL recover the panic, record it as a tool error, and continue the scan.
2. WHEN any goroutine spawned by the Agent_Loop (heartbeat, watchdog, streaming callback) panics, THE Agent_Loop SHALL recover the panic, log a structured error with the goroutine name and stack trace, and continue the scan.
3. WHEN an HTTP handler in the Web_Server panics, THE Web_Server SHALL return HTTP 500 to the client and SHALL keep serving subsequent requests.
4. WHEN a Scheduler task panics, THE Scheduler SHALL log the panic with the schedule ID and stack trace and SHALL continue evaluating other schedules at the next tick.
5. WHEN the LLM_Client panics or the underlying transport returns an unrecoverable error, THE Agent_Loop SHALL surface the failure as a scan error event and SHALL terminate only the affected scan instance.
6. THE System SHALL log every recovered panic with the component name, the scan instance ID (when applicable), the panic value, and a goroutine stack trace.

#### Correctness Properties

- **P1.1 (containment):** For any sequence of N tool invocations where K invocations panic, the Agent_Loop completes processing of all N invocations and reports exactly K tool-error results. The process exit status is unaffected by K.
- **P1.2 (server liveness):** For any sequence of HTTP requests where any subset triggers a handler panic, the Web_Server continues to accept new connections and respond to non-panicking handlers.
- **P1.3 (no silent panics):** Every recovered panic produces exactly one structured log entry containing the component name and a stack trace.

---

### Requirement 2: Crash resilience — hangs and OOM

**User Story:** As an operator, I want hangs and memory growth to be detected and contained instead of silently consuming the host, so that a stuck child process or runaway message history cannot OOM-kill the binary.

#### Acceptance Criteria

1. WHEN a tool invocation exceeds its hard timeout (terminal_execute: 65 minutes; browser_action: 10 minutes; all other tools: 15 minutes), THE Agent_Loop SHALL force-return a timeout error, kill associated child processes for `terminal_execute` and `python_action`, and SHALL clean up the browser context for `browser_action`.
2. WHEN a single tracked subprocess has been running longer than 30 minutes, THE Watchdog SHALL kill the process, reset the Agent_Loop activity timer, and emit an error event identifying the killed command.
3. WHEN the Agent_Loop's accumulated message buffer would exceed the configured pruning threshold, THE Agent_Loop SHALL prune messages before issuing the next LLM call.
4. THE Terminal_Tool SHALL bound captured stdout to 1 MB and captured stderr to 512 KB per invocation, marking output as truncated when those limits are reached.
5. THE Python_Tool SHALL bound captured stdout to 1 MB and captured stderr to 512 KB per invocation, marking output as truncated when those limits are reached.
6. WHEN the Resource_Governor reports `LevelCritical`, THE System SHALL refuse to admit new scan instances and SHALL refuse to acquire new heavy Tool_Leases until the level returns to `LevelCaution` or `LevelOK`.
7. IF the Go runtime memory limit is reached, THEN THE System SHALL cancel the lowest-priority in-flight LLM call or tool invocation rather than allowing the OS OOM killer to terminate the process.

#### Correctness Properties

- **P2.1 (timeout monotonicity):** No tool invocation returns later than its configured hard timeout plus a 30-second grace.
- **P2.2 (output bound):** For any tool invocation, captured stdout size never exceeds 1 MB and captured stderr never exceeds 512 KB; exceeding either flips the truncation flag.
- **P2.3 (bounded message history):** After any sequence of LLM turns, the Agent_Loop's serialized message buffer size remains below the pruning threshold prior to the next LLM call.
- **P2.4 (admission monotonicity):** While the Resource_Governor reports `LevelCritical`, the count of active scan instances and heavy Tool_Leases does not increase.

---

### Requirement 3: Resource bounds — concurrent agents and LLM calls

**User Story:** As an operator, I want concurrent agents and outbound LLM calls to be capped by live system capacity, so that stacking scans never produces more load than the host can sustain.

#### Acceptance Criteria

1. WHEN a new scan instance is requested, THE Web_Server SHALL consult `resources.EffectiveMaxInstances()` and SHALL admit the scan only if the running count is below the live ceiling.
2. IF admission is refused, THEN THE Web_Server SHALL queue the scan request and SHALL return a queued status with the reason returned by the Resource_Governor.
3. THE LLM_Client SHALL enforce a maximum number of in-flight outbound LLM calls per process equal to the value of `XALGORIX_LLM_MAX_INFLIGHT` (default: 4 × `EffectiveMaxInstances` at startup, minimum 1).
4. WHEN the in-flight LLM cap is reached, THE LLM_Client SHALL block additional LLM calls until a slot frees, honoring the calling Agent_Loop's context cancellation.
5. THE LLM_Client SHALL enforce the existing `RateLimitRPS` and `RateLimitBurst` token bucket against outbound LLM calls, blocking rather than dropping requests.
6. WHEN a scan instance terminates (success, error, or cancellation), THE Web_Server SHALL release its instance slot and SHALL evaluate queued requests.

#### Correctness Properties

- **P3.1 (instance ceiling):** At any instant, the number of active scan instances is less than or equal to the value last returned by `resources.EffectiveMaxInstances()`.
- **P3.2 (LLM ceiling):** At any instant, the number of in-flight LLM calls is less than or equal to `XALGORIX_LLM_MAX_INFLIGHT`.
- **P3.3 (no starvation):** If a scan instance slot or LLM slot becomes free and at least one request is waiting, exactly one waiting request becomes runnable in bounded time.
- **P3.4 (cancellation propagation):** When an Agent_Loop's context is cancelled while a queued LLM or admission request is waiting, that waiter exits with a cancellation error within bounded time and does not consume a slot.

---

### Requirement 4: Resource bounds — child processes and per-scan budgets

**User Story:** As an operator, I want every browser, python, and terminal child process to be admitted under the same lease system and bounded by the per-scan memory budget, so that runaway children cannot exceed the host's capacity.

#### Acceptance Criteria

1. WHEN the Terminal_Tool launches a subprocess classified as heavy, THE Terminal_Tool SHALL acquire a heavy Tool_Lease from the Resource_Governor before starting the process.
2. WHEN the Python_Tool launches a Python subprocess, THE Python_Tool SHALL acquire a Tool_Lease from the Resource_Governor before starting the process.
3. WHEN the Browser_Tool launches a browser instance for a Scan_Context, THE Browser_Tool SHALL acquire a Tool_Lease from the Resource_Governor before starting the process.
4. WHEN a Tool_Lease is granted, THE Resource_Governor SHALL apply the lease's memory limit to the child process via `ApplyProcessLimitsWithLimit`.
5. THE Terminal_Tool, Python_Tool, and Browser_Tool SHALL release their Tool_Lease exactly once when the corresponding child process exits or is killed.
6. WHEN a Scan_Context is closed, THE Scan_Context SHALL kill all tracked child processes via `Terminal.KillAll()` and SHALL close the browser instance.
7. IF the Resource_Governor cannot grant a Tool_Lease within the calling tool's context deadline, THEN the calling tool SHALL return a cancellation result and SHALL not start the subprocess.

#### Correctness Properties

- **P4.1 (lease conservation):** For every successfully acquired Tool_Lease there is exactly one matching release; on Scan_Context close, all leases held by that context are released.
- **P4.2 (no orphaned children):** After a Scan_Context is closed, the count of tracked child processes for that context returns to zero within bounded time.
- **P4.3 (per-process memory cap):** No tracked child process is started without `ApplyProcessLimitsWithLimit` being applied with the lease's memory limit.

---

### Requirement 5: Workspace isolation — allow-list policy

**User Story:** As a security tool operator, I want all file writes to be confined to a small, well-defined allow-list, so that running Xalgorix from any directory cannot pollute that directory and cannot accidentally leak data outside the intended boundary.

#### Acceptance Criteria

1. THE Path_Policy SHALL define the Allow_List as exactly three roots: the active Data_Dir, `~/.xalgorix/`, and `/tmp/`.
2. WHEN a Filesystem_Tool resolves a write target, THE Path_Policy SHALL canonicalize the target via `filepath.EvalSymlinks` (when the path exists) or `filepath.Clean` (when it does not), and SHALL verify the canonical path is contained within at least one Allow_List root.
3. IF a Filesystem_Tool attempts to write to a path outside the Allow_List, THEN THE Path_Policy SHALL reject the write, return a structured error containing the rejected path and the Allow_List, and SHALL not create or modify any file.
4. THE Path_Policy SHALL apply identically whether the path is provided as relative or absolute, whether it traverses symlinks, and whether it contains `..` segments.
5. WHEN a Filesystem_Tool resolves a relative path, THE Filesystem_Tool SHALL resolve it against the Scan_Context's `ScanDir` if present, otherwise against the Workspace_Root.
6. THE Filesystem_Tool reject errors SHALL be logged at WARN level with the tool name, the rejected path, and the Scan_Context ID.

#### Correctness Properties

- **P5.1 (containment):** For any path P that a Filesystem_Tool successfully writes to, the canonical form of P is a descendant of at least one Allow_List root.
- **P5.2 (rejection determinism):** For any path P that the Path_Policy rejects, no file under P exists or was modified after the call returns.
- **P5.3 (symlink robustness):** A symlink whose target lies outside the Allow_List is rejected even when the symlink itself is inside the Allow_List.
- **P5.4 (relative-path safety):** A relative path containing `..` segments that resolve outside the Allow_List is rejected.

---

### Requirement 6: Workspace isolation — default Data_Dir and override

**User Story:** As a fresh Xalgorix user, I want a predictable default location for all generated artifacts, so that scans never write into my current directory by surprise.

#### Acceptance Criteria

1. THE Config_Loader SHALL set Data_Dir to `~/.xalgorix/data/` by default.
2. WHEN the environment variable `XALGORIX_DATA_DIR` is set to a non-empty value, THE Config_Loader SHALL set Data_Dir to that value and SHALL canonicalize it via `filepath.Abs` and `filepath.Clean`.
3. WHEN the System starts, THE Config_Loader SHALL create Data_Dir (with parents) using mode `0o700` if it does not already exist.
4. THE Config_Loader SHALL set Workspace_Root equal to Data_Dir.
5. IF Data_Dir resolution or creation fails, THEN THE Config_Loader SHALL return a startup error identifying the path and the underlying error and SHALL prevent the System from starting.
6. WHEN no per-scan `ScanDir` is provided, THE Filesystem_Tool resolution path SHALL use Workspace_Root as the working directory.
7. THE Config_Loader SHALL log the resolved Data_Dir at INFO level once at startup.

#### Correctness Properties

- **P6.1 (deterministic default):** With `XALGORIX_DATA_DIR` unset, Data_Dir equals `filepath.Join(homeDir, ".xalgorix", "data")`.
- **P6.2 (override honored):** With `XALGORIX_DATA_DIR=/foo/bar`, Data_Dir equals `/foo/bar` after canonicalization.
- **P6.3 (creation idempotence):** Repeatedly starting the System with the same `XALGORIX_DATA_DIR` does not change the directory's mode, ownership, or contents.

---

### Requirement 7: Workspace isolation — migration of legacy CWD-based layouts

**User Story:** As an existing Xalgorix user upgrading to this release, I want a clear warning when my prior `$CWD`-based artifacts are no longer the active workspace, so that I am not surprised that scans now write elsewhere and so that I can migrate intentionally.

#### Acceptance Criteria

1. WHEN the System starts, THE Config_Loader SHALL detect a legacy layout by looking for any of `notes.json`, `_schedules/`, `vulnerabilities.json`, or scan-output directories matching the date-based pattern (`YYYY-MM-DD/scan-*`) in the current working directory.
2. WHEN a legacy layout is detected and `$CWD` is not Data_Dir, THE Config_Loader SHALL emit the Migration_Warning to stderr at WARN level. The Migration_Warning SHALL state: the detected legacy directory, the active Data_Dir, that the new default has changed in this release, and a one-line instruction to set `XALGORIX_DATA_DIR=$(pwd)` to retain the legacy behavior.
3. THE Config_Loader SHALL emit the Migration_Warning at most once per process startup.
4. WHERE `XALGORIX_DATA_DIR` is set explicitly, THE Config_Loader SHALL suppress the Migration_Warning regardless of legacy-layout detection.
5. THE Config_Loader SHALL not move, copy, modify, or delete legacy files automatically.

#### Correctness Properties

- **P7.1 (warning idempotence):** A single process start emits the Migration_Warning exactly zero or one time.
- **P7.2 (no data mutation):** No legacy file under `$CWD` is created, modified, or deleted by Config_Loader as a side effect of detection.

---

### Requirement 8: Workspace isolation — filesystem-touching tools comply

**User Story:** As an operator, I want every filesystem-touching tool — including the Python tool that has been leaking pyenv directories — to obey the Path_Policy uniformly, so that no tool is a workspace-isolation hole.

#### Acceptance Criteria

1. THE `fileedit` tool SHALL route every create, replace, insert, and delete operation through the Path_Policy.
2. THE `reporting` tool SHALL route every report file write through the Path_Policy.
3. THE `notes` tool and `NoteStore` SHALL route every note persistence write through the Path_Policy.
4. THE `skills` tool SHALL route every skills cache write through the Path_Policy.
5. THE Browser_Tool SHALL route every cache, extension extraction, and session persistence write through the Path_Policy and SHALL place its caches under `~/.xalgorix/browser/`.
6. THE Terminal_Tool's `prepareCommandWorkspace` SHALL only create `.tmp/`, `.cache/`, `.config/`, `.local/share/` directories under the Scan_Context's `ScanDir` (an Allow_List descendant) and SHALL never create them under `$CWD`.
7. THE Python_Tool's `preparePythonWorkspace` SHALL only create `.tmp/`, `.cache/`, `.config/`, `.local/share/` directories under the Scan_Context's `ScanDir` (an Allow_List descendant) and SHALL never create them under `$CWD`.
8. WHEN the Python_Tool sets `HOME`, `TMPDIR`, `XDG_CACHE_HOME`, `XDG_CONFIG_HOME`, or `XDG_DATA_HOME` for its child process, THE Python_Tool SHALL set them to paths within the Scan_Context's `ScanDir`.
9. WHEN the Terminal_Tool sets `HOME`, `TMPDIR`, or `XDG_*` environment variables for its child process, THE Terminal_Tool SHALL set them to paths within the Scan_Context's `ScanDir`.
10. WHEN no Scan_Context is active (CLI default mode), THE Filesystem_Tool family SHALL use Workspace_Root (Data_Dir) as the resolution root.

#### Correctness Properties

- **P8.1 (Python isolation):** After a Python_Tool invocation, no `.tmp/`, `.cache/`, `.config/`, or `.local/` directory exists under `$CWD` that did not exist before the invocation.
- **P8.2 (Terminal isolation):** After a Terminal_Tool invocation, no `.tmp/`, `.cache/`, `.config/`, or `.local/` directory exists under `$CWD` that did not exist before the invocation.
- **P8.3 (uniform policy):** For each Filesystem_Tool listed above, a write target outside the Allow_List is rejected with the same structured error shape.
- **P8.4 (env-var redirection):** For every child subprocess launched by the Python_Tool or Terminal_Tool with a Scan_Context, the values of `HOME`, `TMPDIR`, `XDG_CACHE_HOME`, `XDG_CONFIG_HOME`, and `XDG_DATA_HOME` are descendants of that Scan_Context's `ScanDir`.

---

### Requirement 9: Observability of stability and isolation

**User Story:** As an operator, I want a single place to see when the System is shedding load, killing children, recovering panics, or rejecting writes, so that I can diagnose stability incidents without grepping the whole binary.

#### Acceptance Criteria

1. WHEN the Path_Policy rejects a write, THE System SHALL emit a structured log entry at WARN level containing the tool name, the rejected path, the Allow_List roots, and the Scan_Context ID.
2. WHEN the Resource_Governor refuses admission or a Tool_Lease, THE System SHALL emit a structured log entry at INFO level containing the level, the reason, and the live ceiling.
3. WHEN the Watchdog kills a subprocess, THE System SHALL emit a structured log entry at WARN level containing the command, the duration, and the Scan_Context ID.
4. WHEN a panic is recovered (Requirement 1), THE System SHALL emit the structured log entry described in Requirement 1.6.
5. THE Web_Server's existing health endpoint SHALL expose, in addition to its current fields, counters for: panics recovered since startup, Path_Policy rejections since startup, watchdog kills since startup, and admission refusals since startup.

#### Correctness Properties

- **P9.1 (counter monotonicity):** Each counter exposed by the health endpoint is monotonically non-decreasing over the lifetime of the process.
- **P9.2 (event-to-log correspondence):** For every panic recovery, Path_Policy rejection, watchdog kill, and admission refusal that occurs, exactly one structured log entry is emitted.
