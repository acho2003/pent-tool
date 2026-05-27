# Changelog

## [Unreleased] — Concurrency model: RAM-only admission

### Changed
- **Scan admission now derives concurrency purely from RAM headroom.** `EffectiveMaxInstances` no longer mixes CPU load and disk pressure into the slot count. CPU saturation throttles scans (the kernel time-slices) but doesn't crash them, so gating new scans on CPU only reduced total throughput. Disk consumption is bursty, not reserved up front; disk now acts as a yes/no admission gate that refuses new scans only when free space is below the critical floor (`XALGORIX_DISK_CRITICAL_MB`, default 1 GB).
- **Per-tool CPU throttling is unchanged** and still lives in the tool-lease layer (`tryAcquireToolLease`), where it correctly queues heavy subprocess launches without blocking scan admission.
- **Dashboard layout.** The "Max N · scan budget · tool cap" caption moved from under the DISK FREE tile to under HOST MEMORY, where the underlying constraint actually lives. DISK FREE now describes its own role.
- **Admission rationale** strings (`/api/status`, the dashboard) only mention dimensions that actually gate admission (RAM and disk-critical). Pre-cleanup, an "instances 4/4 — CPU critical: load X" message was misleading because admission proceeded regardless of CPU.

### Removed
- `XALGORIX_SCAN_CPU_LOAD` env var and its associated `perScanCPULoad` / `autoScanCPULoad` plumbing, the `Capacity().ScanCPULoad` field, the `scan_cpu_load` field on `/api/status`, and the matching settings UI row. The knob hadn't influenced admission since it was a stealth no-op; setting it now logs a one-time deprecation notice on startup.
- Internal `cpuInstanceCapacity` helper (no callers after the refactor).
- Internal `hostMatchesLocalInterface` helper (dead code; `isBlockedTarget` now routes through `ipsMatchLocalInterface`).
- The `level` parameter on `effectiveMaxInstancesForStats` (it was unused after the refactor).

### Fixed
- `effectiveMaxInstancesForStats` no longer calls `memoryInstanceCapacity` twice on the same `stats` snapshot.

## v4.4.19 — Scope guard hardening v2

### Fixed
- **URL-in-query-param bypass closed.** `scopeHostTokenSplit` in `internal/agent/agent.go` now also breaks tokens on `=`, `?`, `#`, and `@`, and a new `extractEmbeddedURLs` sweep pulls every `http://` / `https://` substring out of an arg value before the separator pass. An OOS host smuggled inside a redirect query parameter (e.g. `https://in-scope.example/redirect?next=https://oos.example/path`), a userinfo form (`user@oos.example`, `https://user:pass@oos.example/`), or any of the new delimiters now surfaces as a standalone token and the gated tool call is rejected.
- **Per-arg scan length capped at 8 KiB.** A new `argScanLimitBytes = 8192` constant plus `truncateForScopeScan` helper bound how much of any single Arg_Value the agent-side guard tokenizes. Values ≤ 8 KiB still walk the same path byte-for-byte; values larger than 8 KiB are silently truncated at the largest UTF-8 rune-boundary offset ≤ 8192. The cap never short-circuits to a reject — oversize args fall through to the existing allow path on length alone.
- **Single DNS lookup per `isBlockedTarget` call.** `isBlockedTarget` in `internal/web/server.go` now parses the host as a `net.IP` literal first, otherwise issues exactly one `net.LookupHost` (via a package-level `lookupHost` shim for testability), and threads the resolved IP slice into both the self-listener check (new internal helper `ipsMatchLocalInterface`) and the private-range check. DNS failure preserves the prior `return false` (allow) verdict.
- **OOS hostnames in `add_note` are redacted, not leaked.** A new `(*Agent).redactOutOfScopeHosts` method mirrors the gated tokenization path and substitutes the literal marker `[redacted: out-of-scope host]` for every OOS host span in the `key` and `value` arguments of `add_note`. The agent loop applies redaction in place immediately before `shouldBlockForOutOfScope`, so notes can no longer launder OOS hostnames through `read_notes` on the next iteration. Gated tools continue to reject rather than redact.

### See also
Spec: `.kiro/specs/scope-guard-hardening-v2/requirements.md`

## [Unreleased]

### Breaking changes

#### Default workspace moved to `~/.xalgorix/data/`

The default location for scan output, notes, schedules, and other generated artefacts moved from `$CWD` (the directory the binary was launched from) to `~/.xalgorix/data/`. This is the single most visible part of the stability + workspace-isolation release.

**To retain previous behavior**, run:
```
export XALGORIX_DATA_DIR=$(pwd)
```

A `[MIGRATION]` warning is emitted at startup when legacy markers (`notes.json`, `_schedules/`, `vulnerabilities.json`, or `YYYY-MM-DD/scan-*` directories) are detected in `$CWD` and `XALGORIX_DATA_DIR` is unset.

### Added
- `XALGORIX_LLM_MAX_INFLIGHT`: caps concurrent outbound LLM calls (default: `4 × EffectiveMaxInstances`, minimum 1).
- Health endpoint counters: `panics_recovered`, `path_rejections`, `watchdog_kills`, `admission_refusals`, `llm_inflight_cap`, `data_dir`, `allow_list`, `read_deny`.
- Path_Policy boundary check: every filesystem-touching tool now writes only into `~/.xalgorix/data/`, `~/.xalgorix/`, or `/tmp/`.
- Read-policy: filesystem-touching tools may now READ anywhere on the host (system wordlists, payload directories, `/etc/services`, etc.) so agents can use shared assets without copying them into the workspace. A built-in deny-list still rejects reads of sensitive paths (`~/.ssh`, `~/.aws`, `~/.gnupg`, `/etc/shadow`, `/etc/sudoers`, `/proc/kcore`, etc.). Set `XALGORIX_READ_DENY_LIST` (colon-separated) to extend the defaults. The active deny-list is exposed as `read_deny` on `/api/status`.
- Browser tool now acquires Tool_Leases and applies process memory limits.
- Recovery for tool panics, scheduler ticks, HTTP handler panics, and ScanContext close panics.

### Fixed
- Python and terminal tools no longer leak `.tmp/`, `.cache/`, `.config/`, `.local/` directories into `$CWD`. They now create those scratch dirs under the active scan directory or `~/.xalgorix/data/`.
- Tool stdout/stderr now bounded to 1 MB / 512 KB respectively (prevents OOM from runaway output).

### See also
Spec: `.kiro/specs/xalgorix-stability-and-workspace-isolation/requirements.md`

## [Unreleased] — Findings consistency and pagination

### Fixed
- **Findings page no longer truncated to 30 scans.** The Findings dashboard now enumerates every scan on disk and paginates the union with controls for page size [25, 50, 100, 200] (default 50). Findings deduplicate across runs by `(target, endpoint, title, severity)`, with the surviving row linking to the most recent producing scan.
- **Counter flicker eliminated.** The Findings and Overview totals widgets keep prior data during refetches (`keepPreviousData`), so the visible total no longer drops to zero between background polls.
- **Counter monotonicity per scan.** A new `effectiveVulnCount(inst, sess)` helper consolidates the previous triple-source `inst.VulnCount` assignments. Counters now read in-memory while the scan is running and on-disk after teardown — they never visibly drop without a delete.
- **Panic-safe persistence of child findings.** `reporting.PromoteToParent` is invoked on every successful `report_vulnerability` so a child scan's findings reach the parent aggregate immediately. Combined with `MergeVulnsToContext` running in the deferred `cleanup()`, parent records survive child agent panics.

### Added
- **`/api/findings/summary` endpoint.** Returns severity counts derived from on-disk scan records, with an `as_of` timestamp and `etag` for cheap polling. Polled by the WebUI every 10s; honors `If-None-Match` for `304 Not Modified` responses.
- **`vulns_persisted` field in `/api/status`.** Stable on-disk total alongside the existing `vulns` (in-memory) field. Additive change — no breaking change for existing clients.
- **Legacy `~/xalgorix-data/` import.** On first server start after this release, scan records under `~/xalgorix-data/` are non-destructively copied into `cfg.DataDir`. A sentinel file `.legacy-imported` prevents repeated walks. The legacy directory is preserved; you may manually `rm -rf ~/xalgorix-data` after verifying the import via the WebUI banner and Findings page.

### Notes
- The legacy import is intentionally manual to undo. Automation here is out of scope.
- The previous spec's `safe.Recover` wrappers already contain agent-goroutine panics to a single scan; the panic that motivated this work no longer crashes the whole server even before the persistence fixes land. This bugfix focuses on counter and pagination correctness.
