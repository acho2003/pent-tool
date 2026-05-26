# Changelog

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
