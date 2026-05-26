# Bugfix Requirements Document

## Introduction

A security researcher running 71+ live scans against real targets reports four
interacting bugs on the Findings dashboard:

1. Findings appear, then disappear, then reappear while scans are running.
2. There is no pagination; only the first 30 scans are ever consulted, so the
   list is permanently truncated for any user with more than 30 scans on disk.
3. Severity counters jump (e.g., "critical 3 → critical 0 → critical 1") with
   no scan activity that would explain the drop, and a `runtime error: slice
   bounds out of range` panic in an agent goroutine appears in the live feed
   right before the count drops.
4. The Findings list does not include "current, previous, and subsequent"
   findings together — findings produced by a child scan that crashed never
   show up in the parent aggregate, and findings on disk from other scan runs
   are simply not enumerated.
5. Compounding all of the above: after the workspace migration to
   `~/.xalgorix/data/`, findings the user generated under the legacy
   `~/xalgorix-data/` directory are invisible to the post-migration server,
   amplifying the "data disappears" perception.

The defects span four root causes that all surface as the same user-visible
symptom ("findings disappear"):

- A hardcoded 30-scan slice in the Findings page (`webui/src/pages/findings.tsx`)
  with no pagination controls.
- A client-side `useQueries` fan-out with `staleTime: 30_000` that drops a
  scan's contribution to zero while its sub-query is refetching.
- A dashboard total computed exclusively from the in-memory reporting store
  (`reporting.GetVulnerabilitiesForContext`), which is wiped by
  `reporting.CleanupContext` on scan teardown — including the teardown that
  follows an agent panic.
- A child→parent vulnerability merge (`reporting.MergeVulnsToContext`) that
  runs only at session finalization, so child findings are lost from the
  parent aggregate when a child scan panics before reaching the merge.

Plus a one-time data-locality issue: legacy data under `~/xalgorix-data/` is
not migrated into the current `cfg.DataDir`.

The fix MUST restore consistency, completeness, and persistence of findings on
the dashboard without changing any other UI behavior (mouse clicks, search,
severity filter, single/bulk delete, scan launching, etc.).

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN the user has more than 30 scans on disk THEN the Findings page silently
ignores every scan after the 30th, displaying only findings from the most
recent 30 scan IDs.

1.2 WHEN the user is on the Findings page or the Overview page THEN the page
header and severity counter widgets transiently drop a scan's contribution to
zero while that scan's per-scan query is refetching after its 30-second stale
window, causing the totals to flicker downward and then snap back up with no
underlying state change on the server.

1.3 WHEN a scan finishes, is stopped, or its session is torn down (including
teardown after an agent panic) THEN the dashboard's `vulns` total in
`/api/status` drops the contribution of that scan's reporting context to zero,
because the total is computed solely from the in-memory store and that
in-memory store is deleted by `reporting.CleanupContext` during teardown.

1.4 WHEN an agent goroutine panics mid-scan (for example with `runtime error:
slice bounds out of range`) THEN the child scan's already-reported findings
are not merged into the parent reporting context, and they are not written to
the parent record's on-disk `Vulns` slice, so the parent aggregate loses
those findings even though the child's `scan.json` may contain them.

1.5 WHEN per-event vulnerability counters are updated during a scan THEN the
counter source switches between three different stores (`len(inst.Vulns)`,
`len(reporting.GetVulnerabilitiesForContext(parentReportingCtxID))`, and
`len(reporting.GetVulnerabilitiesForContext(sess.sctx.ID))`) at different
points in the scan lifecycle, so the counter visibly jumps as the scan
transitions between phases or between child sessions.

1.6 WHEN the Findings page is rendered THEN there is no pagination control of
any kind: no page-number controls, no page-size selector, no "load more"
button, no infinite scroll, and no virtualization.

1.7 WHEN the user has findings on disk under the legacy `~/xalgorix-data/`
directory from before the workspace migration THEN those findings are
completely absent from every UI surface, because the post-migration server
reads only from `cfg.DataDir` (`~/.xalgorix/data/`) and never inspects the
legacy path.

### Expected Behavior (Correct)

2.1 WHEN the user has more than 30 scans on disk THEN the Findings page SHALL
display findings from all scans on disk (subject to user-controlled pagination
and filtering), not just the first 30.

2.2 WHEN the user is on the Findings page or the Overview page and a per-scan
sub-query is refetching, finishing, or being torn down THEN the page-level
totals SHALL NOT drop below the previously observed value for the duration of
the page session, except in response to an explicit user delete action.

2.3 WHEN a scan finishes, is stopped, or its session is torn down (including
teardown after an agent panic) THEN the dashboard `vulns` total SHALL be
computed from the on-disk corpus of saved scan records (with the in-memory
store treated as an optimistic addition for unsaved findings), so the total
remains stable across teardown.

2.4 WHEN an agent goroutine panics mid-scan THEN every vulnerability that was
reported via `report_vulnerability` before the panic SHALL be persisted to
disk (in the child's `scan.json`) and SHALL also be merged into the parent
record's aggregate before the in-memory reporting context for that child is
released.

2.5 WHEN per-event vulnerability counters are updated during a scan THEN the
counter SHALL be sourced from a single, monotonic-non-decreasing
representation per running scan instance for the duration of that scan, so
the counter never visibly drops between events without a corresponding
delete operation.

2.6 WHEN the Findings page is rendered THEN it SHALL provide page-number
pagination controls (Prev / 1 2 … N / Next) at the bottom of the list, plus a
page-size selector with options [25, 50, 100, 200] and a default of 50, plus
a visible "updated Xs ago" indicator and manual refresh button on the totals
row.

2.7 WHEN the user has findings on disk under the legacy `~/xalgorix-data/`
directory THEN on first server start after the fix is deployed, the server
SHALL non-destructively copy every scan record from `~/xalgorix-data/` into
`cfg.DataDir` (skipping any record whose `id` is already present in
`cfg.DataDir`), and SHALL surface a one-time dismissible banner in the WebUI
indicating the number of imported scans.

2.8 WHEN the Findings page aggregates findings across multiple scan runs THEN
findings with the same `(target, endpoint, title, severity)` tuple SHALL be
deduplicated, and the surviving row SHALL link to the most recent scan that
produced that finding.

### Unchanged Behavior (Regression Prevention)

3.1 WHEN the user clicks a finding row THEN the system SHALL CONTINUE TO
navigate to the owning scan detail page exactly as before.

3.2 WHEN the user types into the search box on the Findings page THEN the
system SHALL CONTINUE TO filter findings by title, endpoint, host, CVE,
CWE, and OWASP fields with the existing case-insensitive substring match.

3.3 WHEN the user changes the severity filter dropdown THEN the system SHALL
CONTINUE TO restrict the visible findings to that severity using the existing
`normalizeSeverity` mapping.

3.4 WHEN the user selects findings via the row checkboxes and uses the
bulk delete action THEN the system SHALL CONTINUE TO call
`DELETE /api/scans/{scanId}/vulns/{vulnId}` for each selected finding with the
existing confirmation prompt and selection-state invalidation.

3.5 WHEN the user uses the per-row "Delete finding" action THEN the system
SHALL CONTINUE TO delete that single finding via the same endpoint with the
existing confirmation prompt.

3.6 WHEN a scan is running and the user is on a scan detail page THEN the
system SHALL CONTINUE TO show that scan's live findings via the existing
`useScan(id)` polling hook, with no change to its 2-second poll cadence.

3.7 WHEN the user launches, stops, or pauses a scan THEN the system SHALL
CONTINUE TO behave identically to before the fix, with no change to the
queue, scheduler, agent loop, or scan-session lifecycle aside from the
addition of crash-safe persistence and the parent-merge-on-report behavior
required by clauses 2.4 and 2.5.

3.8 WHEN the user uses keyboard or mouse interactions on any page other than
the Findings page and the Overview totals widget THEN the system SHALL
CONTINUE TO behave identically to before the fix.

3.9 WHEN the user has no scans on disk under either `cfg.DataDir` or
`~/xalgorix-data/` THEN the system SHALL CONTINUE TO render the existing
"No matching findings" empty state on the Findings page and SHALL NOT show
the legacy-import banner.

3.10 WHEN the server starts and `~/xalgorix-data/` does not exist or is
empty or has already been imported (sentinel marker present) THEN startup
SHALL CONTINUE TO behave identically to before the fix, with no extra disk
writes and no banner.
