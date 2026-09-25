# Increment 6: Report + Docs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the scanner report scope-aware: group findings by scope (host / source) with the classifier's track labels and a recon summary, collapse the same CVE reported by several scanners on one scope into one multi-source finding, and replace the README's "exactly five scanner statuses" contract with the DAG determinism contract.

**Architecture:** `scanner.ParseRuns` stamps every `Finding` with its run's scope and then runs a new cross-scanner merge keyed on `(Scope, CVE)`. The merged finding keeps the first contributor's `SourceID` (so the Report-AI `allowed` map and evidence trace are unchanged) and records every contributor in `Sources`. On the web side, `generateScannerReport` builds a `[]reportScope` from `rec.ScannerRuns` plus the persisted `recon-scopes.json` (tracks recomputed with the same fail-open rule the pipeline uses). It writes that list and a recon summary into `report.json`, orders findings by scope → severity → source ID, and hands the scopes to the PDF on a non-persisted `ScanRecord.ReportScopes` field. The PDF (`internal/web/report.go`) gains a "Scan Coverage" section plus scope group rows in the Findings Summary table. Both render only when `ReportScopes` is non-empty, so agent-mode (schema < 2) reports are unaffected.

**Tech Stack:** Go 1.26, `internal/scanner` (finding scope + merge + two exports), `internal/web` (report manifest, scope model, PDF via `github.com/go-pdf/fpdf`), `README.md`.

**Spec:** docs/superpowers/specs/2026-09-24-scanning-dag-pipeline-design.md. This implements §10 increment 6, covering §8 (report changes) and §7 (README determinism contract + migration note).

## Global Constraints

- **Go 1.26.** Darwin dev host: run tests with `CGO_ENABLED=0 go test` (CGO segfaults). NEVER use `go test -race` here.
- **Live report path is `internal/web`:** `report_ai.go` → `generateReportAt` (scan_query.go) → `generateReport` (report.go). `internal/reporting` is an unused duplicate (nothing imports it); do NOT modify it in this increment.
- **Determinism:** report ordering must be a pure function of `ScannerRuns` + `recon-scopes.json` + parsed findings. Use stable sorts with a total tie-break (`SourceID`).
- **Source-ID trace preserved:** a merged finding keeps its first contributor's `SourceID` and `EvidenceRef`; every contributor stays listed in `Sources` with its own `SourceID` and `EvidenceRef`. Report AI still may only return source IDs from its input chunk (the dynamic `allowed` map). Do NOT add a static whitelist.
- **Merge rule (spec §8):** collapse only findings with the *same single well-formed CVE* (`^CVE-\d{4}-\d{4,}$`, case-insensitive) on the *same scope* from *different scanners*. A scanner's own repeated reports stay separate. Merging never lowers severity or CVSS.
- **Backward compatibility:** a run with empty `Scope` folds to `scanner.HostScope(run.Target).Key()` (the Increment-1 rule in `indexTerminal`). New JSON fields are `omitempty`, or `json:"-"` where they are not persisted. Schema < 2 PDF output is unchanged.
- **Mandatory gate every task:** `gofmt -l` on touched files (internal/agent/hooks*.go has PRE-EXISTING drift and is out of scope), `CGO_ENABLED=0 go vet` and `CGO_ENABLED=0 go test` on touched packages must be clean before a task is done.

---

## File Structure

- `internal/scanner/merge.go` (Create): `FindingSource`, `singleCVE`, `severityRank`, `mergeCrossScanner`.
- `internal/scanner/merge_test.go` (Create): merge unit tests + ParseRuns scope/merge wiring test.
- `internal/scanner/parse.go`: `Finding.Scope` + `Finding.Sources`; `ParseRuns` stamps scope and calls the merge.
- `internal/scanner/classify.go`: `EffectiveTracks`. `internal/scanner/recon.go`: `LoadReconScopes`. `internal/scanner/pipeline.go`: use `EffectiveTracks`.
- `internal/scanner/classify_test.go`, `recon_test.go`: tests for the two exports.
- `internal/web/report_scopes.go` (Create): `reportScope`, `reportScopeRun`, `reportReconSummary`, `buildReportScopes`, `summarizeReportRecon`, `orderReportFindings`.
- `internal/web/report_scopes_test.go` (Create).
- `internal/web/report_ai.go`: manifest `Scopes`/`Recon`; `reportFinding.Scope`/`Sources`; propagation; ordering; `reportScanners`, `reportEvidenceRefs`.
- `internal/web/server.go`: `VulnSummary.Scope`, `ScanRecord.ReportScopes` (`json:"-"`).
- `internal/web/report_coverage.go` (Create): `reportScopeLabel`, `scopeCoverageLines`, `reconSummaryLine`, `drawScanCoverage`.
- `internal/web/report_coverage_test.go` (Create).
- `internal/web/report.go`: call `drawScanCoverage`; scope group rows in the summary table; SCOPE section in details.
- `internal/web/report_ai_test.go`: end-to-end grouped/merged report test.
- `README.md`: execution model, scanner inputs, selection wording, env vars, persistence/migration note.

---

### Task 1: Finding scope + cross-scanner CVE merge

**Files:**
- Create: `internal/scanner/merge.go`, `internal/scanner/merge_test.go`
- Modify: `internal/scanner/parse.go` (Finding struct lines 17-30; `ParseRuns` lines 32-50)

**Interfaces:**
- Produces: `Finding.Scope string` (`json:"scope,omitempty"`), `Finding.Sources []FindingSource` (`json:"sources,omitempty"`, set only on merged findings, listing every contributor with the primary first), and `type FindingSource struct{ Scanner, SourceID, Endpoint, EvidenceRef string }`. Tasks 3–4 consume these.

- [ ] **Step 1: Write the failing tests.** Create `internal/scanner/merge_test.go`:

```go
package scanner

import "testing"

func TestMergeCrossScannerCollapsesSameCVEOnSameScope(t *testing.T) {
	in := []Finding{
		{SourceID: "openvas:r1", Scanner: "openvas", Severity: "medium", CVSS: 5.0, CVE: "CVE-2021-41773", Scope: "host:a", Endpoint: "443/tcp", EvidenceRef: "ov.xml#openvas:r1"},
		{SourceID: "nuclei:CVE-2021-41773:https://a/", Scanner: "nuclei", Severity: "critical", CVSS: 9.8, CVE: "cve-2021-41773", CWE: "CWE-22", Scope: "host:a", Endpoint: "https://a/", EvidenceRef: "n.jsonl#nuclei:CVE-2021-41773:https://a/"},
	}
	out := mergeCrossScanner(in)
	if len(out) != 1 {
		t.Fatalf("want 1 merged finding, got %d: %#v", len(out), out)
	}
	m := out[0]
	if m.SourceID != "openvas:r1" || m.Scanner != "openvas" || m.EvidenceRef != "ov.xml#openvas:r1" {
		t.Fatalf("primary must stay the first contributor, got %#v", m)
	}
	if m.Severity != "critical" || m.CVSS != 9.8 || m.CWE != "CWE-22" {
		t.Fatalf("merge must raise severity/CVSS and fill CWE, got sev=%s cvss=%v cwe=%s", m.Severity, m.CVSS, m.CWE)
	}
	if len(m.Sources) != 2 || m.Sources[0].Scanner != "openvas" || m.Sources[1].Scanner != "nuclei" || m.Sources[1].Endpoint != "https://a/" || m.Sources[1].EvidenceRef == "" {
		t.Fatalf("sources = %#v", m.Sources)
	}
}

func TestMergeCrossScannerLeavesDistinctFindingsAlone(t *testing.T) {
	cases := map[string][]Finding{
		"different scope": {
			{SourceID: "openvas:r1", Scanner: "openvas", CVE: "CVE-2021-41773", Scope: "host:a"},
			{SourceID: "nuclei:x", Scanner: "nuclei", CVE: "CVE-2021-41773", Scope: "host:b"},
		},
		"no CVE": {
			{SourceID: "zap:1", Scanner: "zap", Scope: "host:a"},
			{SourceID: "nuclei:y", Scanner: "nuclei", Scope: "host:a"},
		},
		"same scanner twice": {
			{SourceID: "trivy:CVE-2023-1111:go.sum", Scanner: "trivy", CVE: "CVE-2023-1111", Scope: "source:main"},
			{SourceID: "trivy:CVE-2023-1111:web/package-lock.json", Scanner: "trivy", CVE: "CVE-2023-1111", Scope: "source:main"},
		},
		"malformed CVE": {
			{SourceID: "openvas:r1", Scanner: "openvas", CVE: "CVE-2021-41773, CVE-2021-42013", Scope: "host:a"},
			{SourceID: "nuclei:z", Scanner: "nuclei", CVE: "CVE-2021-41773, CVE-2021-42013", Scope: "host:a"},
		},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			out := mergeCrossScanner(in)
			if len(out) != 2 || len(out[0].Sources) != 0 || len(out[1].Sources) != 0 {
				t.Fatalf("expected both findings untouched, got %#v", out)
			}
		})
	}
}

func TestParseRunsStampsScopeAndMerges(t *testing.T) {
	nuclei := writeFixture(t, "nuclei.jsonl", `{"template-id":"CVE-2021-41773","matched-at":"https://a.test/cgi-bin/","host":"a.test","info":{"name":"Apache Path Traversal","severity":"critical","classification":{"cve-id":["cve-2021-41773"],"cvss-score":9.8}}}`+"\n")
	openvas := writeFixture(t, "report.xml", `<get_reports_response><report><results><result id="r1"><name>Apache Path Traversal</name><host>a.test</host><port>443/tcp</port><severity>7.5</severity><nvt oid="1.3.6"><cve>CVE-2021-41773</cve></nvt></result></results></report></get_reports_response>`)
	legacy := writeFixture(t, "legacy.jsonl", `{"template-id":"hsts","matched-at":"https://b.test","host":"b.test","info":{"name":"Missing HSTS","severity":"info"}}`+"\n")
	findings, errs := ParseRuns([]Run{
		{Scanner: "nuclei", Scope: "host:a.test", Target: "a.test", Status: "completed", ArtifactPath: nuclei},
		{Scanner: "openvas", Scope: "host:a.test", Target: "a.test", Status: "completed", ArtifactPath: openvas},
		{Scanner: "nuclei", Target: "b.test", Status: "completed", ArtifactPath: legacy}, // pre-scope record
	})
	if len(errs) != 0 {
		t.Fatalf("errs = %v", errs)
	}
	if len(findings) != 2 {
		t.Fatalf("want merged CVE + legacy finding, got %d: %#v", len(findings), findings)
	}
	if findings[0].Scope != "host:a.test" || len(findings[0].Sources) != 2 || findings[0].Scanner != "nuclei" {
		t.Fatalf("merged finding = %#v", findings[0])
	}
	if findings[1].Scope != "host:b.test" {
		t.Fatalf("legacy empty-scope run must fold to host:<target>, got %q", findings[1].Scope)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/scanner/ -run 'TestMergeCrossScanner|TestParseRunsStampsScopeAndMerges' -v`
Expected: build FAIL (`undefined: mergeCrossScanner`, unknown fields `Scope`/`Sources`).

- [ ] **Step 3: Add the fields to `Finding`** (internal/scanner/parse.go), after `CVSS`:

```go
	CVSS        float64 `json:"cvss,omitempty"`
	// Scope is the (scope) key of the run that produced this finding, e.g.
	// "host:api.example.com" or "source:main", so the report can group by it.
	Scope string `json:"scope,omitempty"`
	// Sources is set only when cross-scanner merge collapsed several scanners'
	// reports of one CVE on one scope into this finding; it lists every
	// contributor, this finding's own report first.
	Sources []FindingSource `json:"sources,omitempty"`
```

- [ ] **Step 4: Create `internal/scanner/merge.go`**

```go
package scanner

import (
	"regexp"
	"slices"
	"strings"
)

// FindingSource is one scanner's report of a finding that cross-scanner merge
// collapsed into a single record. It keeps every contributor traceable to its
// own native evidence.
type FindingSource struct {
	Scanner     string `json:"scanner"`
	SourceID    string `json:"source_id"`
	Endpoint    string `json:"endpoint,omitempty"`
	EvidenceRef string `json:"evidence_reference"`
}

var singleCVEPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// singleCVE returns s upper-cased when it is exactly one well-formed CVE ID, and
// "" otherwise, so lists and non-CVE identifiers never drive a merge.
func singleCVE(s string) string {
	c := strings.ToUpper(strings.TrimSpace(s))
	if singleCVEPattern.MatchString(c) {
		return c
	}
	return ""
}

func severityRank(s string) int {
	switch severity(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func sourceOf(f Finding) FindingSource {
	return FindingSource{Scanner: f.Scanner, SourceID: f.SourceID, Endpoint: f.Endpoint, EvidenceRef: f.EvidenceRef}
}

// mergeCrossScanner collapses findings that report the same CVE on the same
// scope from different scanners (e.g. openvas and nuclei both flagging one CVE
// on one host) into one finding that lists every source. The first-seen
// contributor stays the primary record, keeping its SourceID and EvidenceRef, so
// the report's source-ID trace is unchanged. Severity and CVSS are raised to the
// highest any contributor reported, so a merge never downgrades a finding. A
// scanner's own repeated reports (e.g. trivy flagging one CVE in two lockfiles)
// stay separate. Output keeps first-seen order.
func mergeCrossScanner(in []Finding) []Finding {
	primary := map[string]int{} // scope\x00CVE -> index in out
	out := make([]Finding, 0, len(in))
	for _, f := range in {
		cve := singleCVE(f.CVE)
		if cve == "" {
			out = append(out, f)
			continue
		}
		key := f.Scope + "\x00" + cve
		i, ok := primary[key]
		if !ok {
			primary[key] = len(out)
			out = append(out, f)
			continue
		}
		m := &out[i]
		if m.Scanner == f.Scanner || slices.ContainsFunc(m.Sources, func(s FindingSource) bool { return s.Scanner == f.Scanner }) {
			out = append(out, f)
			continue
		}
		if len(m.Sources) == 0 {
			m.Sources = []FindingSource{sourceOf(*m)}
		}
		m.Sources = append(m.Sources, sourceOf(f))
		if severityRank(f.Severity) > severityRank(m.Severity) {
			m.Severity = f.Severity
		}
		if f.CVSS > m.CVSS {
			m.CVSS = f.CVSS
		}
		if m.CWE == "" {
			m.CWE = f.CWE
		}
	}
	return out
}
```

- [ ] **Step 5: Wire into `ParseRuns`** (internal/scanner/parse.go). Replace the body's loop and dedup lines with:

```go
	for _, run := range runs {
		if run.Status != "completed" || run.ArtifactPath == "" {
			continue
		}
		parsed, err := ParseRun(run)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", run.Scanner, err))
		}
		// A pre-scope (Increment-1) run folds to the implicit host scope, the same
		// rule indexTerminal applies on resume.
		scope := run.Scope
		if scope == "" {
			scope = HostScope(run.Target).Key()
		}
		for i := range parsed {
			parsed[i].EvidenceRef = run.ArtifactPath + "#" + parsed[i].SourceID
			parsed[i].Scope = scope
		}
		findings = append(findings, parsed...)
	}
	findings = mergeCrossScanner(dedupFindings(findings))
	return findings, errs
```

- [ ] **Step 6: Run the new tests, then the whole package**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/scanner/ -run 'TestMergeCrossScanner|TestParseRunsStampsScopeAndMerges' -v && CGO_ENABLED=0 go test ./internal/scanner/...`
Expected: PASS. If an existing test compares whole `Finding` structs from `ParseRuns`, add the now-stamped `Scope` to its expectation instead of weakening the assertion.

- [ ] **Step 7: Gate + commit**

```bash
cd /Users/acho/Desktop/cyber/xalgorix && gofmt -l internal/scanner/ && CGO_ENABLED=0 go vet ./internal/scanner/... && CGO_ENABLED=0 go test ./internal/scanner/... ./internal/web/...
git add internal/scanner/merge.go internal/scanner/merge_test.go internal/scanner/parse.go
git commit -m "feat(scanner): stamp findings with scope and merge cross-scanner CVEs"
```

---

### Task 2: Export effective tracks and persisted recon scopes

**Files:**
- Modify: `internal/scanner/classify.go`, `internal/scanner/recon.go` (beside `loadReconScopes`, ~line 310), `internal/scanner/pipeline.go` (host branch of the scan loop, ~lines 225-231)
- Test: `internal/scanner/classify_test.go`, `internal/scanner/recon_test.go`

**Interfaces:**
- Produces: `func EffectiveTracks(ev HostEvidence) []Track` and `func LoadReconScopes(scanDir string) ([]Scope, bool)`. Task 3 consumes both. The pipeline and the report must share one fail-open rule, so the report never labels a host differently from how it was scanned.

- [ ] **Step 1: Write failing tests.** Append to `internal/scanner/classify_test.go`:

```go
func TestEffectiveTracksFailsOpen(t *testing.T) {
	if got := EffectiveTracks(HostEvidence{}); !slices.Equal(got, []Track{TrackWeb, TrackServer}) {
		t.Fatalf("no evidence must fail open to both tracks, got %v", got)
	}
	ev := HostEvidence{OpenPorts: []Port{{Number: 22, Protocol: "tcp", Service: "ssh"}}}
	if got := EffectiveTracks(ev); !slices.Equal(got, []Track{TrackServer}) {
		t.Fatalf("classified evidence must pass through, got %v", got)
	}
}
```

(Add `"slices"` to the file's imports if it is not already there.) Append to `internal/scanner/recon_test.go`:

```go
func TestLoadReconScopesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if _, ok := LoadReconScopes(dir); ok {
		t.Fatal("missing file must report ok=false")
	}
	want := []Scope{{ID: "host:a.test", Kind: ScopeHost, Target: "a.test", Evidence: HostEvidence{LiveURLs: []string{"https://a.test"}, OpenPorts: []Port{{Number: 443, Protocol: "tcp", Service: "https"}}}}}
	saveReconScopes(dir, want)
	got, ok := LoadReconScopes(dir)
	if !ok || len(got) != 1 || got[0].ID != "host:a.test" || len(got[0].Evidence.OpenPorts) != 1 || got[0].Evidence.OpenPorts[0].Number != 443 {
		t.Fatalf("round trip = %#v, ok=%v", got, ok)
	}
}
```

- [ ] **Step 2: Verify they fail**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/scanner/ -run 'TestEffectiveTracksFailsOpen|TestLoadReconScopesRoundTrip' -v`
Expected: build FAIL (`undefined: EffectiveTracks`, `undefined: LoadReconScopes`).

- [ ] **Step 3: Implement.** Append to `internal/scanner/classify.go`:

```go
// EffectiveTracks is the track set a host scope is actually scanned on: the
// classifier's result, failing open to both tracks when recon produced no
// evidence (recon degraded/absent, or the single-host degrade path) so a
// reachable host is never silently under-scanned. The report uses the same rule
// so its track labels always match what ran.
func EffectiveTracks(ev HostEvidence) []Track {
	if tracks := Classify(ev); len(tracks) > 0 {
		return tracks
	}
	return []Track{TrackWeb, TrackServer}
}
```

Add after `loadReconScopes` in `internal/scanner/recon.go`:

```go
// LoadReconScopes returns the discovered host-scope set (with per-host evidence)
// persisted under scanDir by recon, for report generation. ok is false when the
// file is absent or empty, e.g. a single-host scan with no recon evidence.
func LoadReconScopes(scanDir string) ([]Scope, bool) { return loadReconScopes(scanDir) }
```

In `internal/scanner/pipeline.go`, replace the host-branch block

```go
			sc.Tracks = Classify(sc.Evidence)
			if len(sc.Tracks) == 0 {
				// Fail open: ...
				sc.Tracks = []Track{TrackWeb, TrackServer}
			}
```

with

```go
			// Fail open to both tracks when recon produced no evidence; see
			// EffectiveTracks.
			sc.Tracks = EffectiveTracks(sc.Evidence)
```

- [ ] **Step 4: Verify pass + package suite**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/scanner/...`
Expected: PASS (the refactor does not change behavior, so existing pipeline tests stay green).

- [ ] **Step 5: Gate + commit**

```bash
cd /Users/acho/Desktop/cyber/xalgorix && gofmt -l internal/scanner/ && CGO_ENABLED=0 go vet ./internal/scanner/...
git add internal/scanner/classify.go internal/scanner/classify_test.go internal/scanner/recon.go internal/scanner/recon_test.go internal/scanner/pipeline.go
git commit -m "refactor(scanner): export EffectiveTracks and LoadReconScopes for the report"
```

---

### Task 3: Scope-aware report manifest

**Files:**
- Create: `internal/web/report_scopes.go`, `internal/web/report_scopes_test.go`
- Modify: `internal/web/report_ai.go`, `internal/web/server.go` (`VulnSummary` ~line 376, `ScanRecord` ~line 413), `internal/web/report_ai_test.go`

**Interfaces:**
- Consumes: `scanner.Finding.Scope/Sources`, `scanner.FindingSource` (Task 1); `scanner.EffectiveTracks`, `scanner.LoadReconScopes` (Task 2).
- Produces for Task 4: `type reportScope struct{ ID, Kind, Target string; Tracks, OpenPorts, Services, LiveURLs []string; Runs []reportScopeRun }`, `type reportScopeRun struct{ Scanner, Status, Reason string }`, `type reportReconSummary struct{ Hosts, OpenPorts int; Services []string }`, `func summarizeReportRecon([]reportScope) reportReconSummary`, `ScanRecord.ReportScopes []reportScope` (`json:"-"`), `VulnSummary.Scope string`. Kind values are `string(scanner.ScopeHost)` = `"host"` and `string(scanner.ScopeSource)` = `"source"`.

- [ ] **Step 1: Write failing unit tests.** Create `internal/web/report_scopes_test.go`:

```go
package web

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

func writeReconScopes(t *testing.T, scanDir string, scopes []scanner.Scope) {
	t.Helper()
	data, err := json.Marshal(scopes)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(scanDir, "scanner-output", "recon-scopes.json")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestBuildReportScopes(t *testing.T) {
	dir := t.TempDir()
	writeReconScopes(t, dir, []scanner.Scope{
		{ID: "host:a.test", Kind: scanner.ScopeHost, Target: "a.test", Evidence: scanner.HostEvidence{OpenPorts: []scanner.Port{{Number: 443, Protocol: "tcp", Service: "https", Product: "nginx"}, {Number: 22, Protocol: "tcp", Service: "ssh"}}}},
	})
	runs := []scanner.Run{
		{Scanner: "subfinder", Scope: "recon:a.test", Status: "completed"},
		{Scanner: "trivy", Scope: "source:main", Target: "", Status: "not_applicable", Reason: "no source"},
		{Scanner: "nuclei", Scope: "host:a.test", Target: "a.test", Status: "completed"},
		{Scanner: "vuls", Scope: "host:a.test", Target: "a.test", Status: "skipped", Reason: "not selected for this scan"},
		{Scanner: "nuclei", Target: "legacy.test", Status: "completed"}, // pre-scope record
	}
	got := buildReportScopes(dir, runs)
	ids := make([]string, len(got))
	for i, sc := range got {
		ids[i] = sc.ID
	}
	if !slices.Equal(ids, []string{"host:a.test", "host:legacy.test", "source:main"}) {
		t.Fatalf("scope order = %v (recon excluded, hosts first-seen, source last)", ids)
	}
	a := got[0]
	if a.Kind != "host" || !slices.Equal(a.Tracks, []string{"web", "server"}) || !slices.Equal(a.OpenPorts, []string{"443/tcp https nginx", "22/tcp ssh"}) || !slices.Equal(a.Services, []string{"https", "ssh"}) {
		t.Fatalf("host scope = %#v", a)
	}
	if len(a.Runs) != 2 || a.Runs[1] != (reportScopeRun{Scanner: "vuls", Status: "skipped", Reason: "not selected for this scan"}) {
		t.Fatalf("host runs = %#v", a.Runs)
	}
	if legacy := got[1]; !slices.Equal(legacy.Tracks, []string{"web", "server"}) || legacy.Target != "legacy.test" {
		t.Fatalf("host with no evidence must fail open to both tracks, got %#v", legacy)
	}
	if src := got[2]; src.Kind != "source" || len(src.Tracks) != 0 || len(src.Runs) != 1 {
		t.Fatalf("source scope = %#v", src)
	}
	sum := summarizeReportRecon(got)
	if sum.Hosts != 2 || sum.OpenPorts != 2 || !slices.Equal(sum.Services, []string{"https", "ssh"}) {
		t.Fatalf("recon summary = %#v", sum)
	}
}

func TestOrderReportFindings(t *testing.T) {
	scopes := []reportScope{{ID: "host:a"}, {ID: "host:b"}, {ID: "source:main"}}
	in := []reportFinding{
		{SourceID: "trivy:1", Scope: "source:main", Severity: "critical"},
		{SourceID: "nuclei:z", Scope: "host:b", Severity: "low"},
		{SourceID: "nuclei:b", Scope: "host:a", Severity: "medium"},
		{SourceID: "nuclei:a", Scope: "host:a", Severity: "medium"},
		{SourceID: "zap:1", Scope: "host:a", Severity: "high"},
		{SourceID: "x:1", Scope: "unknown", Severity: "critical"},
	}
	orderReportFindings(in, scopes)
	var got []string
	for _, f := range in {
		got = append(got, f.SourceID)
	}
	want := []string{"zap:1", "nuclei:a", "nuclei:b", "nuclei:z", "trivy:1", "x:1"}
	if !slices.Equal(got, want) {
		t.Fatalf("order = %v, want %v (scope, then severity desc, then source id; unknown scope last)", got, want)
	}
}

func TestReportFindingsToVulnsCarriesScopeAndSources(t *testing.T) {
	in := []reportFinding{{
		SourceID: "nuclei:x", Scanner: "nuclei", Title: "t", Severity: "critical", Scope: "host:a", Evidence: "ev", EvidenceRef: "n.jsonl#nuclei:x",
		Sources: []scanner.FindingSource{{Scanner: "nuclei", SourceID: "nuclei:x", EvidenceRef: "n.jsonl#nuclei:x"}, {Scanner: "openvas", SourceID: "openvas:r1", EvidenceRef: "ov.xml#openvas:r1"}},
	}}
	v := reportFindingsToVulns(in)[0]
	if v.Scope != "host:a" || v.VerificationMethod != "nuclei, openvas" || !slices.Contains(v.Tags, "openvas") {
		t.Fatalf("vuln = %#v", v)
	}
	want := "ev\nEvidence reference (nuclei): n.jsonl#nuclei:x\nEvidence reference (openvas): ov.xml#openvas:r1"
	if v.TechnicalAnalysis != want {
		t.Fatalf("technical analysis = %q", v.TechnicalAnalysis)
	}
	single := reportFindingsToVulns([]reportFinding{{SourceID: "zap:1", Scanner: "zap", Evidence: "e", EvidenceRef: "z.json#zap:1"}})[0]
	if single.TechnicalAnalysis != "e\nEvidence reference: z.json#zap:1" || single.VerificationMethod != "zap" {
		t.Fatalf("unmerged vuln must keep the existing shape, got %#v", single)
	}
}
```

- [ ] **Step 2: Verify they fail**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/web/ -run 'TestBuildReportScopes|TestOrderReportFindings|TestReportFindingsToVulnsCarriesScopeAndSources' -v`
Expected: build FAIL (`undefined: buildReportScopes`, unknown fields).

- [ ] **Step 3: Create `internal/web/report_scopes.go`**

```go
package web

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

// reportScope is one host or source block of a scanner report: what it is, the
// classifier's tracks for it, what recon found on it, and the terminal status
// every tool recorded there, so the report accounts for every scope x tool.
type reportScope struct {
	ID        string           `json:"id"`
	Kind      string           `json:"kind"`
	Target    string           `json:"target,omitempty"`
	Tracks    []string         `json:"tracks,omitempty"`
	OpenPorts []string         `json:"open_ports,omitempty"`
	Services  []string         `json:"services,omitempty"`
	LiveURLs  []string         `json:"live_urls,omitempty"`
	Runs      []reportScopeRun `json:"runs"`
}

type reportScopeRun struct {
	Scanner string `json:"scanner"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
}

// reportReconSummary is the scan-wide recon rollup shown above the per-scope
// coverage blocks.
type reportReconSummary struct {
	Hosts     int      `json:"hosts"`
	OpenPorts int      `json:"open_ports"`
	Services  []string `json:"services,omitempty"`
}

// reportScopeID is the scope a run belongs to. A pre-scope run folds to the
// implicit host scope, matching the scanner's resume rule.
func reportScopeID(run scanner.Run) string {
	if run.Scope != "" {
		return run.Scope
	}
	return scanner.HostScope(run.Target).Key()
}

// buildReportScopes derives the report's scope list from the scan's runs and the
// recon-scopes.json persisted under scanDir. Recon-phase runs are excluded (they
// are summarized, not scoped). Host scopes keep first-seen run order; the
// source scope always comes last. Tracks use scanner.EffectiveTracks, the same
// fail-open rule the pipeline scanned with.
func buildReportScopes(scanDir string, runs []scanner.Run) []reportScope {
	evidence := map[string]scanner.HostEvidence{}
	if persisted, ok := scanner.LoadReconScopes(scanDir); ok {
		for _, sc := range persisted {
			evidence[sc.ID] = sc.Evidence
		}
	}
	var out []reportScope
	index := map[string]int{}
	for _, run := range runs {
		id := reportScopeID(run)
		if strings.HasPrefix(id, "recon:") {
			continue
		}
		i, ok := index[id]
		if !ok {
			rs := reportScope{ID: id, Kind: string(scanner.ScopeHost), Target: run.Target}
			if strings.HasPrefix(id, "source:") {
				rs.Kind = string(scanner.ScopeSource)
			} else {
				ev := evidence[id]
				for _, t := range scanner.EffectiveTracks(ev) {
					rs.Tracks = append(rs.Tracks, string(t))
				}
				for _, p := range ev.OpenPorts {
					rs.OpenPorts = append(rs.OpenPorts, formatReportPort(p))
					if svc := strings.TrimSpace(p.Service); svc != "" && !slices.Contains(rs.Services, svc) {
						rs.Services = append(rs.Services, svc)
					}
				}
				sort.Strings(rs.Services)
				rs.LiveURLs = append([]string(nil), ev.LiveURLs...)
			}
			i = len(out)
			index[id] = i
			out = append(out, rs)
		}
		if out[i].Target == "" {
			out[i].Target = run.Target
		}
		out[i].Runs = append(out[i].Runs, reportScopeRun{Scanner: run.Scanner, Status: run.Status, Reason: run.Reason})
	}
	sort.SliceStable(out, func(a, b int) bool {
		return out[a].Kind != string(scanner.ScopeSource) && out[b].Kind == string(scanner.ScopeSource)
	})
	return out
}

func formatReportPort(p scanner.Port) string {
	s := fmt.Sprintf("%d/%s", p.Number, firstNonBlank(p.Protocol, "tcp"))
	if svc := strings.Join(strings.Fields(p.Service+" "+p.Product), " "); svc != "" {
		s += " " + svc
	}
	return s
}

// summarizeReportRecon rolls host scopes up into hosts discovered, open ports,
// and the sorted distinct detected services.
func summarizeReportRecon(scopes []reportScope) reportReconSummary {
	var sum reportReconSummary
	for _, sc := range scopes {
		if sc.Kind != string(scanner.ScopeHost) {
			continue
		}
		sum.Hosts++
		sum.OpenPorts += len(sc.OpenPorts)
		for _, svc := range sc.Services {
			if !slices.Contains(sum.Services, svc) {
				sum.Services = append(sum.Services, svc)
			}
		}
	}
	sort.Strings(sum.Services)
	return sum
}

// orderReportFindings sorts findings in place by scope (report scope order,
// unknown scopes last), then severity (highest first), then source ID, a total
// order so the report is deterministic.
func orderReportFindings(findings []reportFinding, scopes []reportScope) {
	rank := make(map[string]int, len(scopes))
	for i, sc := range scopes {
		rank[sc.ID] = i
	}
	pos := func(id string) int {
		if r, ok := rank[id]; ok {
			return r
		}
		return len(scopes)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if pa, pb := pos(a.Scope), pos(b.Scope); pa != pb {
			return pa < pb
		}
		if ra, rb := severityRankValue(a.Severity), severityRankValue(b.Severity); ra != rb {
			return ra > rb
		}
		return a.SourceID < b.SourceID
	})
}
```

- [ ] **Step 4: Add the record fields** (internal/web/server.go). In `VulnSummary`, after `Target`:

```go
	Target             string   `json:"target,omitempty"`
	Scope              string   `json:"scope,omitempty"` // scanner reports: host:<h> or source:main
```

In `ScanRecord`, after `ReportGeneratedAt`:

```go
	ReportGeneratedAt        string           `json:"report_generated_at,omitempty"`
	// ReportScopes feeds the scanner report's coverage section and scope grouping.
	// It is derived at report time from ScannerRuns + recon-scopes.json and is
	// never persisted.
	ReportScopes []reportScope `json:"-"`
```

- [ ] **Step 5: Thread scope through `report_ai.go`**

(a) Add to `reportManifest`, after `ParseErrors`:

```go
	Scopes        []reportScope       `json:"scopes,omitempty"`
	Recon         *reportReconSummary `json:"recon,omitempty"`
```

(b) Add to `reportFinding`, after `CVSS`:

```go
	Scope   string                  `json:"scope,omitempty"`
	Sources []scanner.FindingSource `json:"sources,omitempty"`
```

(c) In `fallbackReportFindings`, add `Scope: f.Scope, Sources: f.Sources` to the struct literal.

(d) In `aiReportFindings`, next to `f.EvidenceRef = src.EvidenceRef`, add (the AI must not be able to move a finding between scopes or drop its sources):

```go
			f.Scope = src.Scope
			f.Sources = src.Sources
```

(e) In `generateScannerReport`, right after `manifest := reportManifest{...}` is built:

```go
	scopes := buildReportScopes(scanDir, rec.ScannerRuns)
	recon := summarizeReportRecon(scopes)
	manifest.Scopes, manifest.Recon = scopes, &recon
```

then immediately before `data, _ := json.MarshalIndent(manifest, "", "  ")`:

```go
	orderReportFindings(manifest.Findings, scopes)
```

and after `copyRec.Vulns = reportFindingsToVulns(manifest.Findings)`:

```go
	copyRec.ReportScopes = scopes
```

(f) Replace `reportFindingsToVulns` and add its two helpers (add `"slices"` to the imports):

```go
func reportFindingsToVulns(in []reportFinding) []VulnSummary {
	out := make([]VulnSummary, 0, len(in))
	for i, f := range in {
		scanners := reportScanners(f)
		tags := append([]string{"scanner-reported"}, scanners...)
		out = append(out, VulnSummary{ID: fmt.Sprintf("SCAN-%04d", i+1), Title: f.Title, Severity: f.Severity, Target: f.Target, Scope: f.Scope, Endpoint: f.Endpoint, CVSS: f.CVSS, Description: f.Explanation, Impact: f.Impact, CVE: f.CVE, CWE: f.CWE, TechnicalAnalysis: f.Evidence + "\n" + reportEvidenceRefs(f), Remediation: f.Remediation, ExploitationProof: "Scanner-reported evidence; no independent exploitation was performed.", VerificationMethod: strings.Join(scanners, ", "), Verified: false, Tags: tags})
	}
	return out
}

// reportScanners lists the distinct scanners that reported f, primary first.
func reportScanners(f reportFinding) []string {
	if len(f.Sources) == 0 {
		return []string{f.Scanner}
	}
	var out []string
	for _, s := range f.Sources {
		if !slices.Contains(out, s.Scanner) {
			out = append(out, s.Scanner)
		}
	}
	return out
}

// reportEvidenceRefs renders f's evidence trace: the single reference for an
// unmerged finding (unchanged shape), or one labelled line per source.
func reportEvidenceRefs(f reportFinding) string {
	if len(f.Sources) == 0 {
		return "Evidence reference: " + f.EvidenceRef
	}
	lines := make([]string, 0, len(f.Sources))
	for _, s := range f.Sources {
		lines = append(lines, fmt.Sprintf("Evidence reference (%s): %s", s.Scanner, s.EvidenceRef))
	}
	return strings.Join(lines, "\n")
}
```

- [ ] **Step 6: Add the end-to-end test.** Append to `internal/web/report_ai_test.go`:

```go
func TestScannerReportGroupsByScopeAndMergesCVE(t *testing.T) {
	s := newTestServer(t, nil)
	s.cfg.LLM = ""
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	nucleiA := write("nuclei-a.jsonl", `{"template-id":"CVE-2021-41773","matched-at":"https://a.example.test/cgi-bin/","host":"a.example.test","info":{"name":"Apache Path Traversal","severity":"critical","classification":{"cve-id":["cve-2021-41773"],"cvss-score":9.8}}}`+"\n")
	openvasA := write("openvas-a.xml", `<get_reports_response><report><results><result id="r1"><name>Apache Path Traversal</name><host>a.example.test</host><port>443/tcp</port><severity>7.5</severity><nvt oid="1.3.6"><cve>CVE-2021-41773</cve></nvt></result></results></report></get_reports_response>`)
	nucleiB := write("nuclei-b.jsonl", `{"template-id":"missing-hsts","matched-at":"https://b.example.test","host":"b.example.test","info":{"name":"Missing HSTS","severity":"info"}}`+"\n")
	trivySrc := write("trivy.json", `{"Results":[{"Target":"go.sum","Vulnerabilities":[{"VulnerabilityID":"CVE-2023-1111","PkgName":"lib","Severity":"HIGH"}]}]}`)
	writeReconScopes(t, dir, []scanner.Scope{
		{ID: "host:a.example.test", Kind: scanner.ScopeHost, Target: "a.example.test", Evidence: scanner.HostEvidence{OpenPorts: []scanner.Port{{Number: 443, Protocol: "tcp", Service: "https"}, {Number: 22, Protocol: "tcp", Service: "ssh"}}}},
		{ID: "host:b.example.test", Kind: scanner.ScopeHost, Target: "b.example.test", Evidence: scanner.HostEvidence{LiveURLs: []string{"https://b.example.test"}}},
	})
	runs := []scanner.Run{
		{Scanner: "subfinder", Scope: "recon:example.test", Target: "example.test", Status: "completed"},
		{Scanner: "nuclei", Scope: "host:a.example.test", Target: "a.example.test", Status: "completed", ArtifactPath: nucleiA},
		{Scanner: "openvas", Scope: "host:a.example.test", Target: "a.example.test", Status: "completed", ArtifactPath: openvasA},
		{Scanner: "trivy", Scope: "source:main", Target: filepath.Join(dir, "src"), Status: "completed", ArtifactPath: trivySrc},
		{Scanner: "nuclei", Scope: "host:b.example.test", Target: "b.example.test", Status: "completed", ArtifactPath: nucleiB},
	}
	for i := range runs {
		runs[i].Checksum = scanner.CalculateChecksum(runs[i])
	}
	rec := &ScanRecord{SchemaVersion: scanner.SchemaVersion, ID: "scope-report", Target: "example.test", Status: "finished", ScannerRuns: runs, Events: []WSEvent{}, Vulns: []VulnSummary{}}
	if path := s.generateScannerReport(rec, dir, ""); path == "" {
		t.Fatal("report generation failed")
	}
	data, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest reportManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	var scopeIDs []string
	for _, sc := range manifest.Scopes {
		scopeIDs = append(scopeIDs, sc.ID)
	}
	if want := []string{"host:a.example.test", "host:b.example.test", "source:main"}; !slices.Equal(scopeIDs, want) {
		t.Fatalf("scopes = %v, want %v", scopeIDs, want)
	}
	if got := manifest.Scopes[0].Tracks; !slices.Equal(got, []string{"web", "server"}) {
		t.Fatalf("host a tracks = %v", got)
	}
	if got := manifest.Scopes[1].Tracks; !slices.Equal(got, []string{"web"}) {
		t.Fatalf("host b tracks = %v", got)
	}
	if manifest.Recon == nil || manifest.Recon.Hosts != 2 || manifest.Recon.OpenPorts != 2 {
		t.Fatalf("recon = %#v", manifest.Recon)
	}
	if len(manifest.Findings) != 3 {
		t.Fatalf("want 3 findings (CVE merged), got %d: %#v", len(manifest.Findings), manifest.Findings)
	}
	var order []string
	for _, f := range manifest.Findings {
		order = append(order, f.Scope)
	}
	if want := []string{"host:a.example.test", "host:b.example.test", "source:main"}; !slices.Equal(order, want) {
		t.Fatalf("finding scope order = %v, want %v", order, want)
	}
	if merged := manifest.Findings[0]; len(merged.Sources) != 2 || merged.Severity != "critical" {
		t.Fatalf("merged finding = %#v", merged)
	}
}
```

Add `"slices"` to that test file's imports.

- [ ] **Step 7: Run the tests, then the package**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/web/ -run 'TestBuildReportScopes|TestOrderReportFindings|TestReportFindingsToVulnsCarriesScopeAndSources|TestScannerReport|TestGenerateCLIReport|TestFallbackFindingTraceIsPreserved' -v && CGO_ENABLED=0 go test ./internal/web/...`
Expected: PASS. `TestFallbackFindingTraceIsPreserved` must stay green unchanged, because the unmerged trace shape is identical.

- [ ] **Step 8: Gate + commit**

```bash
cd /Users/acho/Desktop/cyber/xalgorix && gofmt -l internal/web/ && CGO_ENABLED=0 go vet ./internal/web/...
git add internal/web/report_scopes.go internal/web/report_scopes_test.go internal/web/report_ai.go internal/web/report_ai_test.go internal/web/server.go
git commit -m "feat(report): group scanner findings by scope with tracks and recon summary"
```

---

### Task 4: PDF scan-coverage section and scope grouping

**Files:**
- Create: `internal/web/report_coverage.go`, `internal/web/report_coverage_test.go`
- Modify: `internal/web/report.go` (after the Reconnaissance Findings block ~line 942-999; Findings Summary row loop ~line 1114; details `sections` ~line 1338)

**Interfaces:**
- Consumes: `reportScope`, `reportScopeRun`, `reportReconSummary`, `summarizeReportRecon`, `ScanRecord.ReportScopes`, `VulnSummary.Scope` (Task 3); `reportPalette` (report.go).
- Produces: `func reportScopeLabel(reportScope) string`, `func scopeCoverageLines(reportScope) []string`, `func reconSummaryLine(reportReconSummary) string`, `func drawScanCoverage(*fpdf.Fpdf, reportPalette, reportReconSummary, []reportScope)`.

- [ ] **Step 1: Write failing tests.** Create `internal/web/report_coverage_test.go`:

```go
package web

import (
	"slices"
	"testing"
)

func TestReportScopeLabel(t *testing.T) {
	cases := []struct {
		in   reportScope
		want string
	}{
		{reportScope{ID: "host:a.test", Kind: "host", Target: "a.test", Tracks: []string{"web", "server"}}, "HOST  a.test  [web, server]"},
		{reportScope{ID: "source:main", Kind: "source", Target: "/scans/x/source/checkout"}, "SOURCE CODE  /scans/x/source/checkout"},
		{reportScope{ID: "source:main", Kind: "source"}, "SOURCE CODE  none provided"},
	}
	for _, tc := range cases {
		if got := reportScopeLabel(tc.in); got != tc.want {
			t.Errorf("reportScopeLabel(%s) = %q, want %q", tc.in.ID, got, tc.want)
		}
	}
}

func TestScopeCoverageLines(t *testing.T) {
	host := reportScope{Kind: "host", Tracks: []string{"web"}, OpenPorts: []string{"443/tcp https"}, Runs: []reportScopeRun{{Scanner: "nuclei", Status: "completed"}, {Scanner: "openvas", Status: "not_applicable", Reason: "not on the server track"}}}
	want := []string{
		"Tracks: web",
		"Open ports: 443/tcp https",
		"nuclei     completed",
		"openvas    not_applicable - not on the server track",
	}
	if got := scopeCoverageLines(host); !slices.Equal(got, want) {
		t.Fatalf("host lines = %q, want %q", got, want)
	}
	src := reportScope{Kind: "source", Runs: []reportScopeRun{{Scanner: "semgrep", Status: "not_applicable"}}}
	if got := scopeCoverageLines(src); !slices.Equal(got, []string{"semgrep    not_applicable"}) {
		t.Fatalf("source lines = %q", got)
	}
	noPorts := reportScope{Kind: "host", Tracks: []string{"web", "server"}}
	if got := scopeCoverageLines(noPorts); !slices.Equal(got, []string{"Tracks: web, server", "Open ports: none recorded"}) {
		t.Fatalf("no-port lines = %q", got)
	}
}

func TestReconSummaryLine(t *testing.T) {
	if got := reconSummaryLine(reportReconSummary{Hosts: 2, OpenPorts: 3, Services: []string{"https", "ssh"}}); got != "Recon discovered 2 host(s) with 3 open port(s). Detected services: https, ssh." {
		t.Fatalf("got %q", got)
	}
	if got := reconSummaryLine(reportReconSummary{Hosts: 1}); got != "Recon discovered 1 host(s) with 0 open port(s). Detected services: none recorded." {
		t.Fatalf("got %q", got)
	}
}
```

- [ ] **Step 2: Verify they fail**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/web/ -run 'TestReportScopeLabel|TestScopeCoverageLines|TestReconSummaryLine' -v`
Expected: build FAIL (`undefined: reportScopeLabel`).

- [ ] **Step 3: Create `internal/web/report_coverage.go`**

```go
package web

import (
	"fmt"
	"strings"

	"github.com/go-pdf/fpdf"
)

// reportScopeLabel is the one-line heading for a scope in the scanner report.
func reportScopeLabel(sc reportScope) string {
	if sc.Kind == "source" {
		return "SOURCE CODE  " + firstNonBlank(sc.Target, "none provided")
	}
	label := "HOST  " + sc.Target
	if len(sc.Tracks) > 0 {
		label += "  [" + strings.Join(sc.Tracks, ", ") + "]"
	}
	return label
}

// scopeCoverageLines lists what the classifier decided for a host (tracks, open
// ports) and the terminal status each tool recorded on the scope.
func scopeCoverageLines(sc reportScope) []string {
	var lines []string
	if sc.Kind != "source" {
		lines = append(lines, "Tracks: "+strings.Join(sc.Tracks, ", "))
		ports := "none recorded"
		if len(sc.OpenPorts) > 0 {
			ports = strings.Join(sc.OpenPorts, ", ")
		}
		lines = append(lines, "Open ports: "+ports)
	}
	for _, r := range sc.Runs {
		line := fmt.Sprintf("%-10s %s", r.Scanner, r.Status)
		if r.Reason != "" && r.Status != "completed" {
			line += " - " + r.Reason
		}
		lines = append(lines, line)
	}
	return lines
}

func reconSummaryLine(sum reportReconSummary) string {
	services := "none recorded"
	if len(sum.Services) > 0 {
		services = strings.Join(sum.Services, ", ")
	}
	return fmt.Sprintf("Recon discovered %d host(s) with %d open port(s). Detected services: %s.", sum.Hosts, sum.OpenPorts, services)
}

// drawScanCoverage renders the scanner report's "Scan Coverage" section: the
// recon rollup, then one block per scope with its tracks, ports, and every
// tool's terminal status, so the report accounts for every scope x tool.
func drawScanCoverage(pdf *fpdf.Fpdf, pal reportPalette, recon reportReconSummary, scopes []reportScope) {
	fill := func(x, y, w, h float64, c [3]int) {
		pdf.SetFillColor(c[0], c[1], c[2])
		pdf.Rect(x, y, w, h, "F")
	}
	text := func(c [3]int) { pdf.SetTextColor(c[0], c[1], c[2]) }
	newPage := func() {
		pdf.AddPage()
		fill(0, 0, 210, 297, pal.bg)
		fill(0, 0, 210, 1.5, pal.accent)
		pdf.SetY(15)
	}

	newPage()
	pdf.SetFont("Helvetica", "B", 22)
	text(pal.accent)
	pdf.CellFormat(190, 12, "Scan Coverage", "", 1, "L", false, 0, "")
	fill(10, pdf.GetY()+2, 45, 0.8, pal.accent)
	pdf.Ln(8)

	pdf.SetFont("Helvetica", "", 9)
	text(pal.fg)
	pdf.SetX(10)
	pdf.MultiCell(190, 4.5, reconSummaryLine(recon)+" Every tool records exactly one terminal status per scope; tools that do not apply to a scope are recorded not_applicable or skipped.", "", "L", false)
	pdf.Ln(4)

	for _, sc := range scopes {
		if pdf.GetY() > 240 {
			newPage()
		}
		y := pdf.GetY()
		fill(10, y, 190, 8, pal.card)
		pdf.SetXY(14, y+1)
		pdf.SetFont("Helvetica", "B", 9)
		text(pal.accent)
		pdf.CellFormat(182, 6, reportScopeLabel(sc), "", 1, "L", false, 0, "")
		pdf.Ln(1)
		pdf.SetFont("Courier", "", 7)
		for _, line := range scopeCoverageLines(sc) {
			if pdf.GetY() > 270 {
				newPage()
			}
			text(pal.fg)
			pdf.SetX(14)
			pdf.MultiCell(182, 4, line, "", "L", false)
		}
		pdf.Ln(4)
	}
}
```

- [ ] **Step 4: Call it from `generateReport`** (internal/web/report.go). Immediately after the closing `}` of the `if recon.hasData() { ... }` block (the Reconnaissance Findings section, before `// ─── BLUE TEAM TIMESTAMPS`), insert:

```go
	// ─── SCAN COVERAGE (scanner reports only) ────────────
	if len(scan.ReportScopes) > 0 {
		drawScanCoverage(pdf, palette, summarizeReportRecon(scan.ReportScopes), scan.ReportScopes)
	}
```

Check the code after the insertion point: the BLUE TEAM section starts with `pdf.Ln(10)` and an `if pdf.GetY() > 230 { pdf.AddPage() ...}` guard, so it tolerates any Y position. No other change is needed.

- [ ] **Step 5: Add scope group rows to the Findings Summary table.** In report.go, just before `// Table rows` / `for i, v := range scan.Vulns {` inside the `// ─── FINDINGS SUMMARY TABLE` block, add:

```go
		scopeLabels := make(map[string]string, len(scan.ReportScopes))
		for _, sc := range scan.ReportScopes {
			scopeLabels[sc.ID] = reportScopeLabel(sc)
		}
		prevScope := ""
```

Then, at the top of that loop body, before the existing `if pdf.GetY() > 268 {` page-break check, insert:

```go
			if len(scopeLabels) > 0 && v.Scope != prevScope {
				prevScope = v.Scope
				if pdf.GetY() > 260 {
					pdf.AddPage()
					drawRect(0, 0, 210, 297, darkBg)
					drawRect(0, 0, 210, 1.5, coral)
					pdf.SetY(15)
				}
				groupY := pdf.GetY()
				drawRect(10, groupY, 190, 6, palette.muted)
				pdf.SetXY(12, groupY)
				pdf.SetFont("Helvetica", "B", 7)
				setColor(teal)
				pdf.CellFormat(186, 6, firstNonBlank(scopeLabels[v.Scope], v.Scope, "UNSCOPED"), "", 1, "L", false, 0, "")
			}
```

- [ ] **Step 6: Add a SCOPE section to each vulnerability detail.** In the details loop, change

```go
			sections := []section{}
			if v.Endpoint != "" {
```

to

```go
			sections := []section{}
			if label, ok := scopeLabels[v.Scope]; ok {
				sections = append(sections, section{"SCOPE", label})
			}
			if v.Endpoint != "" {
```

`scopeLabels` is declared in the summary-table block, which encloses the details block (both sit inside `if len(scan.Vulns) > 0 {`). If the compiler reports it undefined, the blocks are siblings: move the `scopeLabels` construction up to just inside `if len(scan.Vulns) > 0 {`.

- [ ] **Step 7: Run tests.** The end-to-end test from Task 3 (`TestScannerReportGroupsByScopeAndMergesCVE`) now also renders the coverage section and group rows, so a PDF panic or layout error fails it.

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/web/ -run 'TestReportScopeLabel|TestScopeCoverageLines|TestReconSummaryLine|TestScannerReport|TestGenerateCLIReport' -v && CGO_ENABLED=0 go test ./internal/web/...`
Expected: PASS. Existing `generateReportAt` tests (server_test.go) pass unchanged because `ReportScopes` is empty for them.

- [ ] **Step 8: Manual PDF check (one time).** In `TestScannerReportGroupsByScopeAndMergesCVE`, temporarily replace `dir := t.TempDir()` with `dir, _ := os.MkdirTemp("", "scope-report")` and add `t.Log(path)` after generation. Then run:

```bash
cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/web/ -run TestScannerReportGroupsByScopeAndMergesCVE -v
```

Open the logged PDF and confirm three things: the Scan Coverage page is there, the Findings Summary has three scope group rows, and the merged finding shows "SCANNER-REPORTED via NUCLEI, OPENVAS". Revert the temporary edits before committing.

- [ ] **Step 9: Gate + commit**

```bash
cd /Users/acho/Desktop/cyber/xalgorix && gofmt -l internal/web/ && CGO_ENABLED=0 go vet ./internal/web/...
git add internal/web/report_coverage.go internal/web/report_coverage_test.go internal/web/report.go
git commit -m "feat(report): add scan-coverage section and scope grouping to the PDF"
```

---

### Task 5: README determinism contract and docs

**Files:**
- Modify: `README.md` (Execution model lines 5-21; Scanner inputs table ~lines 60-68; Selecting scanners ~lines 69-84; env var table ~lines 92-110; Persistence ~lines 144-148)

**Interfaces:** none (docs only). Every statement below was checked against the code as of commit 49cd633: runner tracks from the `Descriptor`s in pipeline.go/zap.go/openvas.go/vuls.go, web-port rule from classify.go `isWebPort`, env defaults from config.go lines 359-391, source resolution from source.go.

- [ ] **Step 1: Replace the `## Execution model` section** (from the heading through the paragraph ending "…deterministic fallback report.", keeping the "Findings are labelled scanner-reported…" paragraph) with:

```markdown
## Execution model

Each scan runs fixed phases:

1. **Recon** — Subfinder enumerates subdomains (skipped for a bare host or URL), httpx keeps the live hosts, and Nmap records open ports and services per host. Each live host becomes a *host scope*. A target with nothing to expand (for example `localhost:3000`) is scanned as a single host.
2. **Classify** — from recon evidence alone, each host gets the `web` track (a live HTTP(S) URL, TLS, or an open 80/443/8080/8443 or HTTP-like service) and/or the `server` track (any other open port). A host with no recon evidence is scanned on both tracks.
3. **Scan** — per host: Nuclei, OWASP ZAP, and testssl.sh on the web track; OpenVAS/Greenbone and Vuls on the server track.
4. **Source code** — once per scan, on a single *source scope*: Trivy, Semgrep, Gitleaks, and OSV-Scanner. Source comes from `--source` (a local directory, or a git repository cloned into the scan directory) or from a git-URL target. With no source, these tools record `not_applicable`.

Scanners run on a bounded worker pool (`XALGORIX_MAX_WORKERS`, default 3). The heavy tools, ZAP and OpenVAS, never run at the same time.

Every applicable tool records exactly one terminal status per scope. Every scope×tool the classifier deemed inapplicable is recorded `not_applicable` or `skipped`, so the report still accounts for all of them. Recon, target classification, tool selection, and command construction are deterministic; AI runs only after all scanning completes.

A scanner failure is recorded and other scanners continue. Cancelling a scan stops the active scanners and marks the remaining attempts cancelled. Completed attempts and their checksums are reused during restart recovery, keyed by (scope, scanner).

AI does not validate targets, discover subdomains, select tools, construct commands, change scan depth, verify findings, calculate status, or generate live output. During execution the dashboard displays native scanner stdout and stderr only.

After all attempts reach terminal states, Xalgorix parses each tool's native output (Nuclei JSONL, ZAP JSON, testssl JSON, Greenbone XML, Vuls JSON, Nmap XML, Trivy, Semgrep, Gitleaks, and OSV-Scanner JSON) into a private canonical input. When different scanners report the same CVE on the same scope, the report shows one finding that lists every source and keeps each source's evidence reference. Report AI may explain, classify, and recommend remediation for those records. Output records with unknown source IDs are rejected. If Report AI is absent or fails, Xalgorix immediately creates a deterministic fallback report.

The report groups findings by scope (each host, then the source code), shows each host's classifier tracks, and opens with a scan-coverage section: a recon summary (hosts discovered, open ports, detected services) and the terminal status of every tool on every scope.
```

- [ ] **Step 2: Replace the `## Scanner inputs` table** with:

```markdown
| Scanner | Scope | Input |
|---|---|---|
| Subfinder, httpx, Nmap | Recon | Submitted target; per-host Nmap on each live host |
| Nuclei | Host (web) | Host or live URL |
| ZAP | Host (web) | Deterministically normalized HTTP/HTTPS URL |
| testssl.sh | Host (web) | Host with TLS |
| OpenVAS | Host (server) | Host |
| Vuls | Host (server) | Optional operator-managed SSH host alias |
| Trivy, Semgrep, Gitleaks, OSV-Scanner | Source | Resolved source directory |
```

- [ ] **Step 3: Update `## Selecting scanners` wording.** Replace "By default every scan attempts all five." with "By default every scan runs the whole pipeline." Replace "so every scan still accounts for all five and the report shows what was not attempted." with "so every scan still accounts for every scope×tool and the report shows what was not attempted." Replace "(no URL, no artifact, no SSH alias)" with "(no URL, no source, no SSH alias, or a scope outside the tool's track)". In the wildcard paragraph, replace "running the five-attempt pipeline for each discovered target" with "running the full pipeline for each discovered target". Keep the `--scanners` examples.

- [ ] **Step 4: Add the new env vars** to the table, after `XALGORIX_VULS_SSH_CONFIG`:

```markdown
| `XALGORIX_SUBFINDER_PATH` | `subfinder` | Subfinder executable (recon) |
| `XALGORIX_HTTPX_PATH` | `httpx` | httpx executable (recon) |
| `XALGORIX_NMAP_PATH` | `nmap` | Nmap executable (recon) |
| `XALGORIX_TESTSSL_PATH` | `testssl.sh` | testssl.sh executable |
| `XALGORIX_SEMGREP_PATH` | `semgrep` | Semgrep executable |
| `XALGORIX_GITLEAKS_PATH` | `gitleaks` | Gitleaks executable |
| `XALGORIX_OSV_PATH` | `osv-scanner` | OSV-Scanner executable |
| `XALGORIX_MAX_WORKERS` | `3` | Concurrent scanner limit (ZAP/OpenVAS are additionally serialized) |
```

and after `XALGORIX_SCANNER_MAX_OUTPUT_BYTES`:

```markdown
| `XALGORIX_<TOOL>_TIMEOUT_SECONDS` | per tool | Per-tool timeout, e.g. `XALGORIX_NMAP_TIMEOUT_SECONDS` (1800), `XALGORIX_SEMGREP_TIMEOUT_SECONDS` (1800), `XALGORIX_GITLEAKS_TIMEOUT_SECONDS` (900), `XALGORIX_OSV_TIMEOUT_SECONDS` (900) |
```

Replace "Nuclei, Trivy, and Vuls are expected in the Xalgorix runtime image." with "Nuclei, Trivy, Vuls, Subfinder, httpx, Nmap, testssl.sh, Semgrep, Gitleaks, and OSV-Scanner are expected in the Xalgorix runtime image."

- [ ] **Step 5: Update `## Persistence`.** Replace the `scanner_runs` sentence's "with scanner name, target, terminal status," with "with scanner name, scope (`recon:<target>`, `host:<host>`, or `source:main`), target, terminal status,". After it, add:

```markdown
Resume keys on the (scope, scanner) pair. A record written before scopes existed has an empty scope and is treated as the single implicit host scope (`host:<target>`), so older records resume and report unchanged. Recon's discovered host set, with per-host evidence, is persisted at `scanner-output/recon-scopes.json`.
```

Replace the `report.json` sentence with:

```markdown
`report.json` records source run checksums, prompt version, provider/model when used, generation mode, timestamp, parse errors, the per-scope coverage list and recon summary, and validated report findings (each with its scope and, for merged findings, every contributing source).
```

- [ ] **Step 6: Check for leftover stale claims + commit**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && grep -n -i "five" README.md`
Expected: no remaining claim that a scan runs exactly five scanners (an unrelated use of the word is fine).

```bash
git add README.md
git commit -m "docs: replace five-scanner contract with the scope DAG determinism contract"
```

---

### Task 6: Whole-tree verification

**Files:**
- No source changes expected. Adjust a cross-package test only if it asserts on report ordering or `VulnSummary` shape that this increment deliberately changed.

- [ ] **Step 1: Build + vet + gofmt**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go build ./... && gofmt -l internal/ cmd/ && CGO_ENABLED=0 go vet ./internal/... ./cmd/...`
Expected: only the pre-existing `internal/agent/hooks.go` / `hooks_test.go` gofmt drift.

- [ ] **Step 2: Affected suites twice**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/scanner/... ./internal/web/... ./internal/config/... ./internal/reporting/... ./internal/tui/... -count=2`
Expected: PASS, twice. (`internal/tui` is included because the CLI report path calls `web.GenerateCLIReport`. If it is not a package with tests, drop it.)

- [ ] **Step 3: Commit any fixups** (skip if none).

```bash
git add -A && git commit -m "test: account for scope-grouped scanner reports in cross-package assertions"
```

---

## Self-Review

**Spec coverage:**
- §8 group by scope + track labels: Task 3 (`buildReportScopes`, ordering, `VulnSummary.Scope`) and Task 4 (coverage section, group rows, SCOPE detail).
- §8 recon summary (hosts, open ports, services): Task 3 (`summarizeReportRecon`, `report.json` `recon`) and Task 4 (`reconSummaryLine`).
- §8 cross-scope dedup, same CVE on the same host from openvas and nuclei: Task 1 (`mergeCrossScanner`, `(Scope, CVE)` key, contributors in `Sources`).
- §8 new source IDs flow through the existing mappings: unchanged. The merged finding keeps the primary `SourceID`; the CWE/OWASP mappings in report.go read `VulnSummary` as before.
- §7 README contract (verbatim wording) + migration note: Task 5 Steps 1 and 5.
- §9 CLI/web scanner surface already landed in 5a/5b; Task 5 documents the env vars.

**Placeholder scan:** every code step has complete code, and the parser formats named in the README text were checked against parse.go (Nmap is XML; testssl/Semgrep/Gitleaks/OSV are JSON).

**Type consistency:**
- `FindingSource` fields (`Scanner`, `SourceID`, `Endpoint`, `EvidenceRef`) are the same in Tasks 1, 3 and 4.
- `reportScope.Kind` values `"host"`/`"source"` match `string(scanner.ScopeHost/ScopeSource)`.
- `reportScopeRun` is compared with `==` in the Task 3 test, which is valid because it has only string fields.
- `severityRankValue` (web) and `severityRank` (scanner) are different functions in different packages, with no name collision.

**Key risks for the executor (not defects):**
- (a) Task 4 Step 6: the scoping of `scopeLabels` depends on how the summary and details blocks nest in report.go. The step says how to lift it if needed.
- (b) Merging in `ParseRuns` changes the finding count for scans where two scanners report the same CVE on one scope. Any test that fixed a count for that case must be updated to the merged count, not weakened.
- (c) `aiReportFindings` still validates against the chunk's primary `SourceID`s. An AI reply citing a secondary source ID fails validation and falls back to the deterministic report, which is the intended fail-safe.
