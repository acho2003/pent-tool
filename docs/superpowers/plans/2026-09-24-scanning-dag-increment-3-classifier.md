# Scanning DAG — Increment 3: WEB/SERVER Classifier & Tracks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a deterministic classifier that tags each discovered host with WEB and/or SERVER tracks from its recon evidence, and gate the per-host fan-out so each host runs only the scanners whose track applies — recording `not_applicable` for the rest.

**Architecture:** A pure `Classify(HostEvidence) []Track` function (no I/O, no AI) with a documented port/service table. `Pipeline.Run` sets `scope.Tracks = Classify(scope.Evidence)` for every scope (fresh or resumed), then in the per-host loop a runner runs only if its `Descriptor().Tracks` intersect the host's tracks (or it is a no-track runner like trivy, which always runs); a runner whose track doesn't apply records a terminal `not_applicable` run for that scope.

**Tech Stack:** Go 1.26, stdlib only.

**Spec:** `docs/superpowers/specs/2026-09-24-scanning-dag-pipeline-design.md` (§5 classifier, §7 determinism, §10 increment 3)

## Global Constraints

- Run tests with `CGO_ENABLED=0` on Darwin. Command: `CGO_ENABLED=0 go test ./internal/scanner/...`
- Before every commit: `gofmt -l internal/scanner/` prints nothing; `go vet ./internal/scanner/...` passes.
- Classification is deterministic and code-only — never AI.
- Descriptors already encode tracks (Increment 1): nuclei `[web]`, zap `[web]`, openvas `[server]`, vuls `[server]`, trivy `nil` (no tracks). Do NOT change descriptors.
- No-track runners (trivy) ALWAYS run per host in this increment (trivy moves to the SAST phase in Increment 5; excluding it now would be a regression).
- A classifier-excluded scanner records terminal status `not_applicable` (not `skipped`; `skipped` remains reserved for operator deselection via `req.Scanners`).
- Track consts (Increment 1): `TrackWeb = "web"`, `TrackServer = "server"`.

---

### Task 1: Deterministic classifier

**Files:**
- Create: `internal/scanner/classify.go`
- Test: `internal/scanner/classify_test.go`

**Interfaces:**
- Consumes: `HostEvidence`, `Port`, `Track`, `TrackWeb`, `TrackServer` (all from Increment 1).
- Produces:
  - `func Classify(ev HostEvidence) []Track` — returns web and/or server (or empty). Web when: `len(ev.LiveURLs) > 0` OR `ev.TLS` OR any open port is web-ish. Server when: any open port is NOT web-ish. Order: web before server when both.
  - `func isWebPort(p Port) bool` — true when `p.Number` ∈ {80, 443, 8080, 8443} OR `p.Service` contains "http" (covers http, https, http-proxy, http-alt).

- [ ] **Step 1: Write the failing test**

```go
// internal/scanner/classify_test.go
package scanner

import (
	"reflect"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		ev   HostEvidence
		want []Track
	}{
		{"live url only", HostEvidence{LiveURLs: []string{"http://x"}}, []Track{TrackWeb}},
		{"tls flag", HostEvidence{TLS: true}, []Track{TrackWeb}},
		{"std web port", HostEvidence{OpenPorts: []Port{{Number: 443, Service: "https"}}}, []Track{TrackWeb}},
		{"http on nonstandard port", HostEvidence{OpenPorts: []Port{{Number: 3000, Service: "http"}}}, []Track{TrackWeb}},
		{"ssh only", HostEvidence{OpenPorts: []Port{{Number: 22, Service: "ssh"}}}, []Track{TrackServer}},
		{"web plus ssh", HostEvidence{OpenPorts: []Port{{Number: 80, Service: "http"}, {Number: 22, Service: "ssh"}}}, []Track{TrackWeb, TrackServer}},
		{"live url plus db", HostEvidence{LiveURLs: []string{"http://x"}, OpenPorts: []Port{{Number: 5432, Service: "postgresql"}}}, []Track{TrackWeb, TrackServer}},
		{"nothing", HostEvidence{}, nil},
	}
	for _, c := range cases {
		if got := Classify(c.ev); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: Classify = %v, want %v", c.name, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run TestClassify -v`
Expected: FAIL — `undefined: Classify`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/scanner/classify.go
package scanner

import "strings"

// isWebPort reports whether an open port is an HTTP(S) service, by well-known
// port number or by nmap-detected service name.
func isWebPort(p Port) bool {
	switch p.Number {
	case 80, 443, 8080, 8443:
		return true
	}
	return strings.Contains(strings.ToLower(p.Service), "http")
}

// Classify deterministically assigns WEB and/or SERVER tracks to a host from its
// recon evidence. WEB when it serves HTTP(S) (a live URL, TLS, or a web-ish open
// port). SERVER when any non-web service port is open. A host can be both; a live
// host exposing nothing useful is neither.
func Classify(ev HostEvidence) []Track {
	web := ev.TLS || len(ev.LiveURLs) > 0
	server := false
	for _, p := range ev.OpenPorts {
		if isWebPort(p) {
			web = true
		} else {
			server = true
		}
	}
	var out []Track
	if web {
		out = append(out, TrackWeb)
	}
	if server {
		out = append(out, TrackServer)
	}
	return out
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run TestClassify -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/classify.go internal/scanner/classify_test.go
git commit -m "feat(scanner): add deterministic WEB/SERVER host classifier"
```

---

### Task 2: Track-applicability gate in the fan-out loop

**Files:**
- Modify: `internal/scanner/pipeline.go` (`Pipeline.Run` scan-phase loop; add helpers)
- Test: `internal/scanner/pipeline_test.go`

**Interfaces:**
- Consumes: `Classify` (Task 1), `Runner.Descriptor()`, `Track`, existing `skippedRun`/`cancelledRun` patterns.
- Produces:
  - Each scope classified: `sc.Tracks = Classify(sc.Evidence)` before its runner loop.
  - `func runnerAppliesToTracks(d Descriptor, tracks []Track) bool` — true if `len(d.Tracks) == 0` (no-track runners always apply) OR any `d.Tracks[i]` is in `tracks`.
  - `func notApplicableClassifierRun(name, scope string, req Request, emit EmitFunc) Run` — terminal `not_applicable` run stamped with scope, reason `"host tracks do not include this scanner's track"`, emitting a `scanner_not_applicable` event (mirror `skippedRun`'s shape but status `not_applicable`).
  - In the per-host loop, after the deselected-skip check and before the `ctx.Err()` check: if `!runnerAppliesToTracks(runner.Descriptor(), sc.Tracks)` → append `notApplicableClassifierRun(...)` and continue.

- [ ] **Step 1: Write the failing test**

```go
// append to internal/scanner/pipeline_test.go
func TestPipelineClassifierGatesTracks(t *testing.T) {
	var seen []string
	// nuclei is web-track, vuls is server-track (real descriptors via NewPipeline).
	p := NewPipeline(Config{})
	// Keep only nuclei (web) and vuls (server) to make assertions crisp.
	var runners []Runner
	for _, r := range p.Runners {
		if r.Name() == "nuclei" || r.Name() == "vuls" {
			runners = append(runners, fakeRunner{name: r.Name(), seen: &seen})
		}
	}
	p2 := &Pipeline{Runners: runners}
	// One web-only host.
	p2.reconFn = func(context.Context, Request, Config, EmitFunc) ([]Scope, []Run) {
		s := HostScope("web.example.com")
		s.Evidence = HostEvidence{LiveURLs: []string{"https://web.example.com"}}
		return []Scope{s}, nil
	}
	runs := p2.Run(context.Background(), Request{Target: "web.example.com", ScanDir: t.TempDir()}, nil, nil)
	byScanner := map[string]string{}
	for _, r := range runs {
		byScanner[r.Scanner] = r.Status
	}
	// nuclei (web) runs; vuls (server) is not_applicable for a web-only host.
	if byScanner["vuls"] != "not_applicable" {
		t.Errorf("vuls status = %q, want not_applicable", byScanner["vuls"])
	}
	// nuclei actually executed (fakeRunner appended its name).
	found := false
	for _, n := range seen {
		if n == "nuclei" {
			found = true
		}
		if n == "vuls" {
			t.Errorf("vuls should not have executed for a web-only host")
		}
	}
	if !found {
		t.Errorf("nuclei should have executed for a web host")
	}
}
```

> Note: `fakeRunner`'s `Descriptor()` returns `PhaseWeb`/no-heavy but **empty Tracks** today, so a fakeRunner would always apply. This test must give the fake runners the REAL tracks. Adjust `fakeRunner` to carry an optional `tracks []Track` used by its `Descriptor()`, and set `tracks: []Track{TrackWeb}` for nuclei and `[]Track{TrackServer}` for vuls in the test. Keep existing fakeRunner uses compiling (default nil tracks = always applies, preserving prior tests).

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run TestPipelineClassifierGatesTracks -v`
Expected: FAIL — vuls runs (or no not_applicable record) because no gate exists yet.

- [ ] **Step 3: Write minimal implementation**

Add helpers to `pipeline.go`:

```go
func runnerAppliesToTracks(d Descriptor, tracks []Track) bool {
	if len(d.Tracks) == 0 {
		return true // no-track runners (e.g. trivy) always run per host
	}
	for _, dt := range d.Tracks {
		for _, ht := range tracks {
			if dt == ht {
				return true
			}
		}
	}
	return false
}

func notApplicableClassifierRun(name, scope string, req Request, emit EmitFunc) Run {
	now := time.Now().Format(time.RFC3339Nano)
	r := Run{Scanner: name, Target: req.Target, Status: "not_applicable", Reason: "host tracks do not include this scanner's track", StartedAt: now, FinishedAt: now, Scope: scope}
	if emit != nil {
		emit(Event{Type: "scanner_not_applicable", Scanner: name, Run: r, Output: r.Reason})
	}
	return r
}
```

In `Pipeline.Run`, inside the `for _, sc := range scopes` loop, right after computing `scopeKey`, classify:

```go
sc.Tracks = Classify(sc.Evidence)
```

Then in the inner runner loop, after the deselected-skip block and before the `ctx.Err()` block, add:

```go
if !runnerAppliesToTracks(runner.Descriptor(), sc.Tracks) {
	out = append(out, notApplicableClassifierRun(runner.Name(), scopeKey, hostReq, emit))
	continue
}
```

Update `fakeRunner` (test file) to carry optional tracks:

```go
type fakeRunner struct {
	name   string
	seen   *[]string
	status string
	cancel context.CancelFunc
	tracks []Track
}
func (f fakeRunner) Descriptor() Descriptor {
	return Descriptor{Name: f.name, Phase: PhaseWeb, Weight: WeightLight, Tracks: f.tracks}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/scanner/...`
Expected: PASS — new classifier-gate test passes AND all Increment 1/2 tests still pass (existing fakeRunners have nil tracks → always apply → unchanged behavior).

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/pipeline.go internal/scanner/pipeline_test.go
git commit -m "feat(scanner): gate per-host scanners by classified tracks"
```

---

### Task 3: Whole-tree verification

**Files:**
- No source changes expected. If the web layer displays or counts scanner runs and a test asserts specifics that shift because of new `not_applicable` records, adjust that test to the new reality (variable statuses per host).

**Interfaces:**
- Consumes: everything above.
- Produces: green build + affected suites.

- [ ] **Step 1: Build the whole module**

Run: `CGO_ENABLED=0 go build ./...`
Expected: success.

- [ ] **Step 2: Run affected suites**

Run: `CGO_ENABLED=0 go test ./internal/scanner/... ./internal/web/... ./internal/reporting/...`
Expected: PASS. `not_applicable` is already a terminal status the report/web layers handle (used by openvas/vuls/trivy today), so no new source-id or status handling is required — confirm the web suite stays green.

- [ ] **Step 3: gofmt/vet**

Run: `gofmt -l internal/scanner/ && go vet ./internal/scanner/... ./internal/web/...`
Expected: no output / clean.

- [ ] **Step 4: Commit any fixups**

```bash
git add -A
git commit -m "test: adjust for classifier not_applicable records"
```

(Skip if no changes were needed.)

---

## Self-Review

**1. Spec coverage (Increment 3 = spec §5 classifier + §10 increment 3):**
- Deterministic WEB/SERVER classifier with port/service table (§5) → Task 1. ✅
- Both-tracks-allowed; neither → nothing (§5) → Task 1 (Classify returns []). ✅
- Per-host track gating; excluded tools record not_applicable (§7) → Task 2. ✅
- No-track runners (trivy) still run (no regression before Increment 5 SAST phase) → Task 2 (`runnerAppliesToTracks` returns true for empty tracks). ✅
- Classification applies to resumed scopes too (recon-scopes.json carries Evidence) → Task 2 classifies `sc.Evidence` regardless of source. ✅

**2. Placeholder scan:** Tasks 1–2 have complete code. Task 3 is verification with a conditional fixup. No TBDs.

**3. Type consistency:** `Classify`/`isWebPort` (Task 1) consumed in Task 2. `runnerAppliesToTracks`/`notApplicableClassifierRun` defined and used in Task 2. `fakeRunner.tracks` addition keeps existing uses compiling (nil default).

## Notes / risks
- The only cross-cutting edit is `fakeRunner` gaining a `tracks` field; every existing construction omits it (nil), preserving current behavior.
- `not_applicable` is an existing terminal status, so no downstream contract changes.
- Deferred to later increments: testssl on the web track (Increment 5), trivy relocation to the SAST phase (Increment 5), bounded parallelism (Increment 4).
