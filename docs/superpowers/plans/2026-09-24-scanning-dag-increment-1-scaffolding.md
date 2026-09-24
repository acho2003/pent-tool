# Scanning DAG — Increment 1: Scaffolding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Introduce the `Scope` model, a tool registry with per-tool descriptors, and `(scope, scanner)`-keyed resume — with zero change to external behavior (the existing five scanners still run in the same order and produce the same five `Run` records).

**Architecture:** Add new types (`Scope`, `Descriptor`, `Phase`, `Weight`, `Track`, `HostEvidence`, `Port`) to the `scanner` package. Give every existing `Runner` a `Descriptor()`. The `Pipeline` derives a single implicit host scope from `Request.Target`, stamps each `Run` with that scope, and re-keys resume on `(scope, scanner)`. Empty-scope legacy runs are treated as the implicit scope so persisted queue state keeps resuming.

**Tech Stack:** Go 1.26, standard library only (no new deps in this increment). Tests are standard `go test`.

**Spec:** `docs/superpowers/specs/2026-09-24-scanning-dag-pipeline-design.md`

## Global Constraints

- Go module builds with `CGO_ENABLED=0` for tests on Darwin (auto-memory: CGO segfaults on macOS). Always run: `CGO_ENABLED=0 go test ./internal/scanner/...`.
- No behavior change in this increment: `NewPipeline` MUST yield the same five runners (`nuclei, zap, openvas, trivy, vuls`) in the same order; a whole-pipeline run MUST still produce exactly five `Run` records for a single target. Callers assert this (`internal/web/report_ai.go:55`, `internal/web/scanner_handlers.go:183`).
- `OrderedNames` and `NormalizeScanners` keep their current signatures and behavior (web/CLI/TUI/schedules depend on them).
- New `Run.Scope` field is JSON-serialized as `scope` and is `omitempty` so existing persisted records (no scope) round-trip unchanged.
- Descriptor phase values are exactly: `recon`, `web`, `server`, `sast`, `finalize`. Weight values are exactly: `light`, `heavy`. Track values are exactly: `web`, `server`.

---

### Task 1: Core scope and descriptor types

**Files:**
- Modify: `internal/scanner/types.go`
- Create: `internal/scanner/scope.go`
- Test: `internal/scanner/scope_test.go`

**Interfaces:**
- Consumes: nothing (foundation task).
- Produces:
  - `type ScopeKind string` with consts `ScopeHost ScopeKind = "host"`, `ScopeSource ScopeKind = "source"`.
  - `type Track string` with consts `TrackWeb Track = "web"`, `TrackServer Track = "server"`.
  - `type Port struct { Number int; Protocol string; Service string; Product string }`.
  - `type HostEvidence struct { ResolvedIPs []string; OpenPorts []Port; LiveURLs []string; TLS bool }`.
  - `type SourceRef struct { Path string; Provenance string }`.
  - `type Scope struct { ID string; Kind ScopeKind; Target string; Evidence HostEvidence; Source SourceRef; Tracks []Track }`.
  - `func HostScope(target string) Scope` — returns `Scope{ID: "host:"+target, Kind: ScopeHost, Target: target}`.
  - `func (s Scope) Key() string` — returns `s.ID`.

- [ ] **Step 1: Write the failing test**

```go
// internal/scanner/scope_test.go
package scanner

import "testing"

func TestHostScopeKey(t *testing.T) {
	s := HostScope("api.example.com")
	if s.Kind != ScopeHost {
		t.Fatalf("kind = %q, want %q", s.Kind, ScopeHost)
	}
	if s.Target != "api.example.com" {
		t.Fatalf("target = %q", s.Target)
	}
	if got, want := s.Key(), "host:api.example.com"; got != want {
		t.Fatalf("key = %q, want %q", got, want)
	}
}

func TestScopeTrackConsts(t *testing.T) {
	if TrackWeb != "web" || TrackServer != "server" {
		t.Fatalf("track consts drifted: %q %q", TrackWeb, TrackServer)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run 'TestHostScopeKey|TestScopeTrackConsts' -v`
Expected: FAIL — `undefined: HostScope`, `undefined: ScopeHost`, etc.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/scanner/scope.go
package scanner

type ScopeKind string

const (
	ScopeHost   ScopeKind = "host"
	ScopeSource ScopeKind = "source"
)

type Track string

const (
	TrackWeb    Track = "web"
	TrackServer Track = "server"
)

type Port struct {
	Number   int
	Protocol string
	Service  string
	Product  string
}

type HostEvidence struct {
	ResolvedIPs []string
	OpenPorts   []Port
	LiveURLs    []string
	TLS         bool
}

type SourceRef struct {
	Path       string
	Provenance string
}

type Scope struct {
	ID       string
	Kind     ScopeKind
	Target   string
	Evidence HostEvidence
	Source   SourceRef
	Tracks   []Track
}

func HostScope(target string) Scope {
	return Scope{ID: "host:" + target, Kind: ScopeHost, Target: target}
}

func (s Scope) Key() string { return s.ID }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run 'TestHostScopeKey|TestScopeTrackConsts' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/scope.go internal/scanner/scope_test.go
git commit -m "feat(scanner): add Scope and evidence types"
```

---

### Task 2: Tool descriptor type and Runner.Descriptor()

**Files:**
- Modify: `internal/scanner/types.go` (extend `Runner` interface)
- Create: `internal/scanner/descriptor.go`
- Modify: `internal/scanner/pipeline.go` (add `Descriptor()` to `commandRunner`)
- Modify: `internal/scanner/zap.go`, `internal/scanner/openvas.go`, `internal/scanner/vuls.go` (add `Descriptor()` to `zapRunner`, `openVASRunner`, `vulsRunner`)
- Test: `internal/scanner/descriptor_test.go`

**Interfaces:**
- Consumes: `Track`, `ScopeKind` from Task 1.
- Produces:
  - `type Phase string` with consts `PhaseRecon="recon"`, `PhaseWeb="web"`, `PhaseServer="server"`, `PhaseSAST="sast"`, `PhaseFinalize="finalize"`.
  - `type Weight string` with consts `WeightLight="light"`, `WeightHeavy="heavy"`.
  - `type Descriptor struct { Name string; Phase Phase; Tracks []Track; Weight Weight; Applies func(Scope) bool }`.
  - `Runner` interface gains method `Descriptor() Descriptor`.
  - Each existing runner returns a descriptor: nuclei `{web, [web], light}`, zap `{web, [web], heavy}`, openvas `{server, [server], heavy}`, trivy `{sast, nil, light}`, vuls `{server, [server], light}`.

- [ ] **Step 1: Write the failing test**

```go
// internal/scanner/descriptor_test.go
package scanner

import "testing"

func TestExistingRunnerDescriptors(t *testing.T) {
	p := NewPipeline(Config{})
	want := map[string]struct {
		phase  Phase
		weight Weight
	}{
		"nuclei":  {PhaseWeb, WeightLight},
		"zap":     {PhaseWeb, WeightHeavy},
		"openvas": {PhaseServer, WeightHeavy},
		"trivy":   {PhaseSAST, WeightLight},
		"vuls":    {PhaseServer, WeightLight},
	}
	if len(p.Runners) != len(want) {
		t.Fatalf("runner count = %d, want %d", len(p.Runners), len(want))
	}
	for _, r := range p.Runners {
		d := r.Descriptor()
		exp, ok := want[d.Name]
		if !ok {
			t.Fatalf("unexpected runner %q", d.Name)
		}
		if d.Phase != exp.phase || d.Weight != exp.weight {
			t.Errorf("%s: phase/weight = %q/%q, want %q/%q", d.Name, d.Phase, d.Weight, exp.phase, exp.weight)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run TestExistingRunnerDescriptors -v`
Expected: FAIL — `r.Descriptor undefined` (compile error).

- [ ] **Step 3: Write minimal implementation**

Add the descriptor types:

```go
// internal/scanner/descriptor.go
package scanner

type Phase string

const (
	PhaseRecon    Phase = "recon"
	PhaseWeb      Phase = "web"
	PhaseServer   Phase = "server"
	PhaseSAST     Phase = "sast"
	PhaseFinalize Phase = "finalize"
)

type Weight string

const (
	WeightLight Weight = "light"
	WeightHeavy Weight = "heavy"
)

type Descriptor struct {
	Name    string
	Phase   Phase
	Tracks  []Track
	Weight  Weight
	Applies func(Scope) bool
}
```

Extend the `Runner` interface in `internal/scanner/types.go`:

```go
type Runner interface {
	Name() string
	Descriptor() Descriptor
	Run(context.Context, Request, Config, EmitFunc) Run
}
```

Add `Descriptor()` methods. In `internal/scanner/pipeline.go`, `commandRunner` carries a descriptor so nuclei and trivy differ. Change its definition and construction:

```go
// in pipeline.go
type commandRunner struct {
	name  string
	desc  Descriptor
	build commandBuilder
}

func (r commandRunner) Name() string           { return r.name }
func (r commandRunner) Descriptor() Descriptor { return r.desc }
```

Update `NewPipeline` runner construction:

```go
return &Pipeline{Config: cfg, Runners: []Runner{
	commandRunner{name: "nuclei", desc: Descriptor{Name: "nuclei", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightLight}, build: buildNuclei},
	zapRunner{},
	openVASRunner{},
	commandRunner{name: "trivy", desc: Descriptor{Name: "trivy", Phase: PhaseSAST, Weight: WeightLight}, build: buildTrivy},
	vulsRunner{},
}}
```

Add methods to the struct runners (place next to each type's existing `Name()`):

```go
// zap.go
func (zapRunner) Descriptor() Descriptor {
	return Descriptor{Name: "zap", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightHeavy}
}

// openvas.go
func (openVASRunner) Descriptor() Descriptor {
	return Descriptor{Name: "openvas", Phase: PhaseServer, Tracks: []Track{TrackServer}, Weight: WeightHeavy}
}

// vuls.go
func (vulsRunner) Descriptor() Descriptor {
	return Descriptor{Name: "vuls", Phase: PhaseServer, Tracks: []Track{TrackServer}, Weight: WeightLight}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run TestExistingRunnerDescriptors -v`
Expected: PASS

Then the whole package (the interface change must not break existing runners):
Run: `CGO_ENABLED=0 go test ./internal/scanner/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/descriptor.go internal/scanner/types.go internal/scanner/pipeline.go internal/scanner/zap.go internal/scanner/openvas.go internal/scanner/vuls.go internal/scanner/descriptor_test.go
git commit -m "feat(scanner): add tool descriptors to Runner interface"
```

---

### Task 3: Add Scope field to Run with backward-compatible JSON

**Files:**
- Modify: `internal/scanner/types.go` (`Run` struct)
- Test: `internal/scanner/scope_test.go` (add cases)

**Interfaces:**
- Consumes: nothing new.
- Produces: `Run.Scope string` field, JSON tag `scope,omitempty`. Legacy records (no `scope`) unmarshal with `Scope == ""`.

- [ ] **Step 1: Write the failing test**

```go
// append to internal/scanner/scope_test.go
import (
	"encoding/json"
	"testing"
)

func TestRunScopeJSONRoundtrip(t *testing.T) {
	r := Run{Scanner: "nuclei", Target: "x", Status: "completed", Scope: "host:x"}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var got Run
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Scope != "host:x" {
		t.Fatalf("scope = %q, want host:x", got.Scope)
	}
	// Legacy record without scope stays empty.
	var legacy Run
	if err := json.Unmarshal([]byte(`{"scanner":"nuclei","status":"completed"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.Scope != "" {
		t.Fatalf("legacy scope = %q, want empty", legacy.Scope)
	}
}
```

(Note: if `scope_test.go` already imports `testing`, merge imports rather than duplicating the block.)

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run TestRunScopeJSONRoundtrip -v`
Expected: FAIL — `unknown field Scope in struct literal`.

- [ ] **Step 3: Write minimal implementation**

Add the field to `Run` in `internal/scanner/types.go`, immediately after `Scanner`:

```go
type Run struct {
	Scanner      string `json:"scanner"`
	Scope        string `json:"scope,omitempty"`
	Target       string `json:"target"`
	// ... rest unchanged
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run TestRunScopeJSONRoundtrip -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/types.go internal/scanner/scope_test.go
git commit -m "feat(scanner): add backward-compatible Scope field to Run"
```

---

### Task 4: Stamp runs with the implicit scope and re-key resume on (scope, scanner)

**Files:**
- Modify: `internal/scanner/pipeline.go` (`Pipeline.Run`, `runAttempt`, skip/cancel record construction)
- Test: `internal/scanner/pipeline_test.go` (add cases)

**Interfaces:**
- Consumes: `HostScope` (Task 1), `Run.Scope` (Task 3).
- Produces:
  - Every `Run` emitted by `Pipeline.Run` has `Scope == HostScope(req.Target).Key()`.
  - Resume reuse keys on `(scope, scanner)`: a passed-in `existing` run matches when its scanner equals the runner name AND (its `Scope` equals the implicit scope key OR its `Scope == ""` for legacy records).
  - `func resumeKey(scope, scanner string) string` returns `scope + "\x00" + scanner` (unexported helper).

- [ ] **Step 1: Write the failing test**

```go
// append to internal/scanner/pipeline_test.go
func TestRunStampsImplicitScope(t *testing.T) {
	p := NewPipeline(Config{})
	// Only run the "skipped" bookkeeping path so the test needs no real tools:
	// select a scanner subset of one, leaving the rest skipped.
	req := Request{Target: "example.com", Scanners: []string{"nuclei"}, ScanDir: t.TempDir()}
	// Cancel immediately so nuclei is recorded cancelled, not actually executed.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runs := p.Run(ctx, req, nil, nil)
	if len(runs) != len(p.Runners) {
		t.Fatalf("run count = %d, want %d", len(runs), len(p.Runners))
	}
	want := HostScope("example.com").Key()
	for _, r := range runs {
		if r.Scope != want {
			t.Errorf("%s scope = %q, want %q", r.Scanner, r.Scope, want)
		}
	}
}

func TestResumeReusesLegacyEmptyScopeRuns(t *testing.T) {
	p := NewPipeline(Config{})
	// A legacy terminal run with empty Scope must be reused (not re-run).
	legacy := Run{Scanner: "nuclei", Target: "example.com", Status: "completed"}
	req := Request{Target: "example.com", Scanners: []string{"nuclei"}, ScanDir: t.TempDir()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runs := p.Run(ctx, req, []Run{legacy}, nil)
	var got *Run
	for i := range runs {
		if runs[i].Scanner == "nuclei" {
			got = &runs[i]
		}
	}
	if got == nil {
		t.Fatal("no nuclei run returned")
	}
	if got.Status != "completed" {
		t.Fatalf("nuclei status = %q, want completed (legacy run should be reused)", got.Status)
	}
}
```

(Ensure `context` is imported in `pipeline_test.go`.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run 'TestRunStampsImplicitScope|TestResumeReusesLegacyEmptyScopeRuns' -v`
Expected: FAIL — scopes are empty on emitted runs; legacy reuse may already pass by scanner-name luck, but the scope assertion fails.

- [ ] **Step 3: Write minimal implementation**

In `internal/scanner/pipeline.go`, at the top of `Pipeline.Run`, compute the implicit scope and change resume keying:

```go
func (p *Pipeline) Run(ctx context.Context, req Request, existing []Run, emit EmitFunc) []Run {
	scope := HostScope(req.Target).Key()
	byKey := make(map[string]Run, len(existing))
	for _, run := range existing {
		if !run.Terminal() {
			continue
		}
		s := run.Scope
		if s == "" {
			s = scope // legacy records predate scoping; treat as the implicit scope
		}
		byKey[resumeKey(s, run.Scanner)] = run
	}
	out := make([]Run, 0, len(p.Runners))
	for i, runner := range p.Runners {
		if old, ok := byKey[resumeKey(scope, runner.Name())]; ok {
			out = append(out, old)
			continue
		}
		// ... existing skip / cancel / runAttempt logic below, with Scope stamped
	}
	return out
}

func resumeKey(scope, scanner string) string { return scope + "\x00" + scanner }
```

Stamp `Scope` on every constructed `Run` in this function and in `runAttempt`:
- The `skipped` record: add `Scope: scope` to the `Run{...}` literal.
- The `cancelled` records in the `ctx.Err()` loop: add `Scope: scope`.
- After `run := runAttempt(...)`, set `run.Scope = scope` before appending.
- In `runAttempt`'s recover/non-terminal fixups, the caller now stamps scope after return, so no change needed there — but confirm the returned run gets `run.Scope = scope` at the call site.

Concretely, replace the `runAttempt` call site:

```go
run := runAttempt(ctx, runner, req, p.Config, emit)
run.Scope = scope
out = append(out, run)
```

And add `Scope: scope` to the skipped literal and the cancelled literal.

- [ ] **Step 4: Run tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run 'TestRunStampsImplicitScope|TestResumeReusesLegacyEmptyScopeRuns' -v`
Expected: PASS

Then full package:
Run: `CGO_ENABLED=0 go test ./internal/scanner/...`
Expected: PASS (existing `pipeline_test.go` resume tests still green — legacy empty-scope reuse preserves them).

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/pipeline.go internal/scanner/pipeline_test.go
git commit -m "feat(scanner): stamp runs with scope and key resume on (scope, scanner)"
```

---

### Task 5: Verify no downstream breakage and build the whole tree

**Files:**
- No source changes expected. If the build surfaces a caller that constructs a `Runner` (e.g. a test double implementing the interface), add a `Descriptor()` method to it.

**Interfaces:**
- Consumes: everything above.
- Produces: a green build and test run across the repo.

- [ ] **Step 1: Build the whole module**

Run: `CGO_ENABLED=0 go build ./...`
Expected: success. If a mock `Runner` in another package fails to compile (missing `Descriptor()`), add:

```go
func (m mockRunner) Descriptor() scanner.Descriptor {
	return scanner.Descriptor{Name: m.Name(), Phase: scanner.PhaseWeb, Weight: scanner.WeightLight}
}
```

- [ ] **Step 2: Run the scanner + web test suites**

Run: `CGO_ENABLED=0 go test ./internal/scanner/... ./internal/web/...`
Expected: PASS. In particular `internal/web/report_ai_test.go` and the `len(runs) == len(OrderedNames)` checks still hold because run count and order are unchanged.

- [ ] **Step 3: Run the full test suite**

Run: `CGO_ENABLED=0 go test ./...`
Expected: PASS (excluding any pre-existing macOS-only failures noted in auto-memory).

- [ ] **Step 4: Commit any fixups**

```bash
git add -A
git commit -m "test(scanner): satisfy Runner interface across callers"
```

(If Step 1–3 needed no changes, skip the commit.)

---

## Self-Review

**1. Spec coverage (Increment 1 = spec §3 data model + §4.1 resume, scaffolding only):**
- Scope model (§3.1) → Task 1. ✅
- `Run.Scope` + resume re-keying (§3.2, §4.1) → Tasks 3, 4. ✅
- Tool descriptor/registry (§3.3) → Task 2. ✅
- "No behavior change; five tools become registry entries mapped to a single implicit host scope" (§10 increment 1) → Tasks 2, 4 + Task 5 verification. ✅
- Recon, classifier, scheduler, new tools, report (spec §4–§9) → deliberately deferred to later increments; each gets its own plan. Not gaps.

**2. Placeholder scan:** No TBD/TODO. Every code step has concrete code. Task 5 is conditional-fixup but specifies the exact method to add if needed. ✅

**3. Type consistency:** `HostScope`/`Scope.Key()` (Task 1) used verbatim in Task 4. `Descriptor`/`Phase`/`Weight`/`Track` consts defined in Tasks 1–2 used consistently. `Run.Scope` (Task 3) consumed in Task 4. `resumeKey` defined and used only in Task 4. ✅

## Notes for later increments (not part of this plan)

- Increment 2 (recon) will add `Runner`s in `PhaseRecon` and populate `HostEvidence`; it will introduce the fan-out that produces multiple host scopes, at which point the `len(runs) == len(OrderedNames)` caller checks (`report_ai.go:55`, `scanner_handlers.go:183`) must be revisited — that is the deliberate determinism-contract change in spec §7 and belongs to the increment that first produces more than five runs.
- Keep `OrderedNames` until the registry fully subsumes it (a later increment removes it and updates CLI help + `NormalizeScanners`).
