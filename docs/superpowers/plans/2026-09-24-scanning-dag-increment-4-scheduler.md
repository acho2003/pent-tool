# Scanning DAG — Increment 4: Bounded-Parallel Scheduler & Heavy-Tool Lock Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute the per-host scan phase with bounded parallelism (a configurable worker pool, default 3) while guaranteeing at most one heavy tool (ZAP, OpenVAS) runs at a time — and thread the scope through `Request` so live-emitted events carry it, closing the Increment-2 crash-resume residual.

**Architecture:** The scan phase is refactored from a nested sequential loop into a flat list of `(scope, runner)` tasks with pre-assigned output slots (so the returned `[]Run` stays deterministically ordered regardless of completion order). A worker pool of size `MaxWorkers` runs the tasks; a separate exclusive lock, acquired only by `Weight==heavy` runners, serializes ZAP/OpenVAS across the whole scan. `Request` gains a `Scope` field stamped before execution so every emitted event and the crash-persisted record carry the correct per-host scope.

**Tech Stack:** Go 1.26, stdlib `sync`/`context`. NOTE: `go test -race` needs CGO, which segfaults on this Darwin host (see auto-memory) — concurrency tests here are deterministic (synchronized fake runners asserting max-observed concurrency), and `-race` is left to CI/Linux.

**Spec:** `docs/superpowers/specs/2026-09-24-scanning-dag-pipeline-design.md` (§4 execution model, §4.1 resume, §7 determinism, §10 increment 4)

## Global Constraints

- Run tests with `CGO_ENABLED=0` on Darwin. Do NOT run `-race` here (CGO segfault); note it for CI.
- Before every commit: `gofmt -l internal/scanner/` empty; `go vet ./internal/scanner/...` passes.
- Default worker count: **3** (`XALGORIX_MAX_WORKERS`). Heavy tools = `Weight==WeightHeavy` (zap, openvas), capped to **1** concurrent globally, regardless of worker count.
- **Determinism of results:** the returned `[]Run` MUST be ordered identically to the current sequential order (recon runs first, then scopes in discovery order, each scope's runners in `p.Runners` order) — parallelism changes execution timing, never result order. Achieve this with pre-assigned output slots, not append-on-completion.
- Resume, deselected-skip, classifier not_applicable, and cancellation semantics must all be preserved.
- No new external behavior beyond concurrency + scope-on-events; single-host scans behave as before (just possibly parallel across runners, still heavy-serialized).

---

### Task 1: MaxWorkers config field, default, and env wiring

**Files:**
- Modify: `internal/scanner/types.go` (`Config`)
- Modify: `internal/scanner/pipeline.go` (`applyDefaults`)
- Modify: `internal/config/config.go` (add `MaxWorkers` env field) — follow the existing `envOr*` pattern; read the file to match it.
- Modify: `internal/web/deterministic_scan.go` (`scannerConfig` maps it through)
- Test: `internal/scanner/pipeline_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: `Config.MaxWorkers int`; `applyDefaults` sets it to 3 when `<= 0`. `config.Config` gains `MaxWorkers` from `XALGORIX_MAX_WORKERS` (default 3); `scannerConfig` passes `MaxWorkers: cfg.MaxWorkers`.

- [ ] **Step 1: Write the failing test**

```go
// append to internal/scanner/pipeline_test.go
func TestApplyDefaultsMaxWorkers(t *testing.T) {
	if got := NewPipeline(Config{}).Config.MaxWorkers; got != 3 {
		t.Fatalf("MaxWorkers default = %d, want 3", got)
	}
	if got := NewPipeline(Config{MaxWorkers: 8}).Config.MaxWorkers; got != 8 {
		t.Fatalf("MaxWorkers override = %d, want 8", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run TestApplyDefaultsMaxWorkers -v`
Expected: FAIL — `Config.MaxWorkers` undefined.

- [ ] **Step 3: Write minimal implementation**

Add `MaxWorkers int` to `Config` (near `RateRPS`). In `applyDefaults`:

```go
	if cfg.MaxWorkers <= 0 {
		cfg.MaxWorkers = 3
	}
```

In `internal/config/config.go`, add a `MaxWorkers` field read via the existing integer-env helper (read the file to find it, e.g. `envOrInt("XALGORIX_MAX_WORKERS", 3)`), and in `internal/web/deterministic_scan.go` `scannerConfig`, add `MaxWorkers: cfg.MaxWorkers,` to the returned struct.

- [ ] **Step 4: Run test to verify it passes**

Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run TestApplyDefaultsMaxWorkers -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/types.go internal/scanner/pipeline.go internal/config/config.go internal/web/deterministic_scan.go internal/scanner/pipeline_test.go
git commit -m "feat(scanner): add MaxWorkers config with default 3"
```

---

### Task 2: Thread scope through Request; stamp runs at construction (closes crash-resume residual)

**Files:**
- Modify: `internal/scanner/types.go` (`Request` gains `Scope`)
- Modify: `internal/scanner/pipeline.go` (`executeSpec` stamps `run.Scope = req.Scope`; scan loop sets `hostReq.Scope`)
- Modify: `internal/scanner/zap.go`, `internal/scanner/openvas.go`, `internal/scanner/vuls.go` (initial `Run{...}` sets `Scope: req.Scope`)
- Modify: `internal/scanner/recon.go` (`runRecon` sets a per-tool `req.Scope` before each `executeSpec`: subfinder/httpx → `reconScopeKey(target)`; per-host nmap → `reconHostScopeKey(target, host)`)
- Test: `internal/scanner/pipeline_test.go`, `internal/web/deterministic_scan_test.go`

**Interfaces:**
- Consumes: `Request`, `reconScopeKey`, `reconHostScopeKey` (Increment 2/3).
- Produces: `Request.Scope string`. Every `Run` a runner constructs — including the initial "running" record whose `scanner_started` event is emitted — carries `Scope` from `req.Scope`. `Pipeline.Run` sets `hostReq.Scope = scopeKey` before invoking runners (its post-hoc `run.Scope = scopeKey` stays as a belt-and-suspenders no-op).

- [ ] **Step 1: Write the failing test**

```go
// append to internal/scanner/pipeline_test.go
func TestEmittedEventsCarryScope(t *testing.T) {
	var seen []string
	var events []Event
	p := &Pipeline{Runners: []Runner{fakeRunner{name: "nuclei", seen: &seen}}}
	p.reconFn = func(context.Context, Request, Config, EmitFunc) ([]Scope, []Run) {
		return []Scope{HostScope("a.example.com")}, nil
	}
	_ = p.Run(context.Background(), Request{Target: "a.example.com", ScanDir: t.TempDir()}, nil, func(e Event) {
		events = append(events, e)
	})
	// The fakeRunner emits an event; assert it carries the host scope.
	found := false
	for _, e := range events {
		if e.Scanner == "nuclei" {
			if e.Run.Scope != "host:a.example.com" {
				t.Fatalf("emitted event scope = %q, want host:a.example.com", e.Run.Scope)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("no nuclei event observed")
	}
}
```

> Note: this requires `fakeRunner.Run` to stamp `Scope: req.Scope` on the Run it builds and emits (mirroring how real runners will). Update `fakeRunner.Run` to set `Scope: req.Scope` on its emitted Run.

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run TestEmittedEventsCarryScope -v`
Expected: FAIL — emitted event scope is empty (fakeRunner/real runners don't set it yet; Request has no Scope field).

- [ ] **Step 3: Write minimal implementation**

Add `Scope string` to `Request` (json:"-"). In `Pipeline.Run`, in the per-scope loop set `hostReq.Scope = scopeKey` (alongside the existing `hostReq.Target`/`hostReq.ScanDir`). In `executeSpec`, set `Scope: req.Scope` where it constructs `run := Run{Scanner: name, Target: req.Target, Status: "running", ...}`. In `zap.go`/`openvas.go`/`vuls.go`, add `Scope: req.Scope` to their initial `Run{...}` literals. In `runRecon`, set `req.Scope` per tool before calling `executeSpec` (a local copy: `sfReq := req; sfReq.Scope = reconScopeKey(req.Target)` for subfinder/httpx; `nmapReq := req; nmapReq.Scope = reconHostScopeKey(req.Target, host)` per host). Update `fakeRunner.Run` to stamp `Scope: req.Scope`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/scanner/...`
Expected: PASS.

Add a web-layer test proving the crash-persisted record no longer collapses per-host same-named runs during live emit:

```go
// internal/web/deterministic_scan_test.go — TestUpsertDistinguishesLiveEmittedScopes
// Simulate two scanner_started events for scanner "nmap" with different Scope
// (recon:t:a vs recon:t:b) via upsertScannerRun; assert both are retained.
```

Run: `CGO_ENABLED=0 go test ./internal/web/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/types.go internal/scanner/pipeline.go internal/scanner/zap.go internal/scanner/openvas.go internal/scanner/vuls.go internal/scanner/recon.go internal/scanner/pipeline_test.go internal/web/deterministic_scan_test.go
git commit -m "feat(scanner): thread scope through Request so emitted events carry it"
```

---

### Task 3: Flatten the scan phase into deterministic task slots (still sequential)

**Files:**
- Modify: `internal/scanner/pipeline.go` (`Pipeline.Run` scan phase)
- Test: `internal/scanner/pipeline_test.go`

**Interfaces:**
- Consumes: everything above.
- Produces: an internal `scanTask` representation and an output-slot mechanism. Behavior and result order are byte-identical to today; this task only restructures so Task 4 can parallelize. `type scanTask struct { scope Scope; scopeKey string; runner Runner; slot int }`.

- [ ] **Step 1: Write the failing test**

Add a test asserting the CURRENT ordering guarantee is preserved after the refactor (a regression guard Task 4 will rely on):

```go
// append to internal/scanner/pipeline_test.go
func TestScanPhaseResultOrderStable(t *testing.T) {
	var seen []string
	p := &Pipeline{Runners: []Runner{
		fakeRunner{name: "nuclei", seen: &seen}, fakeRunner{name: "vuls", seen: &seen},
	}}
	p.reconFn = func(context.Context, Request, Config, EmitFunc) ([]Scope, []Run) {
		return []Scope{HostScope("a"), HostScope("b")}, nil
	}
	runs := p.Run(context.Background(), Request{Target: "t", ScanDir: t.TempDir()}, nil, nil)
	// Expect order: (a,nuclei),(a,vuls),(b,nuclei),(b,vuls)
	var got []string
	for _, r := range runs {
		got = append(got, r.Scope+"/"+r.Scanner)
	}
	want := []string{"host:a/nuclei", "host:a/vuls", "host:b/nuclei", "host:b/vuls"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}
```

(fakeRunners here have nil tracks → fail-open → both run per host.)

- [ ] **Step 2: Run test to verify it fails or passes**

Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run TestScanPhaseResultOrderStable -v`
Expected: PASS already (documents current order) — keep it; it becomes the guard for Task 4. If it FAILS, the current order differs from the expected literal; fix the expectation to the real current order before refactoring, then keep it stable.

- [ ] **Step 3: Refactor to slots (no behavior change)**

Rewrite the scan phase: first walk scopes×runners to build `[]scanTask` (skipping reused/skipped/not_applicable which are resolved inline into pre-filled output slots), assigning each executable task a `slot` index into a `results []Run` slice sized to the total task count. Execute tasks in order (still sequential), writing each result to `results[task.slot]`. Append `results` to `out` after recon runs. The resulting `out` order MUST match `TestScanPhaseResultOrderStable` and all existing tests.

> Keep the reuse / deselected-skip / classifier-not_applicable / cancellation decisions exactly where they are (they resolve to a Run without executing); only the EXECUTION of `runAttempt` results moves into the slot model. The simplest correct approach: build a `results` slice in scope×runner order, fill every slot (reused/skip/na/cancel inline, executable via runAttempt), so order is intrinsic to slot index.

- [ ] **Step 4: Run tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/scanner/...`
Expected: PASS — order guard + all existing tests.

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/pipeline.go internal/scanner/pipeline_test.go
git commit -m "refactor(scanner): flatten scan phase into ordered result slots"
```

---

### Task 4: Worker pool + heavy-tool exclusive lock

**Files:**
- Modify: `internal/scanner/pipeline.go` (execute the task slots via a bounded pool + heavy lock)
- Test: `internal/scanner/pipeline_test.go`

**Interfaces:**
- Consumes: `scanTask`/slots (Task 3), `Config.MaxWorkers`, `Runner.Descriptor().Weight`.
- Produces: concurrent execution of executable tasks bounded by `p.Config.MaxWorkers`, with a single exclusive lock acquired around a task whose `runner.Descriptor().Weight == WeightHeavy`. Results still written to pre-assigned slots → deterministic output order. Cancellation: on `ctx` cancel, not-yet-started tasks resolve to `cancelled` runs in their slots.

- [ ] **Step 1: Write the failing tests (deterministic, no -race)**

```go
// append to internal/scanner/pipeline_test.go

// concurrentFakeRunner records max observed concurrency (overall and heavy-only).
type concGauge struct {
	mu        sync.Mutex
	cur, max  int
	heavyCur  int
	heavyMax  int
}
func (g *concGauge) enter(heavy bool) {
	g.mu.Lock(); g.cur++; if g.cur > g.max { g.max = g.cur }
	if heavy { g.heavyCur++; if g.heavyCur > g.heavyMax { g.heavyMax = g.heavyCur } }
	g.mu.Unlock()
}
func (g *concGauge) leave(heavy bool) {
	g.mu.Lock(); g.cur--; if heavy { g.heavyCur-- }; g.mu.Unlock()
}

type gaugeRunner struct {
	name  string
	heavy bool
	g     *concGauge
}
func (r gaugeRunner) Name() string { return r.name }
func (r gaugeRunner) Descriptor() Descriptor {
	w := WeightLight
	if r.heavy { w = WeightHeavy }
	return Descriptor{Name: r.name, Phase: PhaseWeb, Weight: w}
}
func (r gaugeRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	r.g.enter(r.heavy)
	time.Sleep(20 * time.Millisecond) // widen the window deterministically
	r.g.leave(r.heavy)
	return Run{Scanner: r.name, Target: req.Target, Scope: req.Scope, Status: "completed"}
}

func TestSchedulerRespectsWorkerBoundAndHeavyLock(t *testing.T) {
	g := &concGauge{}
	// 6 light runners across 3 hosts, plus heavy runners, MaxWorkers=3.
	runners := []Runner{
		gaugeRunner{name: "l1", g: g}, gaugeRunner{name: "l2", g: g},
		gaugeRunner{name: "h1", heavy: true, g: g}, gaugeRunner{name: "h2", heavy: true, g: g},
	}
	p := &Pipeline{Config: Config{MaxWorkers: 3}, Runners: runners}
	p.reconFn = func(context.Context, Request, Config, EmitFunc) ([]Scope, []Run) {
		return []Scope{HostScope("a"), HostScope("b"), HostScope("c")}, nil
	}
	runs := p.Run(context.Background(), Request{Target: "t", ScanDir: t.TempDir()}, nil, nil)
	if g.max > 3 {
		t.Errorf("observed max concurrency %d > MaxWorkers 3", g.max)
	}
	if g.heavyMax > 1 {
		t.Errorf("observed max heavy concurrency %d > 1", g.heavyMax)
	}
	if g.max < 2 {
		t.Errorf("expected some parallelism, observed max %d", g.max)
	}
	if len(runs) != 3*len(runners) {
		t.Errorf("runs = %d, want %d", len(runs), 3*len(runners))
	}
}
```

(Ensure `sync` and `time` imported in the test file.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run TestSchedulerRespectsWorkerBoundAndHeavyLock -v`
Expected: FAIL — sequential execution gives `g.max == 1` (< 2), failing the parallelism assertion.

- [ ] **Step 3: Implement the pool + heavy lock**

Execute the executable task slots with:
- a buffered semaphore channel `sem := make(chan struct{}, max)` where `max = p.Config.MaxWorkers` (guard `< 1` → 1);
- a heavy lock `heavy := make(chan struct{}, 1)`;
- a `sync.WaitGroup`; launch one goroutine per executable task: acquire `sem`; if `runner.Descriptor().Weight == WeightHeavy` acquire `heavy` (release after); run `runAttempt`, stamp scope, write to `results[slot]`; release `sem`.
- Preserve cancellation: before acquiring, if `ctx.Err() != nil`, write a `cancelled` run to the slot instead of executing (and still `sem`-free). Reused/skip/na slots were already filled in Task 3 and are not launched.
- After `wg.Wait()`, append `results` in slot order.

> The heavy lock is a SEPARATE gate from the worker semaphore, so a heavy task holds one worker slot AND the exclusive heavy token; two heavy tasks can never overlap even if MaxWorkers > 1. Acquire `sem` before `heavy` consistently (same order everywhere) to avoid deadlock; never hold `heavy` while blocked on `sem`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/scanner/...`
Expected: PASS — worker-bound/heavy-lock test passes; order-stability test (Task 3) still passes (slots keep order); all existing tests pass.

Run twice more to shake out flakiness:
Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run 'TestScheduler|TestScanPhaseResultOrderStable' -count=5`
Expected: PASS all 5.

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/pipeline.go internal/scanner/pipeline_test.go
git commit -m "feat(scanner): run scan phase on a bounded worker pool with heavy-tool lock"
```

---

### Task 5: Whole-tree verification

**Files:**
- No source changes expected. Adjust a web test only if parallel emit ordering breaks a brittle ordering assertion (the report/record consumers should be order-independent; investigate if a test fails).

**Interfaces:**
- Consumes: everything above.
- Produces: green build + affected suites.

- [ ] **Step 1: Build + vet + gofmt**

Run: `CGO_ENABLED=0 go build ./... && gofmt -l internal/scanner/ internal/web/ internal/config/ && go vet ./internal/scanner/... ./internal/web/...`
Expected: build succeeds; gofmt prints nothing; vet clean.

- [ ] **Step 2: Affected suites (run repeatedly for flakiness)**

Run: `CGO_ENABLED=0 go test ./internal/scanner/... ./internal/web/... ./internal/reporting/... -count=3`
Expected: PASS all three, three times.

- [ ] **Step 3: Commit any fixups**

```bash
git add -A
git commit -m "test: stabilize for parallel scan execution"
```

(Skip if none needed.)

---

## Self-Review

**1. Spec coverage (Increment 4 = spec §4 bounded parallelism + heavy lock, §10 increment 4, + the deferred Increment-2 crash-resume residual):**
- MaxWorkers config + default 3 (§4) → Task 1. ✅
- Scope on emitted events / crash-resume residual (Increment-2 parked item) → Task 2. ✅
- Deterministic result order under parallelism (§7) → Task 3 (slots) + Task 4 (fill by slot). ✅
- Bounded worker pool + heavy-tool exclusive lock (§4) → Task 4. ✅
- Resume/skip/not_applicable/cancel preserved → Tasks 3–4. ✅

**2. Placeholder scan:** Tasks 1–4 have complete code/tests; Task 2's web test and Task 3's refactor describe exact shape + invariants (the refactor is mechanical: same decisions, slot-indexed output). Task 5 is verification. No TBDs.

**3. Type consistency:** `Config.MaxWorkers` (Task 1) used in Task 4. `Request.Scope` (Task 2) consumed by executeSpec/runners/recon. `scanTask`/slots (Task 3) consumed by Task 4's pool. `WeightHeavy` (Increment 1) gates the heavy lock.

## Notes / risks
- Highest-risk increment (concurrency + deadlock potential). Mitigations: consistent lock-acquire order (sem before heavy; never heavy while blocked on sem), deterministic output via slots, deterministic concurrency tests (no reliance on -race, which can't run on this Darwin host).
- Parallel emit interleaves live WS output across runners — acceptable (native output already interleaves per stream); only ensure the persisted `results` order is stable.
- Deferred to Increment 5: testssl on web track, Semgrep/Gitleaks/OSV SAST phase + source auto-fetch, trivy relocation to SAST.
- Pre-existing gap (not this increment): `scannerConfig` doesn't wire the Increment-2 recon tool paths (`XALGORIX_SUBFINDER_PATH` etc.) from `config.Config`; they use `applyDefaults` bare names. Worth wiring in a later cleanup.
