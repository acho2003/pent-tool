# Increment 5b: SAST Phase Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a source-code (SAST) phase: resolve source (git clone / provided path / none), introduce a single source scope, gate runners by scope kind, relocate trivy to scan the source, and add Semgrep, Gitleaks, and OSV runners with parsers.

**Architecture:** Recon produces host scopes; a new `resolveSourceScope` appends exactly one `ScopeSource` scope per scan (its `Target` is the resolved local source path, or empty when none). The scan loop branches on `Scope.Kind`: host scopes classify into tracks and write under `hosts/<host>/`; the source scope skips classification and writes under `source/`. Runner selection uses the previously-unused `Descriptor.Applies` predicate: host runners (nuclei, zap, testssl, openvas, vuls) apply only to host scopes; SAST runners (trivy, semgrep, gitleaks, osv) apply only to the source scope. Every non-matching (scope, tool) pair records `not_applicable`, satisfying the spec §7 "account for all scope×tool" contract. `commandSpec` gains an `okExit` set so tools that signal findings via a non-zero exit code (gitleaks, osv) still record `completed`. New parsers emit `semgrep:rule:file:line`, `gitleaks:rule:file:commit`, `osv:pkg:vulnID` (spec §6).

**Tech Stack:** Go 1.26, `internal/scanner` (runners, parsers, source resolution, scheduler gating), `internal/config` + `internal/web` (config plumbing), Dockerfile.

**Spec:** docs/superpowers/specs/2026-09-24-scanning-dag-pipeline-design.md — implements the SAST half of §10 increment 5, plus §4 (SAST phase), §5 (scope kinds), §6 (source IDs), §9 (tooling/config).

## Global Constraints

- **Go 1.26.** Darwin dev host: run tests with `CGO_ENABLED=0 go test` (CGO segfaults). NEVER use `go test -race` here.
- **Determinism:** output order is slot-based (`results[slot]`); source resolution is deterministic given the same inputs; git clone is I/O but its success/failure only flips the source scope's `Target`, not ordering.
- **SourceID convention:** `"<scanner>:...”`; SAST tools use `semgrep:rule:file:line`, `gitleaks:rule:file:commit`, `osv:pkg:vulnID` (spec §6). trivy keeps `trivy:id:target`.
- **Account for every scope×tool (spec §7):** every runner records exactly one terminal status per scope. A host runner on the source scope, and a SAST runner on a host scope, each record `not_applicable`. SAST runs once per scan because there is exactly one source scope.
- **Reporter whitelist:** none — `report_ai.go`'s `allowed` map is dynamic. Do NOT add a static whitelist.
- **Immutable artifacts / resume:** reuse terminal `(scope, scanner)` runs; never mutate sealed logs. The source scope resumes by (scope, scanner) like any other; a present `source/checkout/.git` is reused rather than re-cloned.
- **Mandatory gate every task:** `gofmt -l internal/` (touched files only; internal/agent/hooks*.go has PRE-EXISTING drift — out of scope), `CGO_ENABLED=0 go vet`, and `CGO_ENABLED=0 go test` on touched packages must be clean before a task is done.

---

## File Structure

- `internal/scanner/types.go` — add `SemgrepPath/GitleaksPath/OsvPath string` + `SemgrepTimeout/GitleaksTimeout/OsvTimeout time.Duration` to `scanner.Config`; grow `OrderedNames`.
- `internal/config/config.go` — matching `*Path`/`*TimeoutSec` fields + env wiring.
- `internal/web/deterministic_scan.go` — `scannerConfig` copies the new fields.
- `internal/scanner/source.go` (Create) — `isGitURL`, `sourceCheckoutDir`, `gitClone`, `resolveSourceScope`.
- `internal/scanner/pipeline.go` — `commandSpec.okExit` + executeSpec change; `runnerAppliesToScope` + `appliesToHost`/`appliesToSource`; `NewPipeline` Applies wiring + new runners; scan-loop branch on `Scope.Kind`; append source scope; buildTrivy fs-scan.
- `internal/scanner/semgrep.go`, `gitleaks.go`, `osv.go` (Create) — the three commandBuilders.
- `internal/scanner/parse.go` — `parseSemgrep`/`parseGitleaks`/`parseOSV` + `ParseRun` cases.
- `internal/scanner/parse_test.go`, `pipeline_test.go`, `descriptor_test.go`, `source_test.go` (Create) — tests.
- `Dockerfile` — add `osv-scanner` install layer; confirm semgrep present.

---

### Task 1: Config plumbing for semgrep/gitleaks/osv

**Files:**
- Modify: `internal/scanner/types.go` (Config fields)
- Modify: `internal/scanner/pipeline.go` (applyDefaults)
- Modify: `internal/config/config.go` (fields + env wiring)
- Modify: `internal/web/deterministic_scan.go` (scannerConfig)
- Test: `internal/web/deterministic_scan_test.go` (extend the existing wiring test)

**Interfaces:**
- Consumes: `envOr`/`envOrInt` (config.go); `applyDefaults` (pipeline.go).
- Produces: `scanner.Config.SemgrepPath/GitleaksPath/OsvPath` (string) and `SemgrepTimeout/GitleaksTimeout/OsvTimeout` (time.Duration), non-zero on the config returned by `scannerConfig`.

- [ ] **Step 1: Add fields to `scanner.Config`** (internal/scanner/types.go), beside the other `*Path`/`*Timeout` fields:

```go
	SemgrepPath  string
	GitleaksPath string
	OsvPath      string
```
```go
	SemgrepTimeout  time.Duration
	GitleaksTimeout time.Duration
	OsvTimeout      time.Duration
```

- [ ] **Step 2: Default them in `applyDefaults`** (internal/scanner/pipeline.go), mirroring the testssl defaults:

```go
	if cfg.SemgrepPath == "" {
		cfg.SemgrepPath = "semgrep"
	}
	if cfg.GitleaksPath == "" {
		cfg.GitleaksPath = "gitleaks"
	}
	if cfg.OsvPath == "" {
		cfg.OsvPath = "osv-scanner"
	}
```
```go
	if cfg.SemgrepTimeout <= 0 {
		cfg.SemgrepTimeout = 30 * time.Minute
	}
	if cfg.GitleaksTimeout <= 0 {
		cfg.GitleaksTimeout = 15 * time.Minute
	}
	if cfg.OsvTimeout <= 0 {
		cfg.OsvTimeout = 15 * time.Minute
	}
```

- [ ] **Step 3: Add fields + env wiring to `config.Config`** (internal/config/config.go):

```go
	SemgrepPath        string
	GitleaksPath       string
	OsvPath            string
	SemgrepTimeoutSec  int
	GitleaksTimeoutSec int
	OsvTimeoutSec      int
```
In the constructor (beside TestsslPath from 5a):
```go
	SemgrepPath:        envOr("XALGORIX_SEMGREP_PATH", "semgrep"),
	GitleaksPath:       envOr("XALGORIX_GITLEAKS_PATH", "gitleaks"),
	OsvPath:            envOr("XALGORIX_OSV_PATH", "osv-scanner"),
	SemgrepTimeoutSec:  envOrInt("XALGORIX_SEMGREP_TIMEOUT_SECONDS", 1800),
	GitleaksTimeoutSec: envOrInt("XALGORIX_GITLEAKS_TIMEOUT_SECONDS", 900),
	OsvTimeoutSec:      envOrInt("XALGORIX_OSV_TIMEOUT_SECONDS", 900),
```

- [ ] **Step 4: Thread through `scannerConfig`** (internal/web/deterministic_scan.go):

```go
		SemgrepPath: cfg.SemgrepPath, GitleaksPath: cfg.GitleaksPath, OsvPath: cfg.OsvPath,
```
```go
		SemgrepTimeout:  time.Duration(cfg.SemgrepTimeoutSec) * time.Second,
		GitleaksTimeout: time.Duration(cfg.GitleaksTimeoutSec) * time.Second,
		OsvTimeout:      time.Duration(cfg.OsvTimeoutSec) * time.Second,
```

- [ ] **Step 5: Extend the wiring test** in internal/web/deterministic_scan_test.go (the 5a `TestScannerConfigThreads...` test). Add assertions that with the env vars set, `scannerConfig` yields the expected semgrep/gitleaks/osv paths and non-zero timeouts. Follow the exact style already there.

- [ ] **Step 6: Gate + commit**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && gofmt -l internal/scanner/ internal/web/ internal/config/ && CGO_ENABLED=0 go vet ./internal/scanner/... ./internal/web/... ./internal/config/... && CGO_ENABLED=0 go test ./internal/scanner/... ./internal/web/... ./internal/config/...`
Expected: clean.

```bash
git add internal/scanner/types.go internal/scanner/pipeline.go internal/config/config.go internal/web/deterministic_scan.go internal/web/deterministic_scan_test.go
git commit -m "feat(config): thread semgrep/gitleaks/osv paths and timeouts to scanner"
```

---

### Task 2: SAST scope machinery (source resolution + scope-kind gating + trivy relocation)

This is the core, interdependent change. Implement all of it in one task.

**Files:**
- Create: `internal/scanner/source.go`
- Create: `internal/scanner/source_test.go`
- Modify: `internal/scanner/pipeline.go` (commandSpec.okExit + executeSpec; runnerAppliesToScope + Applies helpers; NewPipeline Applies wiring; scan-loop branch; append source scope; buildTrivy)
- Modify: `internal/scanner/pipeline_test.go` (new tests + reconcile existing)

**Interfaces:**
- Consumes: `Scope`, `ScopeSource`, `ScopeHost`, `SourceRef` (scope.go); `Descriptor.Applies` (descriptor.go); `Request`, `Config`, `Run`, `EmitFunc`.
- Produces:
  - `resolveSourceScope(ctx context.Context, req Request, cfg Config, emit EmitFunc) Scope` — always returns one `ScopeSource` scope; `Target`/`Source.Path` empty when no source resolved.
  - `runnerAppliesToScope(d Descriptor, sc Scope) bool`.
  - `appliesToHost(Scope) bool`, `appliesToSource(Scope) bool`.
  - `commandSpec.okExit map[int]bool` (exit codes to treat as success).

- [ ] **Step 1: Add `okExit` to `commandSpec` and honor it in `executeSpec`**

In `commandSpec` (pipeline.go), add:
```go
	// okExit lists non-zero process exit codes to treat as success. Some tools
	// (gitleaks, osv-scanner) signal "findings present" with a non-zero code; a
	// completed run must still parse. nil means only exit 0 succeeds.
	okExit map[int]bool
```
In `executeSpec`, change the non-zero-exit `default` branch (currently `run.Status, run.Reason = "failed", err.Error()`):
```go
		default:
			if spec.okExit != nil && spec.okExit[run.ExitCode] {
				run.Status = "completed"
			} else {
				run.Status, run.Reason = "failed", err.Error()
			}
```
(Leave the `ctx.Err()` cancelled and `DeadlineExceeded` timeout cases unchanged — they precede the default and must still win.)

- [ ] **Step 2: Write the failing test for scope-kind gating**

In pipeline_test.go add a test proving host runners are not_applicable on a source scope and vice versa. Use fakeRunner with an `applies func(Scope) bool` field (add the field to fakeRunner and return it from its Descriptor()). Minimal:

```go
func TestScopeKindGating(t *testing.T) {
	if runnerAppliesToScope(Descriptor{Applies: appliesToHost}, Scope{Kind: ScopeSource}) {
		t.Error("host runner must not apply to source scope")
	}
	if !runnerAppliesToScope(Descriptor{Applies: appliesToSource}, Scope{Kind: ScopeSource}) {
		t.Error("source runner must apply to source scope")
	}
	if runnerAppliesToScope(Descriptor{Applies: appliesToSource}, Scope{Kind: ScopeHost, Tracks: []Track{TrackWeb}}) {
		t.Error("source runner must not apply to host scope")
	}
	// host runner on a host scope still respects tracks
	d := Descriptor{Applies: appliesToHost, Tracks: []Track{TrackServer}}
	if runnerAppliesToScope(d, Scope{Kind: ScopeHost, Tracks: []Track{TrackWeb}}) {
		t.Error("host runner with mismatched track must not apply")
	}
	if !runnerAppliesToScope(d, Scope{Kind: ScopeHost, Tracks: []Track{TrackServer}}) {
		t.Error("host runner with matching track must apply")
	}
}
```

- [ ] **Step 3: Run it to verify it fails**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/scanner/ -run TestScopeKindGating`
Expected: FAIL — `undefined: runnerAppliesToScope` / `appliesToHost` / `appliesToSource`.

- [ ] **Step 4: Implement the gating helpers** (pipeline.go, beside runnerAppliesToTracks):

```go
// appliesToHost / appliesToSource are the Descriptor.Applies predicates that bind
// a runner to one scope kind. Host runners scan discovered hosts; SAST runners
// scan the single source scope.
func appliesToHost(s Scope) bool   { return s.Kind == ScopeHost }
func appliesToSource(s Scope) bool { return s.Kind == ScopeSource }

// runnerAppliesToScope decides whether a runner attempts a given scope. The
// Applies predicate gates by scope kind; host scopes additionally gate by the
// classified tracks. A source scope that passes Applies always runs (no tracks).
func runnerAppliesToScope(d Descriptor, sc Scope) bool {
	if d.Applies != nil && !d.Applies(sc) {
		return false
	}
	if sc.Kind == ScopeHost {
		return runnerAppliesToTracks(d, sc.Tracks)
	}
	return true
}
```

- [ ] **Step 5: Run the gating test to verify it passes**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/scanner/ -run TestScopeKindGating`
Expected: PASS.

- [ ] **Step 6: Implement source resolution** — Create `internal/scanner/source.go`:

```go
package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// sourceScopeID is the stable id of the single per-scan source scope.
const sourceScopeID = "source:main"

// sourceCheckoutDir is where a cloned repository lands under the scan dir.
func sourceCheckoutDir(scanDir string) string {
	return filepath.Join(scanDir, "source", "checkout")
}

// isGitURL reports whether target is a git repository URL we should clone.
// Kept conservative so ordinary web targets are never mistaken for repos.
func isGitURL(target string) bool {
	t := strings.TrimSpace(target)
	if strings.HasPrefix(t, "git@") || strings.HasPrefix(t, "git://") {
		return true
	}
	return strings.HasSuffix(t, ".git")
}

// gitClone shallow-clones url into dir. The caller ensures dir does not already
// hold a checkout. Bounded by a fixed timeout derived from ctx.
func gitClone(ctx context.Context, url, dir string) error {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if err := os.MkdirAll(filepath.Dir(dir), 0o750); err != nil {
		return err
	}
	cmd := exec.CommandContext(cctx, "git", "clone", "--depth", "1", url, dir)
	return cmd.Run()
}

// resolveSourceScope returns the single source scope for a scan. Its Target is a
// local source path when one is resolvable — a provided filesystem dir, a
// provided repository URL, or a git-URL target (cloned) — and empty otherwise,
// in which case every SAST runner records not_applicable on it.
func resolveSourceScope(ctx context.Context, req Request, cfg Config, emit EmitFunc) Scope {
	sc := Scope{ID: sourceScopeID, Kind: ScopeSource}

	// 1. Provided local filesystem directory.
	if strings.EqualFold(req.Artifact.Kind, "filesystem") {
		if ref := strings.TrimSpace(req.Artifact.Ref); ref != "" {
			if fi, err := os.Stat(ref); err == nil && fi.IsDir() {
				sc.Target = ref
				sc.Source = SourceRef{Path: ref, Provenance: "provided:filesystem"}
				return sc
			}
		}
	}

	// 2. Repository URL (from artifact ref or a git-URL target) -> clone.
	url := ""
	if strings.EqualFold(req.Artifact.Kind, "repository") {
		url = strings.TrimSpace(req.Artifact.Ref)
	} else if isGitURL(req.Target) {
		url = strings.TrimSpace(req.Target)
	}
	if url != "" {
		dir := sourceCheckoutDir(req.ScanDir)
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			sc.Target = dir // resume: reuse existing checkout
			sc.Source = SourceRef{Path: dir, Provenance: "clone:" + url}
			return sc
		}
		if err := gitClone(ctx, url, dir); err == nil {
			sc.Target = dir
			sc.Source = SourceRef{Path: dir, Provenance: "clone:" + url}
			return sc
		}
	}

	// 3. No source resolved: Target stays empty -> SAST tools not_applicable.
	return sc
}
```

- [ ] **Step 7: Write source-resolution tests** — Create `internal/scanner/source_test.go`:

```go
package scanner

import (
	"context"
	"path/filepath"
	"testing"
)

func TestResolveSourceScopeFilesystem(t *testing.T) {
	dir := t.TempDir()
	req := Request{Artifact: Artifact{Kind: "filesystem", Ref: dir}, ScanDir: t.TempDir()}
	sc := resolveSourceScope(context.Background(), req, Config{}, nil)
	if sc.Kind != ScopeSource {
		t.Fatalf("kind = %q", sc.Kind)
	}
	if sc.Target != dir {
		t.Errorf("Target = %q, want %q", sc.Target, dir)
	}
}

func TestResolveSourceScopeNoSource(t *testing.T) {
	req := Request{Target: "https://example.com/", ScanDir: t.TempDir()}
	sc := resolveSourceScope(context.Background(), req, Config{}, nil)
	if sc.Kind != ScopeSource || sc.ID != sourceScopeID {
		t.Fatalf("unexpected scope %+v", sc)
	}
	if sc.Target != "" {
		t.Errorf("expected empty Target for unresolved source, got %q", sc.Target)
	}
}

func TestResolveSourceScopeReusesCheckout(t *testing.T) {
	scanDir := t.TempDir()
	dir := sourceCheckoutDir(scanDir)
	if err := mkGitDir(dir); err != nil { // helper: create dir + dir/.git
		t.Fatal(err)
	}
	req := Request{Target: "https://github.com/x/y.git", ScanDir: scanDir}
	sc := resolveSourceScope(context.Background(), req, Config{}, nil)
	if sc.Target != dir {
		t.Errorf("expected reused checkout %q, got %q", dir, sc.Target)
	}
}

func mkGitDir(dir string) error {
	if err := mkdirAll(filepath.Join(dir, ".git")); err != nil {
		return err
	}
	return nil
}
```
Implement the tiny `mkdirAll` helper in the test file (`os.MkdirAll(p, 0o750)`), or inline `os.MkdirAll` directly — keep it simple and importable. `isGitURL` is exercised transitively; add a direct `TestIsGitURL` table if desired (`.git` suffix true, `git@` true, `https://x/` false, plain host false).

- [ ] **Step 8: Wire Applies into `NewPipeline` and add the source scope to the scan**

In `NewPipeline`, give every existing runner an Applies predicate and relocate trivy:
```go
	return &Pipeline{Config: cfg, reconFn: runRecon, Runners: []Runner{
		commandRunner{name: "nuclei", desc: Descriptor{Name: "nuclei", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightLight, Applies: appliesToHost}, build: buildNuclei},
		zapRunner{},
		commandRunner{name: "testssl", desc: Descriptor{Name: "testssl", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightLight, Applies: appliesToHost}, build: buildTestssl},
		openVASRunner{},
		vulsRunner{},
		commandRunner{name: "trivy", desc: Descriptor{Name: "trivy", Phase: PhaseSAST, Weight: WeightLight, Applies: appliesToSource}, build: buildTrivy},
	}}
```
Note: trivy moves to the END (it is a SAST tool now; group SAST tools last). zapRunner/openVASRunner/vulsRunner are bespoke structs — update their `Descriptor()` methods (zap.go/openvas.go/vuls.go) to include `Applies: appliesToHost`.

- [ ] **Step 9: Branch the scan loop on scope kind and append the source scope**

In `Pipeline.Run`, after the host-scope set is finalized (the `if len(scopes) == 0 { scopes = []Scope{HostScope(req.Target)} }` degrade line), append exactly one source scope:
```go
	scopes = append(scopes, resolveSourceScope(ctx, req, p.Config, safeEmit))
```
Then in the per-scope loop, replace the host-only preamble with a kind branch. Rename `hostReq` to `scopeReq`:
```go
	for _, sc := range scopes {
		scopeKey := sc.Key()
		scopeReq := req
		scopeReq.Scope = scopeKey
		if sc.Kind == ScopeSource {
			scopeReq.Target = sc.Target // resolved source path or "" (SAST tools -> not_applicable)
			scopeReq.ScanDir = filepath.Join(req.ScanDir, "source")
		} else {
			sc.Tracks = Classify(sc.Evidence)
			if len(sc.Tracks) == 0 {
				sc.Tracks = []Track{TrackWeb, TrackServer} // fail open (Increment 3)
			}
			scopeReq.Target = sc.Target
			scopeReq.ScanDir = filepath.Join(req.ScanDir, "hosts", sanitizeHost(sc.Target))
		}
		for i, runner := range p.Runners {
			if old, ok := byKey[resumeKey(scopeKey, runner.Name())]; ok {
				results[slot] = old
				slot++
				continue
			}
			if len(req.Scanners) > 0 && !slices.Contains(req.Scanners, runner.Name()) {
				results[slot] = skippedRun(runner.Name(), scopeKey, scopeReq, safeEmit)
				slot++
				continue
			}
			if !runnerAppliesToScope(runner.Descriptor(), sc) {
				results[slot] = notApplicableClassifierRun(runner.Name(), scopeKey, scopeReq, safeEmit)
				slot++
				continue
			}
			if err := ctx.Err(); err != nil {
				for j, rest := range p.Runners[i:] {
					results[slot+j] = cancelledRun(rest.Name(), scopeKey, scopeReq, err, safeEmit)
				}
				slot += len(p.Runners) - i
				break
			}
			tasks = append(tasks, scanTask{runner: runner, scopeKey: scopeKey, hostReq: scopeReq, slot: slot})
			slot++
		}
	}
```
The `results` slice sizing (`make([]Run, len(scopes)*len(p.Runners))`) is unchanged and now correctly includes the source scope's row because it was appended to `scopes` before sizing. IMPORTANT: append the source scope BEFORE `results := make(...)` — move the append above the results allocation.

- [ ] **Step 10: Generalize the not_applicable reason**

`notApplicableClassifierRun`'s hardcoded reason ("host tracks do not include this scanner's track") is now also used for scope-kind mismatches. Change the reason to a scope-generic string, e.g. `"scanner does not apply to this scope"`. Update any test asserting the old text (grep: `host tracks do not include`).

- [ ] **Step 11: Relocate trivy's command to scan the source path** (buildTrivy, pipeline.go):

```go
func buildTrivy(req Request, cfg Config) commandSpec {
	// SAST source scope: filesystem-scan the resolved source directory.
	if src := strings.TrimSpace(req.Target); src != "" {
		artifact := filepath.Join(req.ScanDir, "scanner-output", "trivy", "results.json")
		args := []string{"fs", "--format", "json", "--output", artifact, "--scanners", "vuln,misconfig,secret,license", src}
		return commandSpec{path: cfg.TrivyPath, args: args, artifact: artifact, timeout: cfg.TrivyTimeout}
	}
	// Fallback: artifact-based scan (image/sbom/etc.) when no source path.
	kind := strings.ToLower(strings.TrimSpace(req.Artifact.Kind))
	ref := strings.TrimSpace(req.Artifact.Ref)
	if kind == "" || ref == "" {
		return commandSpec{notApp: "Trivy requires a source path or artifact.kind/ref", timeout: cfg.TrivyTimeout}
	}
	cmd := map[string]string{"filesystem": "fs", "repository": "repo", "image": "image", "sbom": "sbom"}[kind]
	if cmd == "" {
		return commandSpec{notApp: "unsupported Trivy artifact kind: " + kind, timeout: cfg.TrivyTimeout}
	}
	artifact := filepath.Join(req.ScanDir, "scanner-output", "trivy", "results.json")
	args := []string{cmd, "--format", "json", "--output", artifact}
	if cmd != "sbom" {
		args = append(args, "--scanners", "vuln,misconfig,secret,license")
	}
	args = append(args, ref)
	return commandSpec{path: cfg.TrivyPath, args: args, artifact: artifact, timeout: cfg.TrivyTimeout}
}
```

- [ ] **Step 12: Add an integration test for the source scope in the fan-out**

In pipeline_test.go, add a test that runs a `NewPipeline`-style pipeline (or a `&Pipeline{}` with fakeRunners carrying Applies predicates) over a stub recon returning one host scope, and asserts: (a) the results include a source-scope row for each runner; (b) host runners are `not_applicable` on the source scope; (c) a source runner is `not_applicable` on the host scope. Since the real runners need binaries, prefer fakeRunners with `applies` set to `appliesToHost`/`appliesToSource`. Confirm the total result count is `(numHostScopes + 1) * numRunners`.

- [ ] **Step 13: Reconcile existing pipeline tests**

Run the full scanner suite. The source scope now adds one scope to every `NewPipeline`-based run, so any test asserting an exact total run count, or that trivy runs per-host, will change:
- trivy is now `not_applicable` on host scopes and runs (or is not_applicable) only on the source scope. A test expecting trivy `completed`/attempted per host must be updated.
- Total runs = `(hosts + 1) * len(p.Runners)`.
Search: `grep -rn "trivy\|len(scopes)\|len(runs)\|len(p.Runners)" internal/scanner/*_test.go`. Update each and LIST them in the report.

- [ ] **Step 14: Gate + commit**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && gofmt -l internal/scanner/ && CGO_ENABLED=0 go vet ./internal/scanner/... && CGO_ENABLED=0 go test ./internal/scanner/... -count=2`
Expected: clean; twice.

```bash
git add internal/scanner/source.go internal/scanner/source_test.go internal/scanner/pipeline.go internal/scanner/pipeline_test.go internal/scanner/zap.go internal/scanner/openvas.go internal/scanner/vuls.go
git commit -m "feat(scanner): add SAST source scope with scope-kind gating and trivy relocation"
```

---

### Task 3: Semgrep runner + parser

**Files:**
- Create: `internal/scanner/semgrep.go`
- Modify: `internal/scanner/pipeline.go` (register runner), `internal/scanner/types.go` (OrderedNames), `internal/scanner/parse.go` (parseSemgrep + case), `internal/scanner/descriptor_test.go`
- Test: `internal/scanner/semgrep_test.go` (Create), `internal/scanner/parse_test.go`

**Interfaces:**
- Consumes: `commandRunner`, `commandSpec`, `appliesToSource`, `PhaseSAST`, `WeightLight`.
- Produces: `buildSemgrep(Request, Config) commandSpec`; runner `"semgrep"` `{Phase: PhaseSAST, Weight: WeightLight, Applies: appliesToSource}`; `parseSemgrep(string) ([]Finding, error)`.

- [ ] **Step 1: Write failing tests** — Create `internal/scanner/semgrep_test.go`:

```go
package scanner

import (
	"strings"
	"testing"
	"time"
)

func TestBuildSemgrepCommand(t *testing.T) {
	req := Request{Target: "/src/app", ScanDir: t.TempDir()}
	spec := buildSemgrep(req, Config{SemgrepPath: "semgrep", SemgrepTimeout: time.Minute})
	if spec.path != "semgrep" || spec.args[len(spec.args)-1] != "/src/app" {
		t.Fatalf("unexpected spec %+v", spec)
	}
}

func TestBuildSemgrepNoSource(t *testing.T) {
	spec := buildSemgrep(Request{ScanDir: t.TempDir()}, Config{SemgrepPath: "semgrep", SemgrepTimeout: time.Minute})
	if spec.notApp == "" {
		t.Fatalf("expected notApp when no source, got %+v", spec)
	}
}
```
And in parse_test.go add `TestParseSemgrepFindings`:
```go
func TestParseSemgrepFindings(t *testing.T) {
	body := `{"results":[{"check_id":"go.lang.security.audit.xss","path":"web/h.go","start":{"line":42},"extra":{"message":"XSS","severity":"ERROR"}}]}`
	p := writeFixture(t, "results.json", body)
	got, err := ParseRun(Run{Scanner: "semgrep", ArtifactPath: p})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SourceID != "semgrep:go.lang.security.audit.xss:web/h.go:42" {
		t.Fatalf("parsed %#v", got)
	}
	if got[0].Severity != "high" {
		t.Errorf("severity = %q, want high", got[0].Severity)
	}
}
```

- [ ] **Step 2: Verify they fail**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/scanner/ -run 'TestBuildSemgrep|TestParseSemgrep'`
Expected: FAIL (undefined buildSemgrep; unsupported scanner "semgrep").

- [ ] **Step 3: Implement `buildSemgrep`** — Create `internal/scanner/semgrep.go`:

```go
package scanner

import (
	"path/filepath"
	"strings"
)

// buildSemgrep runs semgrep's auto ruleset over the resolved source directory.
// semgrep exits 0 whether or not it finds issues (no --error), so no okExit is
// needed. --config auto fetches the registry ruleset; offline scans yield a
// failed run and no findings, which is acceptable (best-effort SAST).
func buildSemgrep(req Request, cfg Config) commandSpec {
	src := strings.TrimSpace(req.Target)
	if src == "" {
		return commandSpec{notApp: "semgrep requires a source path", timeout: cfg.SemgrepTimeout}
	}
	artifact := filepath.Join(req.ScanDir, "scanner-output", "semgrep", "results.json")
	args := []string{"scan", "--config", "auto", "--json", "--output", artifact, "--quiet", src}
	return commandSpec{path: cfg.SemgrepPath, args: args, artifact: artifact, timeout: cfg.SemgrepTimeout}
}
```

- [ ] **Step 4: Implement `parseSemgrep` + case** (parse.go):

```go
	case "semgrep":
		return parseSemgrep(run.ArtifactPath)
```
```go
// parseSemgrep reads semgrep --json output. SourceID is semgrep:rule:file:line.
func parseSemgrep(path string) ([]Finding, error) {
	var root map[string]any
	if err := readJSON(path, &root); err != nil {
		return nil, err
	}
	var out []Finding
	for _, rv := range array(root["results"]) {
		r, _ := rv.(map[string]any)
		rule := str(r["check_id"])
		file := str(r["path"])
		start, _ := r["start"].(map[string]any)
		line := str(start["line"])
		extra, _ := r["extra"].(map[string]any)
		out = append(out, Finding{
			SourceID:    "semgrep:" + rule + ":" + file + ":" + line,
			Scanner:     "semgrep",
			Title:       firstNonEmpty(rule, "semgrep finding"),
			Severity:    semgrepSeverity(str(extra["severity"])),
			Target:      file,
			Endpoint:    file + ":" + line,
			Description: str(extra["message"]),
		})
	}
	return out, nil
}

// semgrepSeverity maps semgrep's ERROR/WARNING/INFO to the shared scale.
func semgrepSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ERROR":
		return "high"
	case "WARNING":
		return "medium"
	default:
		return "low"
	}
}
```

- [ ] **Step 5: Register the runner** — add to `NewPipeline` slice (group with SAST tools, before or after trivy):
```go
		commandRunner{name: "semgrep", desc: Descriptor{Name: "semgrep", Phase: PhaseSAST, Weight: WeightLight, Applies: appliesToSource}, build: buildSemgrep},
```
Add `"semgrep"` to `OrderedNames` in the matching relative position; add `"semgrep": {phase: PhaseSAST, weight: WeightLight}` to the descriptor_test expected map. Update any total-count assertion (now 7 runners).

- [ ] **Step 6: Verify tests pass + gate + commit**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && gofmt -l internal/scanner/ && CGO_ENABLED=0 go vet ./internal/scanner/... && CGO_ENABLED=0 go test ./internal/scanner/...`
Expected: PASS.
```bash
git add internal/scanner/semgrep.go internal/scanner/semgrep_test.go internal/scanner/pipeline.go internal/scanner/types.go internal/scanner/parse.go internal/scanner/parse_test.go internal/scanner/descriptor_test.go
git commit -m "feat(scanner): add semgrep SAST runner and parser"
```

---

### Task 4: Gitleaks runner + parser

**Files:**
- Create: `internal/scanner/gitleaks.go`, `internal/scanner/gitleaks_test.go`
- Modify: pipeline.go, types.go, parse.go, parse_test.go, descriptor_test.go

**Interfaces:**
- Produces: `buildGitleaks(Request, Config) commandSpec` (uses `okExit`); runner `"gitleaks"` `{Phase: PhaseSAST, Weight: WeightLight, Applies: appliesToSource}`; `parseGitleaks(string) ([]Finding, error)`.

- [ ] **Step 1: Failing tests** — `gitleaks_test.go`:
```go
package scanner

import (
	"testing"
	"time"
)

func TestBuildGitleaksCommand(t *testing.T) {
	req := Request{Target: "/src/app", ScanDir: t.TempDir()}
	spec := buildGitleaks(req, Config{GitleaksPath: "gitleaks", GitleaksTimeout: time.Minute})
	if spec.path != "gitleaks" {
		t.Fatalf("path %q", spec.path)
	}
	if spec.okExit == nil || !spec.okExit[1] {
		t.Errorf("gitleaks must treat exit 1 (leaks found) as success: %+v", spec.okExit)
	}
}

func TestBuildGitleaksNoSource(t *testing.T) {
	spec := buildGitleaks(Request{ScanDir: t.TempDir()}, Config{GitleaksPath: "gitleaks", GitleaksTimeout: time.Minute})
	if spec.notApp == "" {
		t.Fatalf("expected notApp, got %+v", spec)
	}
}
```
parse_test.go add `TestParseGitleaksFindings`:
```go
func TestParseGitleaksFindings(t *testing.T) {
	body := `[{"RuleID":"generic-api-key","File":"config.py","Commit":"abc123","StartLine":5,"Description":"API key"}]`
	p := writeFixture(t, "results.json", body)
	got, err := ParseRun(Run{Scanner: "gitleaks", ArtifactPath: p})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SourceID != "gitleaks:generic-api-key:config.py:abc123" {
		t.Fatalf("parsed %#v", got)
	}
}
```

- [ ] **Step 2: Verify fail**, then implement.

- [ ] **Step 3: Implement `buildGitleaks`** — `gitleaks.go`:
```go
package scanner

import (
	"path/filepath"
	"strings"
)

// buildGitleaks scans the source working tree for secrets. --no-git scans files
// directly so a provided (non-repo) directory works; --exit-code and okExit both
// ensure a "leaks found" run still records completed. Report is written even on a
// non-zero exit.
func buildGitleaks(req Request, cfg Config) commandSpec {
	src := strings.TrimSpace(req.Target)
	if src == "" {
		return commandSpec{notApp: "gitleaks requires a source path", timeout: cfg.GitleaksTimeout}
	}
	artifact := filepath.Join(req.ScanDir, "scanner-output", "gitleaks", "results.json")
	args := []string{"detect", "--source", src, "--no-git", "--report-format", "json", "--report-path", artifact, "--no-banner", "--exit-code", "1"}
	return commandSpec{path: cfg.GitleaksPath, args: args, artifact: artifact, timeout: cfg.GitleaksTimeout, okExit: map[int]bool{1: true}}
}
```

- [ ] **Step 4: Implement `parseGitleaks` + case** (parse.go):
```go
	case "gitleaks":
		return parseGitleaks(run.ArtifactPath)
```
```go
// parseGitleaks reads gitleaks' JSON array. Secrets have no native severity;
// they are reported high. SourceID is gitleaks:rule:file:commit.
func parseGitleaks(path string) ([]Finding, error) {
	var entries []map[string]any
	if err := readJSON(path, &entries); err != nil {
		return nil, err
	}
	var out []Finding
	for _, m := range entries {
		rule := str(m["RuleID"])
		file := str(m["File"])
		commit := str(m["Commit"])
		out = append(out, Finding{
			SourceID:    "gitleaks:" + rule + ":" + file + ":" + commit,
			Scanner:     "gitleaks",
			Title:       firstNonEmpty(rule, "secret"),
			Severity:    "high",
			Target:      file,
			Endpoint:    file + ":" + str(m["StartLine"]),
			Description: firstNonEmpty(str(m["Description"]), "secret detected"),
		})
	}
	return out, nil
}
```

- [ ] **Step 5: Register** (NewPipeline + OrderedNames + descriptor_test; now 8 runners). Same shape as Task 3 Step 5, name `"gitleaks"`.

- [ ] **Step 6: Gate + commit**
```bash
git add internal/scanner/gitleaks.go internal/scanner/gitleaks_test.go internal/scanner/pipeline.go internal/scanner/types.go internal/scanner/parse.go internal/scanner/parse_test.go internal/scanner/descriptor_test.go
git commit -m "feat(scanner): add gitleaks SAST runner and parser"
```

---

### Task 5: OSV runner + parser

**Files:**
- Create: `internal/scanner/osv.go`, `internal/scanner/osv_test.go`
- Modify: pipeline.go, types.go, parse.go, parse_test.go, descriptor_test.go

**Interfaces:**
- Produces: `buildOSV(Request, Config) commandSpec` (uses `okExit`); runner `"osv"` `{Phase: PhaseSAST, Weight: WeightLight, Applies: appliesToSource}`; `parseOSV(string) ([]Finding, error)`.

- [ ] **Step 1: Failing tests** — `osv_test.go`:
```go
package scanner

import (
	"testing"
	"time"
)

func TestBuildOSVCommand(t *testing.T) {
	req := Request{Target: "/src/app", ScanDir: t.TempDir()}
	spec := buildOSV(req, Config{OsvPath: "osv-scanner", OsvTimeout: time.Minute})
	if spec.path != "osv-scanner" {
		t.Fatalf("path %q", spec.path)
	}
	if spec.okExit == nil || !spec.okExit[1] {
		t.Errorf("osv must treat exit 1 (vulns found) as success: %+v", spec.okExit)
	}
}

func TestBuildOSVNoSource(t *testing.T) {
	spec := buildOSV(Request{ScanDir: t.TempDir()}, Config{OsvPath: "osv-scanner", OsvTimeout: time.Minute})
	if spec.notApp == "" {
		t.Fatalf("expected notApp, got %+v", spec)
	}
}
```
parse_test.go add `TestParseOSVFindings`:
```go
func TestParseOSVFindings(t *testing.T) {
	body := `{"results":[{"source":{"path":"go.mod"},"packages":[{"package":{"name":"golang.org/x/net"},"vulnerabilities":[{"id":"GHSA-vvpx","summary":"DoS","aliases":["CVE-2023-44487"]}]}]}]}`
	p := writeFixture(t, "results.json", body)
	got, err := ParseRun(Run{Scanner: "osv", ArtifactPath: p})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SourceID != "osv:golang.org/x/net:GHSA-vvpx" {
		t.Fatalf("parsed %#v", got)
	}
	if got[0].CVE != "CVE-2023-44487" {
		t.Errorf("CVE = %q", got[0].CVE)
	}
}
```

- [ ] **Step 2: Verify fail**, then implement.

- [ ] **Step 3: Implement `buildOSV`** — `osv.go`:
```go
package scanner

import (
	"path/filepath"
	"strings"
)

// buildOSV scans the source tree's dependency manifests. osv-scanner exits 1 when
// it finds vulnerabilities, so okExit={1} keeps such a run completed.
// NOTE: verify the subcommand against the installed osv-scanner version; v1 uses
// `osv-scanner --format json -r <dir>`, v2 uses `osv-scanner scan ...`.
func buildOSV(req Request, cfg Config) commandSpec {
	src := strings.TrimSpace(req.Target)
	if src == "" {
		return commandSpec{notApp: "osv-scanner requires a source path", timeout: cfg.OsvTimeout}
	}
	artifact := filepath.Join(req.ScanDir, "scanner-output", "osv", "results.json")
	args := []string{"--format", "json", "--output", artifact, "-r", src}
	return commandSpec{path: cfg.OsvPath, args: args, artifact: artifact, timeout: cfg.OsvTimeout, okExit: map[int]bool{1: true}}
}
```

- [ ] **Step 4: Implement `parseOSV` + case** (parse.go):
```go
	case "osv":
		return parseOSV(run.ArtifactPath)
```
```go
// parseOSV reads osv-scanner --format json. SourceID is osv:pkg:vulnID; the CVE
// is taken from the first CVE alias when present.
func parseOSV(path string) ([]Finding, error) {
	var root map[string]any
	if err := readJSON(path, &root); err != nil {
		return nil, err
	}
	var out []Finding
	for _, rv := range array(root["results"]) {
		r, _ := rv.(map[string]any)
		src, _ := r["source"].(map[string]any)
		srcPath := str(src["path"])
		for _, pv := range array(r["packages"]) {
			pkgObj, _ := pv.(map[string]any)
			pkg, _ := pkgObj["package"].(map[string]any)
			name := str(pkg["name"])
			for _, vv := range array(pkgObj["vulnerabilities"]) {
				v, _ := vv.(map[string]any)
				id := str(v["id"])
				cve := ""
				for _, a := range array(v["aliases"]) {
					if c := asCVE(str(a)); c != "" {
						cve = c
						break
					}
				}
				out = append(out, Finding{
					SourceID:    "osv:" + name + ":" + id,
					Scanner:     "osv",
					Title:       firstNonEmpty(id, name),
					Severity:    "medium",
					Target:      name,
					Endpoint:    srcPath,
					Description: str(v["summary"]),
					CVE:         cve,
				})
			}
		}
	}
	return out, nil
}
```

- [ ] **Step 5: Register** (NewPipeline + OrderedNames + descriptor_test; now 9 runners), name `"osv"`.

- [ ] **Step 6: Gate + commit**
```bash
git add internal/scanner/osv.go internal/scanner/osv_test.go internal/scanner/pipeline.go internal/scanner/types.go internal/scanner/parse.go internal/scanner/parse_test.go internal/scanner/descriptor_test.go
git commit -m "feat(scanner): add osv-scanner SAST runner and parser"
```

---

### Task 6: Dockerfile — osv-scanner (+ confirm semgrep)

**Files:**
- Modify: `Dockerfile`

**Interfaces:**
- Produces: `osv-scanner` and `semgrep` on PATH in the image.

- [ ] **Step 1: Add osv-scanner as a mandatory go-install layer**, mirroring the nuclei/trivy/vuls `-p 4` pattern (near those lines):
```dockerfile
RUN GOEXPERIMENT=jsonv2 go install -v -p 4 github.com/google/osv-scanner/v2/cmd/osv-scanner@latest \
    || go install -v -p 4 github.com/google/osv-scanner/cmd/osv-scanner@latest \
    || echo "WARN: osv-scanner install failed (installable at runtime)"
```
(The `v2` module path first, falling back to v1; best-effort so a build hiccup never fails the image. If GOEXPERIMENT is not needed for osv, the plain form is fine — the implementer confirms which path the current version wants.)

- [ ] **Step 2: Confirm semgrep is installed.** semgrep is already in the pip/pipx best-effort loop (search the Dockerfile for `semgrep`). If present, no change. If not, add `semgrep` to that loop. gitleaks is already installed via the optional go-install loop — confirm it is there.

- [ ] **Step 3: Validate + commit**
```bash
cd /Users/acho/Desktop/cyber/xalgorix && docker build --check -f Dockerfile . 2>&1 | tail -20 || true
git add Dockerfile
git commit -m "build: install osv-scanner in the scanner image"
```

---

### Task 7: Whole-tree verification

**Files:**
- No source changes expected. Adjust a cross-package test only if it asserts a fixed scanner set or a report snapshot that the new SAST tools/scope change.

- [ ] **Step 1: Build + vet + gofmt**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go build ./... && gofmt -l internal/ cmd/ && CGO_ENABLED=0 go vet ./internal/... ./cmd/...`
(internal/agent/hooks*.go pre-existing gofmt drift is out of scope.)

- [ ] **Step 2: Affected suites twice**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/scanner/... ./internal/web/... ./internal/config/... ./internal/reporting/... -count=2`
Expected: PASS all four, twice.

- [ ] **Step 3: CLI scanner-name surface**

Confirm main.go derives scanner names from `OrderedNames` (5a confirmed it does, dynamically) so `semgrep`/`gitleaks`/`osv`/`trivy` validate via `--scanners`. Run: `cd /Users/acho/Desktop/cyber/xalgorix && grep -n "OrderedNames" cmd/xalgorix/main.go`.

- [ ] **Step 4: Commit any fixups** (skip if none).
```bash
git add -A && git commit -m "test: account for SAST scope and tools in cross-package assertions"
```

---

## Self-Review

**Spec coverage:** SAST phase with source auto-fetch (git clone) / provided source / none→not_applicable ✅ (Task 2, spec §4); one source scope per scan ✅ (Task 2); scope-kind gating via Descriptor.Applies ✅ (Task 2, spec §5 scope kinds); Semgrep/Gitleaks/OSV runners + `semgrep:rule:file:line`/`gitleaks:rule:file:commit`/`osv:pkg:vulnID` ✅ (Tasks 3–5, spec §6); trivy relocated to SAST source scan ✅ (Task 2); Docker installs ✅ (Task 6, spec §9); config env vars ✅ (Task 1, spec §9). Report grouping / recon summary / cross-scope dedup / README contract are Increment 6, intentionally deferred.

**Placeholder scan:** no TBD/TODO; every code step has concrete content. The osv-scanner subcommand carries an explicit "verify against installed version" note — that is a real verification instruction, not a placeholder; the parser (fixture-tested) is version-independent.

**Type consistency:** all three builders match `commandBuilder = func(Request, Config) commandSpec`; all parsers match the `ParseRun` case signature `func(string) ([]Finding, error)`; `Applies` predicates match `func(Scope) bool`; each new runner appears in NewPipeline, OrderedNames, and descriptor_test in the same relative order; `okExit map[int]bool` is added once (Task 2) and consumed by Tasks 4–5.

**Key risks for the executor (not defects):** (a) Task 2 is large and interdependent — the source scope MUST be appended before `results := make([]Run, len(scopes)*len(p.Runners))`; (b) trivy's move from host to source scope changes several existing tests (they expected trivy per-host) — reconcile them; (c) gitleaks/osv `okExit` is essential or their findings are dropped as "failed"; (d) confirm the osv-scanner subcommand against the installed binary in Task 6.
