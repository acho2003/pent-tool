# Increment 5a: testssl Web-Track Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `testssl` as a sixth, web-track, host-scope scanner runner (TLS/cert findings) and, while touching config wiring, close the pre-existing gap where `XALGORIX_SUBFINDER/HTTPX/NMAP_PATH` and their timeouts are never threaded through to the scanner.

**Architecture:** testssl.sh is a subprocess tool that emits a flat JSON array. It fits the existing `commandRunner{build: commandBuilder}` shape (like nuclei/trivy), executed via the shared `executeSpec`. It becomes a 6th entry in the hardcoded `NewPipeline` runner slice with descriptor `{Phase: PhaseWeb, Tracks: [TrackWeb], Weight: WeightLight}`, so the existing track classifier and bounded scheduler run it per web-classified host with zero pipeline changes. A new `parseTestssl` + `ParseRun` case turns its JSON into `Finding`s with `SourceID` `testssl:host:port:id`. The reporter needs no whitelist edit (its allowed-source-id map is rebuilt dynamically from parsed findings).

**Tech Stack:** Go 1.26, `internal/scanner` (runner + parser), `internal/config` + `internal/web` (config plumbing), Dockerfile (tool install).

**Spec:** docs/superpowers/specs/2026-09-24-scanning-dag-pipeline-design.md — this plan implements the "testssl (web)" half of spec §10 increment 5, plus §9's `XALGORIX_TESTSSL_PATH` and the deferred subfinder/httpx/nmap path wiring.

## Global Constraints

- **Go 1.26.** Darwin dev host: run tests with `CGO_ENABLED=0 go test` (CGO segfaults). Do NOT use `go test -race` on this host.
- **Deterministic scanning:** command construction is deterministic; no behavior depends on wall-clock or map iteration order.
- **SourceID convention:** every `Finding.SourceID` is `"<scanner>:...”` with a scanner-unique prefix; `dedupFindings` and the AI-fidelity guard key on the raw string. testssl uses `testssl:host:port:id` (spec §6).
- **Every applicable tool records exactly one terminal status per scope.** A web-track host runs testssl; a server-only host records it `not_applicable` via the existing track gating — no code needed beyond the descriptor's `Tracks`.
- **Reporter whitelist:** none. `report_ai.go`'s `allowed` map (report_ai.go:~162) is rebuilt per request from parsed findings. Do NOT add a static whitelist.
- **Mandatory gate every task:** `gofmt -l internal/`, `CGO_ENABLED=0 go vet ./...`, and `CGO_ENABLED=0 go test` on the touched packages must all be clean before a task is done.

---

## File Structure

- `internal/scanner/types.go` — add `TestsslPath string` + `TestsslTimeout time.Duration` to `scanner.Config`. (Subfinder/Httpx/Nmap path+timeout fields already exist here.)
- `internal/config/config.go` — add `TestsslPath`, `TestsslTimeoutSec`, `SubfinderPath`, `HttpxPath`, `NmapPath`, `SubfinderTimeoutSec`, `HttpxTimeoutSec`, `NmapTimeoutSec` fields + `envOr`/`envOrInt` wiring.
- `internal/web/deterministic_scan.go` — `scannerConfig` copies all the above into `scanner.Config`.
- `internal/scanner/testssl.go` (Create) — `buildTestssl` commandBuilder.
- `internal/scanner/pipeline.go` — register `commandRunner{name:"testssl", ...}` as the 6th entry in `NewPipeline`.
- `internal/scanner/types.go` — add `"testssl"` to `OrderedNames`.
- `internal/scanner/parse.go` — `parseTestssl` + `ParseRun` case `"testssl"`.
- `internal/scanner/parse_test.go` — testssl fixture + assertion.
- `internal/scanner/descriptor_test.go` — extend the expected-descriptors map to 6 entries.
- `Dockerfile` — install testssl.sh (git clone + PATH wrapper).

---

### Task 1: Config plumbing (testssl + close subfinder/httpx/nmap wiring gap)

**Files:**
- Modify: `internal/scanner/types.go` (add `TestsslPath`, `TestsslTimeout` to `Config`)
- Modify: `internal/config/config.go` (add fields + env wiring)
- Modify: `internal/web/deterministic_scan.go` (`scannerConfig` copies fields)
- Test: `internal/config/config_test.go` (if a config env test exists; otherwise assert in a new small test)

**Interfaces:**
- Consumes: existing `envOr(key, fallback string) string`, `envOrInt(key string, fallback int) int` in config.go; `applyDefaults` in pipeline.go (already defaults these paths to bare names / fixed timeouts when zero-valued).
- Produces: `scanner.Config.TestsslPath` (string), `scanner.Config.TestsslTimeout` (time.Duration), and non-zero `SubfinderPath/HttpxPath/NmapPath` + `SubfinderTimeout/HttpxTimeout/NmapTimeout` on the config returned by `scannerConfig`.

- [ ] **Step 1: Add fields to `scanner.Config`**

In `internal/scanner/types.go`, in the `Config` struct, add `TestsslPath` beside the other `*Path` fields and `TestsslTimeout` beside the other `*Timeout` fields:

```go
	NucleiPath        string
	TrivyPath         string
	VulsPath          string
	VulsSSHConfigPath string
	SubfinderPath     string
	HttpxPath         string
	NmapPath          string
	TestsslPath       string
```
```go
	NucleiTimeout    time.Duration
	ZAPTimeout       time.Duration
	OpenVASTimeout   time.Duration
	TrivyTimeout     time.Duration
	VulsTimeout      time.Duration
	SubfinderTimeout time.Duration
	HttpxTimeout     time.Duration
	NmapTimeout      time.Duration
	TestsslTimeout   time.Duration
```

- [ ] **Step 2: Default the new path/timeout in `applyDefaults`**

In `internal/scanner/pipeline.go` `applyDefaults`, mirror the existing recon defaults:

```go
	if cfg.TestsslPath == "" {
		cfg.TestsslPath = "testssl.sh"
	}
```
```go
	if cfg.TestsslTimeout <= 0 {
		cfg.TestsslTimeout = 30 * time.Minute
	}
```

- [ ] **Step 3: Add fields + env wiring to `config.Config`**

In `internal/config/config.go`, add to the `Config` struct (near the other `*Path`/`*TimeoutSec` fields):

```go
	SubfinderPath       string
	HttpxPath           string
	NmapPath            string
	TestsslPath         string
	SubfinderTimeoutSec int
	HttpxTimeoutSec     int
	NmapTimeoutSec      int
	TestsslTimeoutSec   int
```

In the constructor where `NucleiPath`/`TrivyPath` etc. are assigned via `envOr`, add:

```go
	SubfinderPath:       envOr("XALGORIX_SUBFINDER_PATH", "subfinder"),
	HttpxPath:           envOr("XALGORIX_HTTPX_PATH", "httpx"),
	NmapPath:            envOr("XALGORIX_NMAP_PATH", "nmap"),
	TestsslPath:         envOr("XALGORIX_TESTSSL_PATH", "testssl.sh"),
	SubfinderTimeoutSec: envOrInt("XALGORIX_SUBFINDER_TIMEOUT_SECONDS", 600),
	HttpxTimeoutSec:     envOrInt("XALGORIX_HTTPX_TIMEOUT_SECONDS", 600),
	NmapTimeoutSec:      envOrInt("XALGORIX_NMAP_TIMEOUT_SECONDS", 1800),
	TestsslTimeoutSec:   envOrInt("XALGORIX_TESTSSL_TIMEOUT_SECONDS", 1800),
```

(600s/1800s match the current hardcoded `applyDefaults` fallbacks: subfinder/httpx 10min, nmap 30min, testssl 30min.)

- [ ] **Step 4: Thread through `scannerConfig`**

In `internal/web/deterministic_scan.go` `scannerConfig`, add to the returned `scanner.Config` literal:

```go
		SubfinderPath: cfg.SubfinderPath, HttpxPath: cfg.HttpxPath, NmapPath: cfg.NmapPath, TestsslPath: cfg.TestsslPath,
```
```go
		SubfinderTimeout: time.Duration(cfg.SubfinderTimeoutSec) * time.Second,
		HttpxTimeout:     time.Duration(cfg.HttpxTimeoutSec) * time.Second,
		NmapTimeout:      time.Duration(cfg.NmapTimeoutSec) * time.Second,
		TestsslTimeout:   time.Duration(cfg.TestsslTimeoutSec) * time.Second,
```

- [ ] **Step 5: Test the wiring**

Add a test (in `internal/web` or `internal/config`, wherever an existing `scannerConfig`/config test lives — search for `scannerConfig(` and `TestLoad` first) asserting that with the env vars set, `scannerConfig` produces the expected non-zero paths/timeouts. Minimal shape:

```go
func TestScannerConfigThreadsReconAndTestsslPaths(t *testing.T) {
	t.Setenv("XALGORIX_TESTSSL_PATH", "/opt/testssl.sh/testssl.sh")
	t.Setenv("XALGORIX_SUBFINDER_PATH", "/usr/local/bin/subfinder")
	cfg := config.Load() // use whatever the existing constructor is named
	sc := scannerConfig(cfg)
	if sc.TestsslPath != "/opt/testssl.sh/testssl.sh" {
		t.Errorf("TestsslPath = %q", sc.TestsslPath)
	}
	if sc.SubfinderPath != "/usr/local/bin/subfinder" {
		t.Errorf("SubfinderPath = %q", sc.SubfinderPath)
	}
	if sc.TestsslTimeout <= 0 || sc.NmapTimeout <= 0 {
		t.Errorf("timeouts not threaded: testssl=%v nmap=%v", sc.TestsslTimeout, sc.NmapTimeout)
	}
}
```
(If `config.Load` needs required env/paths to succeed, follow the setup that the existing config test uses. If `scannerConfig` is unexported and no same-package test file exists, put the test in `internal/web` package `web`.)

- [ ] **Step 6: Run gate + commit**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && gofmt -l internal/ && CGO_ENABLED=0 go vet ./internal/scanner/... ./internal/web/... ./internal/config/... && CGO_ENABLED=0 go test ./internal/scanner/... ./internal/web/... ./internal/config/...`
Expected: gofmt prints nothing; vet clean; tests pass.

```bash
git add internal/scanner/types.go internal/scanner/pipeline.go internal/config/config.go internal/web/deterministic_scan.go internal/web/*_test.go internal/config/*_test.go
git commit -m "feat(config): thread testssl + subfinder/httpx/nmap paths and timeouts to scanner"
```

---

### Task 2: testssl runner + registration

**Files:**
- Create: `internal/scanner/testssl.go`
- Modify: `internal/scanner/pipeline.go` (`NewPipeline` runner slice)
- Modify: `internal/scanner/types.go` (`OrderedNames`)
- Modify: `internal/scanner/descriptor_test.go` (expected map → 6 entries)
- Test: `internal/scanner/testssl_test.go` (Create) — buildTestssl arg assertions

**Interfaces:**
- Consumes: `commandRunner`, `commandSpec` (pipeline.go), `Request`, `Config`, `Descriptor`, `PhaseWeb`, `TrackWeb`, `WeightLight`.
- Produces: `buildTestssl(req Request, cfg Config) commandSpec`; a registered runner named `"testssl"` with descriptor `{Name:"testssl", Phase:PhaseWeb, Tracks:[]Track{TrackWeb}, Weight:WeightLight}`.

- [ ] **Step 1: Write the failing test for `buildTestssl`**

Create `internal/scanner/testssl_test.go`:

```go
package scanner

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestBuildTestsslCommand(t *testing.T) {
	req := Request{Target: "example.com", ScanDir: t.TempDir()}
	cfg := Config{TestsslPath: "testssl.sh", TestsslTimeout: 5 * time.Minute}
	spec := buildTestssl(req, cfg)
	if spec.path != "testssl.sh" {
		t.Errorf("path = %q", spec.path)
	}
	if spec.timeout != 5*time.Minute {
		t.Errorf("timeout = %v", spec.timeout)
	}
	if !strings.HasSuffix(spec.artifact, "results.json") {
		t.Errorf("artifact = %q", spec.artifact)
	}
	// jsonfile must point at the artifact and the target must be last.
	if !slices.Contains(spec.args, "--jsonfile") {
		t.Errorf("args missing --jsonfile: %v", spec.args)
	}
	if spec.args[len(spec.args)-1] != "example.com" {
		t.Errorf("target not last arg: %v", spec.args)
	}
}

func TestBuildTestsslRejectsArtifactTarget(t *testing.T) {
	req := Request{Target: "artifact://blob", ScanDir: t.TempDir()}
	spec := buildTestssl(req, Config{TestsslPath: "testssl.sh", TestsslTimeout: time.Minute})
	if spec.notApp == "" {
		t.Errorf("expected notApp for artifact target, got spec %+v", spec)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/scanner/ -run TestBuildTestssl`
Expected: FAIL — `undefined: buildTestssl`.

- [ ] **Step 3: Implement `buildTestssl`**

Create `internal/scanner/testssl.go`:

```go
package scanner

import (
	"path/filepath"
	"strconv"
	"strings"
)

// buildTestssl runs testssl.sh against a web host and writes a flat JSON array
// of results. It is a light, web-track, host-scope scanner. The artifact path
// is fresh per (scope) because each host scope gets its own ScanDir, so
// testssl's refuse-to-overwrite behavior never triggers on a first run; on
// resume the terminal run is reused and testssl is not re-invoked.
func buildTestssl(req Request, cfg Config) commandSpec {
	target := strings.TrimSpace(req.Target)
	if target == "" || strings.HasPrefix(target, "artifact://") {
		return commandSpec{notApp: "testssl requires a host or URL target", timeout: cfg.TestsslTimeout}
	}
	artifact := filepath.Join(req.ScanDir, "scanner-output", "testssl", "results.json")
	args := []string{
		"--quiet",          // no banner
		"--color", "0",     // no ANSI in logs
		"--warnings", "batch", // never prompt
		"--connect-timeout", strconv.Itoa(15),
		"--openssl-timeout", strconv.Itoa(15),
		"--jsonfile", artifact,
		target, // must remain the final arg
	}
	return commandSpec{path: cfg.TestsslPath, args: args, artifact: artifact, timeout: cfg.TestsslTimeout}
}
```

- [ ] **Step 4: Run the build test to verify it passes**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/scanner/ -run TestBuildTestssl`
Expected: PASS.

- [ ] **Step 5: Register the runner in `NewPipeline`**

In `internal/scanner/pipeline.go` `NewPipeline`, add testssl to the runner slice. Per spec ordering, web-track tools group together — place it after `nuclei`/`zap` (both web) and before the server/sast tools is not required for correctness (output order is slot-based) but keep it grouped with web tools for readability:

```go
	return &Pipeline{Config: cfg, reconFn: runRecon, Runners: []Runner{
		commandRunner{name: "nuclei", desc: Descriptor{Name: "nuclei", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightLight}, build: buildNuclei},
		zapRunner{},
		commandRunner{name: "testssl", desc: Descriptor{Name: "testssl", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightLight}, build: buildTestssl},
		openVASRunner{},
		commandRunner{name: "trivy", desc: Descriptor{Name: "trivy", Phase: PhaseSAST, Weight: WeightLight}, build: buildTrivy},
		vulsRunner{},
	}}
```

- [ ] **Step 6: Add `"testssl"` to `OrderedNames`**

In `internal/scanner/types.go`, keep the order aligned with the runner slice:

```go
var OrderedNames = []string{"nuclei", "zap", "testssl", "openvas", "trivy", "vuls"}
```

- [ ] **Step 7: Update `descriptor_test.go` expected map**

In `internal/scanner/descriptor_test.go`, add the testssl entry to the expected `want` map and bump any hardcoded count so `len(p.Runners) == len(want)` holds. Match the existing entry shape exactly, e.g.:

```go
	"testssl": {phase: PhaseWeb, weight: WeightLight},
```

- [ ] **Step 8: Run the scanner suite; fix any 5-vs-6 assertions**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/scanner/... -count=1`
Expected: PASS. If any test hardcodes 5 runners / the old `OrderedNames` length / an expected slot count, update it to 6 (search: `len(p.Runners)`, `OrderedNames`, `len(scopes)*`, and any test asserting an exact number of runs per scope). Report each such test touched.

- [ ] **Step 9: Gate + commit**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && gofmt -l internal/scanner/ && CGO_ENABLED=0 go vet ./internal/scanner/... && CGO_ENABLED=0 go test ./internal/scanner/...`
Expected: clean.

```bash
git add internal/scanner/testssl.go internal/scanner/testssl_test.go internal/scanner/pipeline.go internal/scanner/types.go internal/scanner/descriptor_test.go
git commit -m "feat(scanner): add testssl web-track runner"
```

---

### Task 3: testssl parser + ParseRun case

**Files:**
- Modify: `internal/scanner/parse.go` (`parseTestssl` + `ParseRun` case)
- Test: `internal/scanner/parse_test.go` (fixture + assertion)

**Interfaces:**
- Consumes: `Finding` struct, `readJSON`/`array`/`str`/`firstNonEmpty`/`severity`/`asCVE` helpers in parse.go, `Run` struct.
- Produces: `parseTestssl(path string) ([]Finding, error)` and a `case "testssl"` in `ParseRun`.

testssl `--jsonfile` (flat, non-pretty) emits a JSON array of objects. Relevant fields per entry: `id`, `ip` (format `"fqdn/1.2.3.4"`), `port`, `severity` (`OK|INFO|LOW|MEDIUM|HIGH|CRITICAL|WARN|DEBUG`), `finding`, and sometimes `cve`, `cwe`. We keep only actionable severities (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`) so the report is not flooded with hundreds of `OK`/`INFO` lines.

- [ ] **Step 1: Write the failing parser test**

In `internal/scanner/parse_test.go`, add:

```go
func TestParseTestsslFindings(t *testing.T) {
	body := `[
	  {"id":"SSLv3","ip":"example.com/93.184.216.34","port":"443","severity":"OK","finding":"not offered"},
	  {"id":"cert_expirationStatus","ip":"example.com/93.184.216.34","port":"443","severity":"HIGH","finding":"expired 3 days ago","cve":"","cwe":"CWE-298"},
	  {"id":"BREACH","ip":"example.com/93.184.216.34","port":"443","severity":"MEDIUM","finding":"potentially vulnerable","cve":"CVE-2013-3587"}
	]`
	p := writeFixture(t, "results.json", body)
	got, err := ParseRun(Run{Scanner: "testssl", ArtifactPath: p})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 { // OK filtered out; HIGH + MEDIUM kept
		t.Fatalf("want 2 findings, got %d: %#v", len(got), got)
	}
	for _, f := range got {
		if f.Scanner != "testssl" {
			t.Errorf("scanner = %q", f.Scanner)
		}
		if !strings.HasPrefix(f.SourceID, "testssl:example.com:443:") {
			t.Errorf("SourceID = %q", f.SourceID)
		}
	}
}
```
(Ensure `strings` is imported in parse_test.go; add it if missing.)

- [ ] **Step 2: Run it to verify it fails**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/scanner/ -run TestParseTestssl`
Expected: FAIL — `unsupported scanner "testssl"` (no case yet).

- [ ] **Step 3: Implement `parseTestssl` and the case**

In `internal/scanner/parse.go`, add the case to the `ParseRun` switch (beside the other cases):

```go
	case "testssl":
		return parseTestssl(run.ArtifactPath)
```

Add the parser function (follow the `parseTrivy` style — direct file read, defensive field access):

```go
// parseTestssl reads testssl.sh's flat --jsonfile array and emits one Finding
// per actionable entry (severity LOW and above). OK/INFO/DEBUG/WARN entries are
// status lines, not vulnerabilities, and are dropped so the report stays focused.
func parseTestssl(path string) ([]Finding, error) {
	var entries []map[string]any
	if err := readJSON(path, &entries); err != nil {
		return nil, err
	}
	actionable := map[string]bool{"LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true}
	var out []Finding
	for _, m := range entries {
		sev := strings.ToUpper(strings.TrimSpace(str(m["severity"])))
		if !actionable[sev] {
			continue
		}
		id := str(m["id"])
		host := str(m["ip"])
		if i := strings.IndexByte(host, '/'); i >= 0 { // "fqdn/ip" -> "fqdn"
			host = host[:i]
		}
		port := str(m["port"])
		out = append(out, Finding{
			SourceID:    "testssl:" + host + ":" + port + ":" + id,
			Scanner:     "testssl",
			Title:       firstNonEmpty(id, "TLS finding"),
			Severity:    severity(sev),
			Target:      host,
			Endpoint:    host + ":" + port,
			Description: str(m["finding"]),
			CVE:         asCVE(str(m["cve"])),
			CWE:         str(m["cwe"]),
		})
	}
	return out, nil
}
```
(Verify the exact helper names by reading parse.go: use whatever the existing parsers use for JSON decode (`readJSON`), string coercion (`str`), CVE normalization (`asCVE`), and severity mapping (`severity`). If `asCVE("")` does not return `""`, guard the empty case.)

- [ ] **Step 4: Run the parser test to verify it passes**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/scanner/ -run TestParseTestssl`
Expected: PASS.

- [ ] **Step 5: Gate + commit**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && gofmt -l internal/scanner/ && CGO_ENABLED=0 go vet ./internal/scanner/... && CGO_ENABLED=0 go test ./internal/scanner/...`
Expected: clean.

```bash
git add internal/scanner/parse.go internal/scanner/parse_test.go
git commit -m "feat(scanner): parse testssl JSON into TLS findings"
```

---

### Task 4: Dockerfile — install testssl.sh

**Files:**
- Modify: `Dockerfile`

**Interfaces:**
- Produces: a `testssl.sh` executable on `PATH` inside the `xalgorix:local` image, resolvable by the default `XALGORIX_TESTSSL_PATH=testssl.sh`.

- [ ] **Step 1: Add the install step**

testssl.sh is a bash script with a bundled `etc/` data dir; it must be run from its checkout (or with the checkout on PATH). Mirror the existing CMSmap `git clone --depth 1` pattern. Add near the other cloned tools:

```dockerfile
# testssl.sh — TLS/cert scanner (bash script; needs its bundled etc/ data dir)
RUN git clone --depth 1 https://github.com/testssl/testssl.sh /opt/testssl.sh \
      && ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh \
    || echo "WARN: testssl.sh install failed (installable at runtime)"
```

(Use the best-effort `|| echo WARN` form consistent with the other optional utilities so a network hiccup cloning testssl never fails the whole image build. testssl.sh needs `bash`, `openssl` — both present in the Kali base.)

- [ ] **Step 2: Sanity-check the Dockerfile parses (no full build required here)**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && docker build --check -f Dockerfile . 2>&1 | tail -20 || true`
Expected: no syntax errors reported for the new lines. (A full image build is out of scope for this task's gate — it's exercised in Task 5's optional build note. `--check` only validates the Dockerfile.)

- [ ] **Step 3: Commit**

```bash
git add Dockerfile
git commit -m "build: install testssl.sh in the scanner image"
```

---

### Task 5: Whole-tree verification

**Files:**
- No source changes expected. Adjust a test only if a cross-package assertion (e.g. a web/reporting test asserting a fixed set of scanner names or a report snapshot) needs the new `testssl` name.

**Interfaces:**
- Consumes: everything above.
- Produces: green build + affected suites.

- [ ] **Step 1: Build + vet + gofmt**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go build ./... && gofmt -l internal/ cmd/ && CGO_ENABLED=0 go vet ./internal/... ./cmd/...`
Expected: build succeeds; gofmt prints nothing; vet clean.

- [ ] **Step 2: Affected suites (twice, for flakiness)**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/scanner/... ./internal/web/... ./internal/config/... ./internal/reporting/... -count=2`
Expected: PASS all four, twice.

- [ ] **Step 3: CLI help / scanner-name surface check**

Confirm `cmd/xalgorix/main.go`'s scanner-name help text (the `OrderedNames` usage at ~line 432) now includes `testssl`, and that `--scanners testssl` validates. Run: `cd /Users/acho/Desktop/cyber/xalgorix && grep -n "testssl" cmd/xalgorix/main.go || echo "check main.go uses OrderedNames dynamically"`
If main.go lists scanner names dynamically from `OrderedNames`, no edit is needed; if it hardcodes a list, add `testssl`. Report which.

- [ ] **Step 4: Commit any fixups**

```bash
git add -A
git commit -m "test: account for testssl in cross-package assertions"
```
(Skip if none needed.)

---

## Self-Review

**Spec coverage:** testssl runner (web track) ✅ (Task 2); parser + SourceID `testssl:host:port:id` ✅ (Task 3, spec §6); `XALGORIX_TESTSSL_PATH` + timeout ✅ (Task 1, spec §9); Docker install ✅ (Task 4, spec §9); the deferred subfinder/httpx/nmap path wiring ✅ (Task 1). Semgrep/Gitleaks/OSV/source-fetch/trivy-relocation are intentionally deferred to Increment 5b.

**Placeholder scan:** no TBD/TODO; every code step has concrete content.

**Type consistency:** `buildTestssl(Request, Config) commandSpec` matches `commandBuilder`; descriptor uses `PhaseWeb`/`TrackWeb`/`WeightLight` (defined in descriptor.go/scope.go); `parseTestssl(string) ([]Finding, error)` matches the `ParseRun` case call; `OrderedNames` and the `NewPipeline` slice both list testssl in the same relative position.

**Known verification points for the implementer (not defects):** (a) confirm the exact parse.go helper names (`readJSON`, `str`, `severity`, `asCVE`, `firstNonEmpty`) before using them; (b) confirm `config.Load`'s real constructor name for the Task 1 test; (c) find and update every test that hardcodes 5 runners / old `OrderedNames` length.
