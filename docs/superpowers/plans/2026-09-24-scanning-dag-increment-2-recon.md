# Scanning DAG — Increment 2: Recon Phase & Fan-out Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a recon phase (Subfinder → httpx → Nmap) that discovers live hosts, then fan the existing scan-phase tools out once per discovered host — each recon tool and each per-host scanner producing its own scoped `Run` record.

**Architecture:** Three new custom runners (`subfinderRunner`, `httpxRunner`, `nmapRunner`, all `PhaseRecon`) execute in order and populate `[]Scope` (host scopes with `HostEvidence`). `Pipeline.Run` is restructured: run recon → collect live host scopes → for each host scope run the five existing scan runners against that host's target. Recon and per-host runs are all stamped with their scope and resumed on `(scope, scanner)` (Increment 1's keying). No classifier yet (Increment 3) — every host runs all five scan tools.

**Tech Stack:** Go 1.26, stdlib only. Subfinder/httpx emit JSONL; Nmap emits XML (`encoding/xml`). Tools already in the image: subfinder, httpx, nmap.

**Spec:** `docs/superpowers/specs/2026-09-24-scanning-dag-pipeline-design.md` (§3.1, §4 recon, §6, §7, §10 increment 2)

## Global Constraints

- Run tests with `CGO_ENABLED=0` on Darwin. Command: `CGO_ENABLED=0 go test ./internal/scanner/... ./internal/web/...`
- Recon runs FIRST and always (no user selection in this increment). The five scan tools remain selectable via `req.Scanners`.
- Decision (locked): recon tools each produce a visible `Run` record. subfinder/httpx produce NO findings (evidence only); nmap produces findings with SourceID `nmap:host:port`.
- Decision (locked): "scan complete" is determined by every `Run` being terminal AND `record.Status == "finished"` — the `len(runs) == len(scanner.OrderedNames)` checks are REMOVED (spec §7 contract change).
- Fan-out is sequential in this increment (bounded parallelism is Increment 4): hosts processed in discovery order, tools per host in pipeline order.
- A bare host/URL/IP input yields exactly one host scope (subfinder finds nothing to expand) — the `localhost:3000` path must still work as a single-host scan.
- Recon scope ID for recon runs: `recon:<target>`. Per-host scan scope ID: `HostScope(host).Key()` = `host:<host>`.
- Determinism: recon, host discovery, and command construction are code-only; no AI.

---

### Task 1: Recon config fields and defaults

**Files:**
- Modify: `internal/scanner/types.go` (`Config` struct)
- Modify: `internal/scanner/pipeline.go` (`applyDefaults`)
- Test: `internal/scanner/pipeline_test.go` (add a defaults test)

**Interfaces:**
- Consumes: nothing new.
- Produces: `Config.SubfinderPath, HttpxPath, NmapPath string`; `Config.SubfinderTimeout, HttpxTimeout, NmapTimeout time.Duration`. Defaults: paths `"subfinder"`/`"httpx"`/`"nmap"`; timeouts subfinder 10m, httpx 10m, nmap 30m.

- [ ] **Step 1: Write the failing test**

```go
// append to internal/scanner/pipeline_test.go
func TestApplyDefaultsReconFields(t *testing.T) {
	p := NewPipeline(Config{})
	c := p.Config
	if c.SubfinderPath != "subfinder" || c.HttpxPath != "httpx" || c.NmapPath != "nmap" {
		t.Fatalf("recon paths = %q/%q/%q", c.SubfinderPath, c.HttpxPath, c.NmapPath)
	}
	if c.SubfinderTimeout != 10*time.Minute || c.HttpxTimeout != 10*time.Minute || c.NmapTimeout != 30*time.Minute {
		t.Fatalf("recon timeouts = %v/%v/%v", c.SubfinderTimeout, c.HttpxTimeout, c.NmapTimeout)
	}
}
```

(Ensure `time` is imported in the test file.)

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run TestApplyDefaultsReconFields -v`
Expected: FAIL — `c.SubfinderPath undefined`.

- [ ] **Step 3: Write minimal implementation**

Add to `Config` in `types.go` (after `VulsSSHConfigPath`):

```go
	SubfinderPath string
	HttpxPath     string
	NmapPath      string
```

Add timeout fields after `VulsTimeout`:

```go
	SubfinderTimeout time.Duration
	HttpxTimeout     time.Duration
	NmapTimeout      time.Duration
```

Add to `applyDefaults` in `pipeline.go`:

```go
	if cfg.SubfinderPath == "" {
		cfg.SubfinderPath = "subfinder"
	}
	if cfg.HttpxPath == "" {
		cfg.HttpxPath = "httpx"
	}
	if cfg.NmapPath == "" {
		cfg.NmapPath = "nmap"
	}
	if cfg.SubfinderTimeout <= 0 {
		cfg.SubfinderTimeout = 10 * time.Minute
	}
	if cfg.HttpxTimeout <= 0 {
		cfg.HttpxTimeout = 10 * time.Minute
	}
	if cfg.NmapTimeout <= 0 {
		cfg.NmapTimeout = 30 * time.Minute
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run TestApplyDefaultsReconFields -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/types.go internal/scanner/pipeline.go internal/scanner/pipeline_test.go
git commit -m "feat(scanner): add recon tool config fields and defaults"
```

---

### Task 2: Nmap XML parser and finding source ID

**Files:**
- Modify: `internal/scanner/parse.go` (add `parseNmap`, wire into `ParseRun`)
- Test: `internal/scanner/parse_test.go`

**Interfaces:**
- Consumes: `Finding`, `Run`.
- Produces: `ParseRun` handles `case "nmap"`; `parseNmap(path string) ([]Finding, error)` reading nmap XML, emitting one `Finding` per open port with `SourceID: "nmap:" + host + ":" + port`, `Scanner: "nmap"`, `Severity: "info"`, `Target: host`, `Endpoint: port`, `Title: service name`, `Evidence: product+version`. `ParseRun` returns `(nil, nil)` for `"subfinder"` and `"httpx"` (evidence-only, no findings).

- [ ] **Step 1: Write the failing test**

```go
// append to internal/scanner/parse_test.go
func TestParseNmapPorts(t *testing.T) {
	xml := `<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.5" addrtype="ipv4"/>` +
		`<ports><port protocol="tcp" portid="22"><state state="open"/>` +
		`<service name="ssh" product="OpenSSH" version="9.2"/></port>` +
		`<port protocol="tcp" portid="443"><state state="closed"/>` +
		`<service name="https"/></port></ports></host></nmaprun>`
	dir := t.TempDir()
	p := filepath.Join(dir, "nmap.xml")
	if err := os.WriteFile(p, []byte(xml), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := parseNmap(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 { // only the open port
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	f := findings[0]
	if f.SourceID != "nmap:10.0.0.5:22" || f.Scanner != "nmap" || f.Endpoint != "22" {
		t.Fatalf("unexpected finding: %+v", f)
	}
	if f.Title != "ssh" {
		t.Fatalf("title = %q, want ssh", f.Title)
	}
}

func TestParseRunEvidenceOnlyRecon(t *testing.T) {
	for _, name := range []string{"subfinder", "httpx"} {
		got, err := ParseRun(Run{Scanner: name, Status: "completed"})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got) != 0 {
			t.Fatalf("%s produced %d findings, want 0", name, len(got))
		}
	}
}
```

(Ensure `os`, `path/filepath` imported in parse_test.go.)

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run 'TestParseNmapPorts|TestParseRunEvidenceOnlyRecon' -v`
Expected: FAIL — `undefined: parseNmap`; ParseRun returns an error for unknown scanner names.

- [ ] **Step 3: Write minimal implementation**

In `parse.go`, extend the `ParseRun` switch:

```go
	case "nmap":
		return parseNmap(run.ArtifactPath)
	case "subfinder", "httpx":
		return nil, nil // recon evidence tools produce no findings
```

Add the parser and its XML types:

```go
type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}
type nmapHost struct {
	Addresses []nmapAddr `xml:"address"`
	Ports     []nmapPort `xml:"ports>port"`
}
type nmapAddr struct {
	Addr string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}
type nmapPort struct {
	Protocol string  `xml:"protocol,attr"`
	PortID   string  `xml:"portid,attr"`
	State    string  `xml:"state>state,attr"`
	Service  nmapSvc `xml:"service"`
}
type nmapSvc struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

func parseNmap(path string) ([]Finding, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var run nmapRun
	if err := xml.Unmarshal(b, &run); err != nil {
		return nil, err
	}
	var out []Finding
	for _, h := range run.Hosts {
		host := ""
		for _, a := range h.Addresses {
			if a.Type == "ipv4" || a.Type == "ipv6" {
				host = a.Addr
				break
			}
		}
		for _, p := range h.Ports {
			if p.State != "open" {
				continue
			}
			out = append(out, Finding{
				SourceID: "nmap:" + host + ":" + p.PortID,
				Scanner:  "nmap",
				Title:    firstNonEmpty(p.Service.Name, "open port "+p.PortID),
				Severity: "info",
				Target:   host,
				Endpoint: p.PortID,
				Evidence: strings.TrimSpace(p.Service.Product + " " + p.Service.Version),
			})
		}
	}
	return out, nil
}
```

Add `"encoding/xml"` to parse.go imports (and confirm `strings` is already imported).

- [ ] **Step 4: Run tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run 'TestParseNmapPorts|TestParseRunEvidenceOnlyRecon' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/parse.go internal/scanner/parse_test.go
git commit -m "feat(scanner): parse nmap XML into port findings"
```

---

### Task 3: Recon host-discovery types and the recon runner scaffold

**Files:**
- Create: `internal/scanner/recon.go`
- Test: `internal/scanner/recon_test.go`

**Interfaces:**
- Consumes: `Scope`, `HostScope`, `HostEvidence`, `Port`, `Run`, `Config`, `EmitFunc`, `Descriptor`, `PhaseRecon`.
- Produces:
  - `func isBareHostInput(target string) bool` — true when target is an IP, `host:port`, or URL (not an apex domain suitable for subdomain enumeration). Used to decide whether subfinder runs.
  - `func reconScopeKey(target string) string` — returns `"recon:" + target`.
  - `func candidateHosts(target string) []string` — normalizes the input target to a starting host list (strips scheme/port for the host form; always includes the input's host). This is the seed list when subfinder does not apply.

- [ ] **Step 1: Write the failing test**

```go
// internal/scanner/recon_test.go
package scanner

import "testing"

func TestReconScopeKey(t *testing.T) {
	if got := reconScopeKey("example.com"); got != "recon:example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestIsBareHostInput(t *testing.T) {
	cases := map[string]bool{
		"http://localhost:3000/": true,
		"127.0.0.1":              true,
		"10.0.0.5:8080":          true,
		"example.com":            false,
		"sub.example.com":        false,
	}
	for in, want := range cases {
		if got := isBareHostInput(in); got != want {
			t.Errorf("isBareHostInput(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestCandidateHostsStripsSchemeAndPort(t *testing.T) {
	got := candidateHosts("http://localhost:3000/")
	if len(got) != 1 || got[0] != "localhost" {
		t.Fatalf("got %v, want [localhost]", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run 'TestReconScopeKey|TestIsBareHostInput|TestCandidateHostsStripsSchemeAndPort' -v`
Expected: FAIL — undefined functions.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/scanner/recon.go
package scanner

import (
	"net"
	"net/url"
	"strings"
)

func reconScopeKey(target string) string { return "recon:" + target }

// hostFromTarget extracts the bare host from a URL, host:port, or host.
func hostFromTarget(target string) string {
	t := strings.TrimSpace(target)
	if strings.Contains(t, "://") {
		if u, err := url.Parse(t); err == nil && u.Host != "" {
			t = u.Host
		}
	}
	if h, _, err := net.SplitHostPort(t); err == nil {
		return h
	}
	return t
}

// isBareHostInput reports whether the target is an IP, host:port, or URL —
// i.e. not an apex/subdomain name that subfinder should enumerate.
func isBareHostInput(target string) bool {
	t := strings.TrimSpace(target)
	if strings.Contains(t, "://") {
		return true
	}
	host := hostFromTarget(t)
	if net.ParseIP(host) != nil {
		return true
	}
	// host:port form (a port after the host) is a bare host input.
	if _, _, err := net.SplitHostPort(t); err == nil {
		return true
	}
	return false
}

func candidateHosts(target string) []string {
	h := hostFromTarget(target)
	if h == "" {
		return nil
	}
	return []string{h}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run 'TestReconScopeKey|TestIsBareHostInput|TestCandidateHostsStripsSchemeAndPort' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/recon.go internal/scanner/recon_test.go
git commit -m "feat(scanner): add recon host-discovery helpers"
```

---

### Task 4: Recon executor — run subfinder/httpx/nmap and build host scopes

**Files:**
- Modify: `internal/scanner/recon.go`
- Test: `internal/scanner/recon_test.go`

**Interfaces:**
- Consumes: everything from Task 3, plus `executeSpec`/`commandSpec` patterns in pipeline.go (reuse for running each recon tool and capturing its artifact), `Run`, `Config`, `EmitFunc`.
- Produces:
  - `func runRecon(ctx context.Context, req Request, cfg Config, emit EmitFunc) (scopes []Scope, runs []Run)` — runs subfinder (only when `!isBareHostInput`), then httpx over the candidate+discovered hosts, then nmap per live host. Returns the live host scopes (with `Evidence.OpenPorts`, `LiveURLs`, `TLS`) and one `Run` per recon tool (scanner names `subfinder`, `httpx`, `nmap`; scope `reconScopeKey(req.Target)`; nmap's `ArtifactPath` set to its XML so `parseNmap` can read it).
  - Helper parsers (unexported): `parseSubfinderHosts(path string) []string` (JSONL `{"host":...}`), `parseHttpxLive(path string) []httpxResult` (JSONL `{"url","host","port","scheme","tls"}`), where `type httpxResult struct { URL, Host, Port, Scheme string; TLS bool }`.

- [ ] **Step 1: Write the failing test**

```go
// append to internal/scanner/recon_test.go
func TestParseHttpxLive(t *testing.T) {
	jsonl := `{"url":"https://a.example.com","host":"a.example.com","port":"443","scheme":"https","tls":true}` + "\n" +
		`{"url":"http://b.example.com","host":"b.example.com","port":"80","scheme":"http"}` + "\n"
	dir := t.TempDir()
	p := filepath.Join(dir, "httpx.jsonl")
	if err := os.WriteFile(p, []byte(jsonl), 0o600); err != nil {
		t.Fatal(err)
	}
	res := parseHttpxLive(p)
	if len(res) != 2 {
		t.Fatalf("results = %d, want 2", len(res))
	}
	if res[0].Host != "a.example.com" || !res[0].TLS || res[0].Scheme != "https" {
		t.Fatalf("unexpected result[0]: %+v", res[0])
	}
}

func TestParseSubfinderHosts(t *testing.T) {
	jsonl := `{"host":"a.example.com"}` + "\n" + `{"host":"b.example.com"}` + "\n"
	dir := t.TempDir()
	p := filepath.Join(dir, "subfinder.jsonl")
	if err := os.WriteFile(p, []byte(jsonl), 0o600); err != nil {
		t.Fatal(err)
	}
	hosts := parseSubfinderHosts(p)
	if len(hosts) != 2 || hosts[0] != "a.example.com" {
		t.Fatalf("hosts = %v", hosts)
	}
}
```

(Ensure `os`, `path/filepath` imported in recon_test.go.)

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run 'TestParseHttpxLive|TestParseSubfinderHosts' -v`
Expected: FAIL — undefined parsers.

- [ ] **Step 3: Write minimal implementation**

Add to `recon.go` the `httpxResult` type and the two JSONL parsers (read file, split lines, `json.Unmarshal` each non-empty line into a small struct, collect). Then implement `runRecon`:

- Build the candidate host list: `candidateHosts(req.Target)`; if `!isBareHostInput(req.Target)`, run subfinder (`subfinder -d <host> -silent -json -o <artifact>`), append `parseSubfinderHosts(artifact)`; dedup.
- Run httpx over the candidate list (write hosts to an input file, `httpx -silent -json -l <input> -o <artifact>`), `parseHttpxLive(artifact)` → the live set. If httpx finds none, fall back to treating the candidate hosts as live (so a reachable host that httpx misconfigures is not silently dropped) — record this in the httpx run's `Reason`.
- For each live host, run nmap (`nmap -sV -oX <artifact> <host>`), set the nmap `Run.ArtifactPath` to the XML, and populate that host's `HostEvidence.OpenPorts` via `parseNmap` (reuse the parser: map its `Finding.Endpoint`/`Title` back into `Port`).
- Assemble one `Scope` per live host: `s := HostScope(host)`, fill `s.Evidence` (LiveURLs, TLS from httpx; OpenPorts from nmap). Stamp all recon `Run`s with `Scope: reconScopeKey(req.Target)`.

Use `executeSpec` (already in pipeline.go) for running each tool so output capture, timeout, truncation, and secret redaction match the existing scanners. Each recon tool's `commandSpec` sets `timeout` from the matching `cfg.*Timeout`, `path` from `cfg.*Path`, `artifact` to the tool's output file under `req.ScanDir/scanner-output/<tool>`.

(The implementer writes the full parser + runRecon code here following these exact shapes; keep functions small and file focused.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run 'TestParseHttpxLive|TestParseSubfinderHosts' -v`
Expected: PASS

Then the whole package (runRecon must compile; it is exercised end-to-end in Task 6's fan-out test with fake tools):
Run: `CGO_ENABLED=0 go test ./internal/scanner/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/recon.go internal/scanner/recon_test.go
git commit -m "feat(scanner): run subfinder/httpx/nmap recon and build host scopes"
```

---

### Task 5: Recon runner descriptors (registry membership)

**Files:**
- Modify: `internal/scanner/recon.go` (add three `Runner` types)
- Test: `internal/scanner/recon_test.go`

**Interfaces:**
- Consumes: `Runner`, `Descriptor`, `PhaseRecon`, `WeightLight`.
- Produces: `subfinderRunner`, `httpxRunner`, `nmapRunner` types, each with `Name()`, `Descriptor()` (Phase `PhaseRecon`, no tracks, `WeightLight`), and a `Run` method that returns a single-tool `Run` (these satisfy the `Runner` interface for uniformity, but recon orchestration goes through `runRecon`; the individual `Run` methods delegate to the tool execution used by `runRecon`). If wiring each as a full `Runner` adds complexity without use, implement only `Name()`+`Descriptor()` and a `Run` that returns a `failed`/`not_applicable` guard — the orchestrator uses `runRecon`, not these directly.

> Implementer note: prefer the SIMPLER path — `runRecon` is the real entry point. Only add the three descriptor stubs so recon tools are nameable/among descriptors. Do NOT build parallel execution paths. If you find yourself duplicating `runRecon` logic inside the runner `Run` methods, stop and report DONE_WITH_CONCERNS.

- [ ] **Step 1: Write the failing test**

```go
// append to internal/scanner/recon_test.go
func TestReconRunnerDescriptors(t *testing.T) {
	rs := []Runner{subfinderRunner{}, httpxRunner{}, nmapRunner{}}
	for _, r := range rs {
		d := r.Descriptor()
		if d.Phase != PhaseRecon {
			t.Errorf("%s phase = %q, want recon", d.Name, d.Phase)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run TestReconRunnerDescriptors -v`
Expected: FAIL — undefined runner types.

- [ ] **Step 3: Write minimal implementation**

Add the three types with `Name()` returning `"subfinder"`/`"httpx"`/`"nmap"`, `Descriptor()` returning `Descriptor{Name: <name>, Phase: PhaseRecon, Weight: WeightLight}`, and a minimal `Run` guard (recon is driven by `runRecon`, so the direct `Run` returns `notApplicableRun(<name>, req, cfg, "recon runs via the recon phase", emit)`).

- [ ] **Step 4: Run test to verify it passes**

Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run TestReconRunnerDescriptors -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/recon.go internal/scanner/recon_test.go
git commit -m "feat(scanner): add recon runner descriptors"
```

---

### Task 6: Fan-out — restructure Pipeline.Run for recon → per-host scan

**Files:**
- Modify: `internal/scanner/pipeline.go` (`Pipeline.Run`)
- Test: `internal/scanner/pipeline_test.go`

**Interfaces:**
- Consumes: `runRecon`, `reconScopeKey`, `HostScope`, `resumeKey`, the existing per-runner execution.
- Produces: `Pipeline.Run` that (1) runs recon and appends its runs; (2) for each discovered host scope, runs the five scan runners against a per-scope request (`Request` copy with `Target = scope.Target`), stamping each run with `scope.Key()`; (3) preserves `(scope, scanner)` resume across recon and all host scopes. Run order: all recon runs first, then host scopes in discovery order, each with its five scan runs in pipeline order.

- [ ] **Step 1: Write the failing test**

```go
// append to internal/scanner/pipeline_test.go
// A pipeline built from fakeRunners plus an injected recon function that
// returns two host scopes must yield: recon runs + 2 * len(scan runners).
func TestPipelineFansOutPerHost(t *testing.T) {
	seen := map[string]int{}
	p := &Pipeline{Runners: []Runner{
		fakeRunner{name: "nuclei", seen: &seenCounter{m: seen}},
		fakeRunner{name: "zap", seen: &seenCounter{m: seen}},
	}}
	// Inject a recon stub via the pipeline's recon hook (see impl).
	p.reconFn = func(ctx context.Context, req Request, cfg Config, emit EmitFunc) ([]Scope, []Run) {
		now := time.Now().Format(time.RFC3339Nano)
		return []Scope{HostScope("a.example.com"), HostScope("b.example.com")},
			[]Run{{Scanner: "subfinder", Scope: reconScopeKey(req.Target), Status: "completed", StartedAt: now, FinishedAt: now}}
	}
	runs := p.Run(context.Background(), Request{Target: "example.com", ScanDir: t.TempDir()}, nil, nil)
	// 1 recon run + 2 hosts * 2 scan runners = 5
	if len(runs) != 5 {
		t.Fatalf("runs = %d, want 5", len(runs))
	}
	var hostScopes = map[string]int{}
	for _, r := range runs {
		if r.Scanner == "nuclei" || r.Scanner == "zap" {
			hostScopes[r.Scope]++
		}
	}
	if hostScopes["host:a.example.com"] != 2 || hostScopes["host:b.example.com"] != 2 {
		t.Fatalf("per-host scan runs wrong: %v", hostScopes)
	}
}
```

> Note: this task changes the `fakeRunner.seen` field to a small counter type `seenCounter{m map[string]int}` (or keep the existing `seen` shape and adapt the test). The implementer reconciles the test's `seen` usage with the existing `fakeRunner` definition — keep existing tests compiling.

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/scanner/ -run TestPipelineFansOutPerHost -v`
Expected: FAIL — `p.reconFn undefined`, run count wrong.

- [ ] **Step 3: Write minimal implementation**

Add a `reconFn` field to `Pipeline` defaulting to `runRecon`:

```go
type Pipeline struct {
	Config  Config
	Runners []Runner
	reconFn func(context.Context, Request, Config, EmitFunc) ([]Scope, []Run)
}
```

In `NewPipeline`, set `reconFn: runRecon`. In `Run`:

```go
func (p *Pipeline) Run(ctx context.Context, req Request, existing []Run, emit EmitFunc) []Run {
	recon := p.reconFn
	if recon == nil {
		recon = runRecon
	}
	byKey := indexTerminal(existing) // helper: map resumeKey->Run, empty scope folds to implicit
	out := make([]Run, 0)

	// Recon phase (reused on resume via reconScopeKey).
	scopes, reconRuns := recon(ctx, req, p.Config, emit)
	for _, rr := range reconRuns {
		if old, ok := byKey[resumeKey(rr.Scope, rr.Scanner)]; ok {
			out = append(out, old)
			continue
		}
		out = append(out, rr)
	}
	if len(scopes) == 0 {
		scopes = []Scope{HostScope(req.Target)} // degrade: single host
	}

	// Scan phase, fanned out per host scope.
	for _, sc := range scopes {
		scopeKey := sc.Key()
		hostReq := req
		hostReq.Target = sc.Target
		for i, runner := range p.Runners {
			if old, ok := byKey[resumeKey(scopeKey, runner.Name())]; ok {
				out = append(out, old)
				continue
			}
			if len(req.Scanners) > 0 && !slices.Contains(req.Scanners, runner.Name()) {
				out = append(out, skippedRun(runner.Name(), scopeKey, hostReq, emit))
				continue
			}
			if err := ctx.Err(); err != nil {
				for _, rest := range p.Runners[i:] {
					out = append(out, cancelledRun(rest.Name(), scopeKey, hostReq, err, emit))
				}
				break
			}
			run := runAttempt(ctx, runner, hostReq, p.Config, emit)
			run.Scope = scopeKey
			out = append(out, run)
		}
	}
	return out
}
```

Extract the previous inline skip/cancel record construction into `skippedRun`/`cancelledRun` helpers (each stamps scope) and `indexTerminal` (the Increment-1 legacy-fold logic). Keep behavior identical for the single-scope case so Increment-1 tests still pass (with a nil `reconFn` in `&Pipeline{}`-built test pipelines, `runRecon` runs; those tests build pipelines with `NewPipeline` or set `reconFn`). For existing `&Pipeline{Runners: ...}` tests that don't set `reconFn`, add `reconFn` returning the single implicit scope and no recon runs, OR have the nil-guard default produce the single implicit scope when `reconFn` is nil AND tools are fake — simplest: when `reconFn` is nil, use a built-in `singleScopeRecon` that returns `[]Scope{HostScope(req.Target)}, nil`. Then `NewPipeline` sets `reconFn = runRecon` explicitly.

> Implementer: reconcile so ALL Increment-1 pipeline_test.go tests pass unchanged. The cleanest route: nil `reconFn` → single implicit scope, no recon runs (preserves old behavior for the hand-built `&Pipeline{}` tests); `NewPipeline` sets the real `runRecon`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/scanner/...`
Expected: PASS — new fan-out test passes AND all Increment-1 tests (fixed order, skip, resume, cancellation) still pass.

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/pipeline.go internal/scanner/pipeline_test.go
git commit -m "feat(scanner): fan scan phase out per discovered host"
```

---

### Task 7: Update web callers — drop the fixed-count completeness gate

**Files:**
- Modify: `internal/web/report_ai.go` (`GenerateCLIReport`)
- Modify: `internal/web/scanner_handlers.go` (report regeneration handler)
- Test: `internal/web/report_ai_test.go` (adjust expectations)

**Interfaces:**
- Consumes: `scanner.Run.Terminal()`, `ScanRecord.Status`.
- Produces: completeness determined by "all runs terminal AND record finished", not by `len == len(OrderedNames)`.

- [ ] **Step 1: Write the failing test**

Adjust `report_ai_test.go` to pass a run set whose length is NOT 5 (e.g. recon runs + fanned host runs) and assert the report still generates. Add a case with a non-terminal run that still fails. (The implementer updates the existing test that builds exactly `len(OrderedNames)` runs.)

```go
// in report_ai_test.go — replace the exact-five construction with a variable set
runs := []scanner.Run{
	{Scanner: "subfinder", Scope: "recon:x", Status: "completed", StartedAt: "t", FinishedAt: "t"},
	{Scanner: "nuclei", Scope: "host:x", Status: "completed", StartedAt: "t", FinishedAt: "t"},
	{Scanner: "zap", Scope: "host:x", Status: "failed", StartedAt: "t", FinishedAt: "t"},
}
// ... expect GenerateCLIReport to succeed (all terminal), not error on count
```

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/web/ -run TestGenerateCLIReport -v`
Expected: FAIL — current code errors "expected five scanner statuses".

- [ ] **Step 3: Write minimal implementation**

In `GenerateCLIReport` remove:

```go
	if len(runs) != len(scanner.OrderedNames) {
		return "", fmt.Errorf("expected five scanner statuses, got %d", len(runs))
	}
```

and replace with a non-empty + terminal guard:

```go
	if len(runs) == 0 {
		return "", fmt.Errorf("no scanner runs to report")
	}
```

(the existing loop already enforces every run terminal). In `scanner_handlers.go`, replace the `len(rec.ScannerRuns) != len(scanner.OrderedNames)` conflict check with `len(rec.ScannerRuns) == 0 || rec.Status != "finished"` guarding the same 409, keeping the per-run terminal loop.

- [ ] **Step 4: Run tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/web/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/web/report_ai.go internal/web/scanner_handlers.go internal/web/report_ai_test.go
git commit -m "feat(web): gate report on terminal+finished, not fixed scanner count"
```

---

### Task 8: Whole-tree verification and report source-ID whitelist

**Files:**
- Modify (if needed): the reporting source-ID acceptance list so `nmap:` findings are not rejected (spec §6). Locate via `grep -rn "unknown source" internal/`.
- No other source changes expected.

**Interfaces:**
- Consumes: everything above.
- Produces: green build + affected suites; nmap findings survive report generation.

- [ ] **Step 1: Find and extend the source-ID acceptance**

Run: `grep -rniE "source.?id|unknown source|reject" internal/reporting internal/web | grep -v _test`
If a whitelist of scanner prefixes exists, add `nmap` (and confirm `subfinder`/`httpx` need no entry since they emit no findings). If acceptance is derived from `scanner.OrderedNames`, extend that derivation to include recon finding-producers (`nmap`). Add a test asserting an `nmap:` finding is retained.

- [ ] **Step 2: Build the whole module**

Run: `CGO_ENABLED=0 go build ./...`
Expected: success.

- [ ] **Step 3: Run affected suites**

Run: `CGO_ENABLED=0 go test ./internal/scanner/... ./internal/web/... ./internal/reporting/...`
Expected: PASS.

- [ ] **Step 4: Commit any fixups**

```bash
git add -A
git commit -m "feat(report): accept nmap recon findings"
```

---

## Self-Review

**1. Spec coverage (Increment 2 = spec §4 recon, §3.1 evidence, §6 nmap/recon parsers, §7 contract, §10 increment 2):**
- Recon phase subfinder→httpx→nmap (§4) → Tasks 3–6. ✅
- HostEvidence populated (§3.1) → Task 4. ✅
- Per-live-host fan-out (§4, §10) → Task 6. ✅
- nmap findings + evidence-only subfinder/httpx (§6) → Task 2, Task 8 whitelist. ✅
- Determinism contract / drop exactly-five (§7) → Task 7. ✅
- Recon tools as visible Run rows (locked decision) → Tasks 4–6. ✅
- Classifier/tracks, scheduler bounded parallelism, SAST, report grouping → deferred to Increments 3–6. Not gaps.

**2. Placeholder scan:** Tasks 1–3, 5, 7 contain complete code. Task 4's `runRecon` and Task 6's reconcile step give exact shapes/signatures and the algorithm but leave some assembly to the implementer — flagged explicitly with the exact function signatures, JSONL/XML formats, and the reuse of `executeSpec`/`parseNmap`. Task 8 is discovery-then-fix with the exact grep. These are the two genuinely integration-heavy tasks; they carry enough signatures to avoid guesswork but are not line-complete. Acceptable given they depend on runtime tool output shapes; the reviewer verifies against real fixtures.

**3. Type consistency:** `HostScope`/`Scope.Key()`/`resumeKey`/`PhaseRecon`/`WeightLight` (Increment 1) used consistently. `runRecon` signature identical in Task 4 (definition), Task 6 (`reconFn` type), and the fan-out test. `httpxResult`, `parseNmap`, `parseSubfinderHosts`, `parseHttpxLive` names consistent across tasks.

## Notes / risks
- Tasks 4 and 6 are the heaviest and least mechanical; consider a more capable model for those implementers.
- The `fakeRunner.seen` shape may need reconciling in Task 6 — keep Increment-1 tests compiling.
- Live tool execution (subfinder/httpx/nmap) is not unit-tested end-to-end here; unit tests cover the parsers and the fan-out with an injected `reconFn`. A later integration pass (or Increment 6) should add a real-tool smoke test.
