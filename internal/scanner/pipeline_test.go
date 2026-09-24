package scanner

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeRunner struct {
	name    string
	seen    *[]string
	gotDir  *[]string
	status  string
	cancel  context.CancelFunc
	tracks  []Track
	applies func(Scope) bool
}

func (f fakeRunner) Name() string { return f.name }
func (f fakeRunner) Descriptor() Descriptor {
	return Descriptor{Name: f.name, Phase: PhaseWeb, Weight: WeightLight, Tracks: f.tracks, Applies: f.applies}
}
func (f fakeRunner) Run(_ context.Context, req Request, _ Config, emit EmitFunc) Run {
	*f.seen = append(*f.seen, f.name)
	if f.gotDir != nil {
		*f.gotDir = append(*f.gotDir, req.ScanDir)
	}
	if f.cancel != nil {
		f.cancel()
	}
	r := Run{Scanner: f.name, Target: req.Target, Scope: req.Scope, Status: f.status}
	if r.Status == "" {
		r.Status = "completed"
	}
	if emit != nil {
		emit(Event{Type: "scanner_" + r.Status, Scanner: f.name, Run: r})
	}
	return r
}

func TestPipelineFixedOrderAndFailureContinuation(t *testing.T) {
	var seen []string
	// Host runners (Applies: appliesToHost) execute only on the host scope; the
	// appended source scope records each as not_applicable, so seen stays the
	// host-only execution order and the total doubles to two scopes worth of rows.
	p := &Pipeline{Runners: []Runner{
		fakeRunner{name: "nuclei", seen: &seen, applies: appliesToHost},
		fakeRunner{name: "zap", seen: &seen, status: "failed", applies: appliesToHost},
		fakeRunner{name: "testssl", seen: &seen, applies: appliesToHost},
		fakeRunner{name: "openvas", seen: &seen, applies: appliesToHost},
		fakeRunner{name: "trivy", seen: &seen, status: "not_applicable", applies: appliesToHost},
		fakeRunner{name: "vuls", seen: &seen, status: "not_applicable", applies: appliesToHost},
	}}
	runs := p.Run(context.Background(), Request{Target: "example.com"}, nil, nil)
	if !reflect.DeepEqual(seen, OrderedNames) {
		t.Fatalf("order = %v, want %v", seen, OrderedNames)
	}
	// 6 runners * (1 host scope + 1 source scope) = 12 rows.
	if len(runs) != 12 || runs[1].Status != "failed" || runs[2].Status != "completed" {
		t.Fatalf("unexpected runs: %#v", runs)
	}
}

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

func TestNormalizeScanners(t *testing.T) {
	got, err := NormalizeScanners([]string{"vuls", " ZAP ", "vuls", ""})
	if err != nil || !reflect.DeepEqual(got, []string{"zap", "vuls"}) {
		t.Fatalf("normalized = %v err = %v, want pipeline order without duplicates", got, err)
	}
	if got, err := NormalizeScanners(nil); err != nil || got != nil {
		t.Fatalf("empty selection = %v err = %v, want nil (whole pipeline)", got, err)
	}
	if got, err := NormalizeScanners([]string{"  "}); err != nil || got != nil {
		t.Fatalf("blank selection = %v err = %v, want nil (whole pipeline)", got, err)
	}
	if _, err := NormalizeScanners([]string{"nuclei", "nmap"}); err == nil {
		t.Fatal("an unknown scanner name must be rejected")
	}
}

func TestPipelineSelectionRecordsDeselectedScannersAsSkipped(t *testing.T) {
	var seen []string
	var events []Event
	p := &Pipeline{Runners: []Runner{
		fakeRunner{name: "nuclei", seen: &seen, applies: appliesToHost}, fakeRunner{name: "zap", seen: &seen, applies: appliesToHost},
		fakeRunner{name: "testssl", seen: &seen, applies: appliesToHost}, fakeRunner{name: "openvas", seen: &seen, applies: appliesToHost},
		fakeRunner{name: "trivy", seen: &seen, applies: appliesToHost}, fakeRunner{name: "vuls", seen: &seen, applies: appliesToHost},
	}}
	runs := p.Run(context.Background(), Request{Target: "example.com", Scanners: []string{"nuclei", "trivy"}}, nil,
		func(e Event) { events = append(events, e) })

	if !reflect.DeepEqual(seen, []string{"nuclei", "trivy"}) {
		t.Fatalf("executed %v, want only the selected scanners", seen)
	}
	// The source scope adds a second scope's worth of rows; assert the deselection
	// bookkeeping on the host scope, which is the first len(OrderedNames) rows.
	if len(runs) != 2*len(OrderedNames) {
		t.Fatalf("runs = %d, want %d", len(runs), 2*len(OrderedNames))
	}
	for i, run := range runs[:len(OrderedNames)] {
		if run.Scanner != OrderedNames[i] {
			t.Fatalf("run %d = %s, want %s", i, run.Scanner, OrderedNames[i])
		}
		if !run.Terminal() {
			t.Fatalf("%s is not terminal: %#v", run.Scanner, run)
		}
		wantSkipped := run.Scanner != "nuclei" && run.Scanner != "trivy"
		if wantSkipped && run.Status != "skipped" {
			t.Errorf("%s status = %q, want skipped", run.Scanner, run.Status)
		}
		if wantSkipped && run.Reason == "" {
			t.Errorf("%s was skipped without a recorded reason", run.Scanner)
		}
		if !wantSkipped && run.Status != "completed" {
			t.Errorf("%s status = %q, want completed", run.Scanner, run.Status)
		}
	}
	skippedEvents := 0
	for _, e := range events {
		if e.Type == "scanner_skipped" {
			skippedEvents++
		}
	}
	// 4 deselected scanners per scope * 2 scopes (host + source) = 8.
	if skippedEvents != 8 {
		t.Errorf("scanner_skipped events = %d, want 8", skippedEvents)
	}
}

func TestPipelineResumeKeepsTerminalRunImmutable(t *testing.T) {
	var seen []string
	p := &Pipeline{Runners: []Runner{
		fakeRunner{name: "nuclei", seen: &seen, applies: appliesToHost}, fakeRunner{name: "zap", seen: &seen, applies: appliesToHost},
		fakeRunner{name: "openvas", seen: &seen, applies: appliesToHost}, fakeRunner{name: "trivy", seen: &seen, applies: appliesToHost}, fakeRunner{name: "vuls", seen: &seen, applies: appliesToHost},
	}}
	old := Run{Scanner: "nuclei", Target: "old", Status: "completed", Checksum: "immutable"}
	runs := p.Run(context.Background(), Request{Target: "example.com"}, []Run{old}, nil)
	if reflect.DeepEqual(seen, OrderedNames) || len(seen) != 4 || seen[0] != "zap" {
		t.Fatalf("resume executed %v", seen)
	}
	if runs[0].Checksum != "immutable" || runs[0].Target != "old" {
		t.Fatalf("terminal run mutated: %#v", runs[0])
	}
}

func TestPipelineCancellationPreventsRemainingAttempts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var seen []string
	p := &Pipeline{Runners: []Runner{
		fakeRunner{name: "nuclei", seen: &seen, cancel: cancel}, fakeRunner{name: "zap", seen: &seen},
		fakeRunner{name: "openvas", seen: &seen}, fakeRunner{name: "trivy", seen: &seen}, fakeRunner{name: "vuls", seen: &seen},
	}}
	runs := p.Run(ctx, Request{Target: "example.com"}, nil, nil)
	if !reflect.DeepEqual(seen, []string{"nuclei"}) {
		t.Fatalf("executed after cancellation: %v", seen)
	}
	// 5 runners * (1 host scope + 1 source scope) = 10 rows; the source runners
	// (applies unset -> apply to any scope) are also recorded cancelled.
	if len(runs) != 10 {
		t.Fatalf("got %d statuses, want ten", len(runs))
	}
	for _, run := range runs[1:] {
		if run.Status != "cancelled" {
			t.Fatalf("remaining status = %q", run.Status)
		}
	}
}

func TestApplicabilityAndArguments(t *testing.T) {
	cfg := Config{RateRPS: 17, ScanHeaders: []string{"X-Test: yes"}}
	n := buildNuclei(Request{Target: "https://example.com", ScanDir: t.TempDir()}, cfg)
	joined := strings.Join(n.args, " ")
	for _, want := range []string{"-u https://example.com", "-rl 17", "-H X-Test: yes", "-duc", "-dut"} {
		if !strings.Contains(joined, want) {
			t.Errorf("nuclei args %q missing %q", joined, want)
		}
	}
	if got := buildNuclei(Request{Target: "artifact://filesystem"}, cfg).notApp; got == "" {
		t.Error("artifact-only Nuclei must be not applicable")
	}
	if got := buildTrivy(Request{}, cfg).notApp; got == "" {
		t.Error("missing Trivy artifact must be not applicable")
	}
	trivy := buildTrivy(Request{ScanDir: t.TempDir(), Artifact: Artifact{Kind: "image", Ref: "alpine:3"}}, cfg)
	if got := strings.Join(trivy.args, " "); !strings.Contains(got, "image --format json") || !strings.HasSuffix(got, "alpine:3") {
		t.Fatalf("trivy args = %q", got)
	}
	if got := buildVuls(Request{}, cfg).notApp; got == "" {
		t.Error("missing SSH alias must be not applicable")
	}
	vuls := vulsConfig("prod-web", "/operator/.ssh/config")
	if !strings.Contains(vuls, `scanMode = ["fast"]`) || !strings.Contains(vuls, `sshConfigPath = "/operator/.ssh/config"`) {
		t.Fatalf("Vuls config is not fixed fast/SSH-alias mode: %s", vuls)
	}
}

func TestRedactionAndOutputLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	var seq atomicInt64Adapter
	_ = seq
	// Exercise the stable helpers directly; command output uses these helpers.
	if got := redact("token=supersecret", []string{"supersecret"}); strings.Contains(got, "supersecret") {
		t.Fatalf("secret leaked: %q", got)
	}
	truncated := false
	if got := capOutput([]byte("123456"), 4, &truncated); string(got) != "1234" || !truncated {
		t.Fatalf("limit result = %q truncated=%v", got, truncated)
	}
	_ = f.Close()
}

func TestFakeBinaryRawStreamingRedactionAndLimit(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-scanner")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf 'secret-token-abcdefghijklmnopqrstuvwxyz'\nprintf 'stderr-line' >&2\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	var events []Event
	run := executeSpec(context.Background(), "nuclei", Request{Target: "example.test", ScanDir: dir}, Config{MaxOutputBytes: 18, ZAPAPIKey: "secret-token", NucleiTimeout: 10 * time.Second}, commandSpec{path: bin, timeout: 10 * time.Second}, func(e Event) { events = append(events, e) })
	if run.Status != "completed" || !run.Truncated {
		t.Fatalf("run = %#v", run)
	}
	data, err := os.ReadFile(run.StdoutPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret-token") {
		t.Fatalf("credential leaked: %q", data)
	}
	if len(data) > 18 {
		t.Fatalf("output limit exceeded: %d", len(data))
	}
	foundOutput := false
	for _, event := range events {
		if event.Type == "scanner_output" {
			foundOutput = true
		}
	}
	if !foundOutput {
		t.Error("raw scanner output was not streamed")
	}
}

// Kept as a named type so this test does not reach into outputWriter's atomic implementation.
type atomicInt64Adapter struct{}

func TestRunStampsImplicitScope(t *testing.T) {
	p := NewPipeline(Config{})
	// Inject a deterministic recon stub so this test needs no real recon tools:
	// a single implicit host scope and no recon runs (pre-fan-out behavior).
	p.reconFn = func(context.Context, Request, Config, EmitFunc) ([]Scope, []Run) {
		return []Scope{HostScope("example.com")}, nil
	}
	// Only run the "skipped" bookkeeping path so the test needs no real tools:
	// select a scanner subset of one, leaving the rest skipped.
	req := Request{Target: "example.com", Scanners: []string{"nuclei"}, ScanDir: t.TempDir()}
	// Cancel immediately so nuclei is recorded cancelled, not actually executed.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runs := p.Run(ctx, req, nil, nil)
	// One host scope + one appended source scope, each with len(p.Runners) rows.
	if len(runs) != 2*len(p.Runners) {
		t.Fatalf("run count = %d, want %d", len(runs), 2*len(p.Runners))
	}
	hostKey := HostScope("example.com").Key()
	for _, r := range runs {
		// Every run carries its scope: host rows the implicit host scope, source
		// rows the single source scope.
		if r.Scope != hostKey && r.Scope != sourceScopeID {
			t.Errorf("%s scope = %q, want %q or %q", r.Scanner, r.Scope, hostKey, sourceScopeID)
		}
	}
}

func TestResumeReusesLegacyEmptyScopeRuns(t *testing.T) {
	p := NewPipeline(Config{})
	// Inject a deterministic recon stub so this test needs no real recon tools:
	// a single implicit host scope and no recon runs (pre-fan-out behavior).
	p.reconFn = func(context.Context, Request, Config, EmitFunc) ([]Scope, []Run) {
		return []Scope{HostScope("example.com")}, nil
	}
	// A legacy terminal run with empty Scope must be reused (not re-run).
	legacy := Run{Scanner: "nuclei", Target: "example.com", Status: "completed"}
	req := Request{Target: "example.com", Scanners: []string{"nuclei"}, ScanDir: t.TempDir()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runs := p.Run(ctx, req, []Run{legacy}, nil)
	var got *Run
	for i := range runs {
		// The source scope also yields a nuclei row (not_applicable); assert on the
		// host-scope row. The reused legacy run keeps its original empty Scope, so it
		// is identified as the non-source nuclei row.
		if runs[i].Scanner == "nuclei" && runs[i].Scope != sourceScopeID {
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

func TestPipelineFansOutPerHost(t *testing.T) {
	seen := []string{}
	p := &Pipeline{Runners: []Runner{
		fakeRunner{name: "nuclei", seen: &seen},
		fakeRunner{name: "zap", seen: &seen},
	}}
	// Inject a recon stub returning two host scopes plus one recon run.
	p.reconFn = func(ctx context.Context, req Request, cfg Config, emit EmitFunc) ([]Scope, []Run) {
		now := time.Now().Format(time.RFC3339Nano)
		return []Scope{HostScope("a.example.com"), HostScope("b.example.com")},
			[]Run{{Scanner: "subfinder", Scope: reconScopeKey(req.Target), Status: "completed", StartedAt: now, FinishedAt: now}}
	}
	runs := p.Run(context.Background(), Request{Target: "example.com", ScanDir: t.TempDir()}, nil, nil)
	// 1 recon run + (2 hosts + 1 source) scopes * 2 scan runners = 7.
	reconRuns := 1
	if want := reconRuns + 3*len(p.Runners); len(runs) != want {
		t.Fatalf("runs = %d, want %d", len(runs), want)
	}
	hostScopes := map[string]int{}
	for _, r := range runs {
		if r.Scanner == "nuclei" || r.Scanner == "zap" {
			hostScopes[r.Scope]++
		}
	}
	if hostScopes["host:a.example.com"] != 2 || hostScopes["host:b.example.com"] != 2 {
		t.Fatalf("per-host scan runs wrong: %v", hostScopes)
	}
	// Recon runs come first and carry the recon scope.
	if runs[0].Scanner != "subfinder" || runs[0].Scope != reconScopeKey("example.com") {
		t.Fatalf("first run = %#v, want subfinder in recon scope", runs[0])
	}
}

// TestPipelineSourceScopeFanOut proves the appended source scope produces one row
// per runner, that host runners are not_applicable on it, and that a source
// runner is not_applicable on host scopes.
func TestPipelineSourceScopeFanOut(t *testing.T) {
	var seen []string
	p := &Pipeline{Runners: []Runner{
		fakeRunner{name: "nuclei", seen: &seen, applies: appliesToHost},
		fakeRunner{name: "trivy", seen: &seen, applies: appliesToSource},
	}}
	p.reconFn = func(context.Context, Request, Config, EmitFunc) ([]Scope, []Run) {
		return []Scope{HostScope("a.example.com")}, nil
	}
	runs := p.Run(context.Background(), Request{Target: "a.example.com", ScanDir: t.TempDir()}, nil, nil)
	// (1 host scope + 1 source scope) * 2 runners = 4 rows.
	if want := 2 * len(p.Runners); len(runs) != want {
		t.Fatalf("runs = %d, want %d", len(runs), want)
	}
	byScopeScanner := map[string]string{}
	for _, r := range runs {
		byScopeScanner[r.Scope+"/"+r.Scanner] = r.Status
	}
	// Host runner (nuclei) executes on the host scope, not_applicable on source.
	if got := byScopeScanner["host:a.example.com/nuclei"]; got != "completed" {
		t.Errorf("nuclei on host = %q, want completed", got)
	}
	if got := byScopeScanner[sourceScopeID+"/nuclei"]; got != "not_applicable" {
		t.Errorf("nuclei on source = %q, want not_applicable", got)
	}
	// Source runner (trivy) is not_applicable on the host scope, executes on source.
	if got := byScopeScanner["host:a.example.com/trivy"]; got != "not_applicable" {
		t.Errorf("trivy on host = %q, want not_applicable", got)
	}
	if got := byScopeScanner[sourceScopeID+"/trivy"]; got != "completed" {
		t.Errorf("trivy on source = %q, want completed", got)
	}
	// Only the applicable runners actually executed.
	if !reflect.DeepEqual(seen, []string{"nuclei", "trivy"}) {
		t.Errorf("executed %v, want [nuclei trivy]", seen)
	}
}

func TestPipelineIsolatesPerHostScanDirs(t *testing.T) {
	seen := []string{}
	dirs := []string{}
	root := t.TempDir()
	p := &Pipeline{Runners: []Runner{
		// Host runner: executes per host only, not on the appended source scope.
		fakeRunner{name: "nuclei", seen: &seen, gotDir: &dirs, applies: appliesToHost},
	}}
	p.reconFn = func(context.Context, Request, Config, EmitFunc) ([]Scope, []Run) {
		return []Scope{HostScope("a.example.com"), HostScope("b.example.com")}, nil
	}
	p.Run(context.Background(), Request{Target: "example.com", ScanDir: root}, nil, nil)
	if len(dirs) != 2 {
		t.Fatalf("scan runner invoked %d times, want 2", len(dirs))
	}
	if dirs[0] == dirs[1] {
		t.Fatalf("both hosts shared ScanDir %q; artifacts would collide", dirs[0])
	}
	wantA := filepath.Join(root, "hosts", sanitizeHost("a.example.com"))
	wantB := filepath.Join(root, "hosts", sanitizeHost("b.example.com"))
	if dirs[0] != wantA || dirs[1] != wantB {
		t.Fatalf("per-host ScanDirs = %v, want [%q %q]", dirs, wantA, wantB)
	}
}

func TestPipelineReusesReconOnResume(t *testing.T) {
	seen := []string{}
	p := &Pipeline{Runners: []Runner{
		fakeRunner{name: "nuclei", seen: &seen, applies: appliesToHost},
	}}
	called := false
	p.reconFn = func(context.Context, Request, Config, EmitFunc) ([]Scope, []Run) {
		called = true
		t.Error("reconFn must not run on resume with prior recon runs")
		return nil, nil
	}
	scanDir := t.TempDir()
	// Persist the discovered scope set so resume exercises the recon-scopes.json path.
	saveReconScopes(scanDir, []Scope{HostScope("a.example.com")})
	existing := []Run{
		{Scanner: "subfinder", Scope: reconScopeKey("example.com"), Status: "completed"},
		{Scanner: "nuclei", Scope: "host:a.example.com", Target: "a.example.com", Status: "completed", Checksum: "immutable"},
	}
	runs := p.Run(context.Background(), Request{Target: "example.com", ScanDir: scanDir}, existing, nil)
	if called {
		t.Fatal("reconFn was invoked on resume")
	}
	if len(seen) != 0 {
		t.Fatalf("scan runner re-executed on resume: %v", seen)
	}
	var nuclei *Run
	for i := range runs {
		if runs[i].Scanner == "nuclei" && runs[i].Scope == "host:a.example.com" {
			nuclei = &runs[i]
		}
	}
	if nuclei == nil {
		t.Fatal("completed nuclei run for host:a.example.com was dropped on resume")
	}
	if nuclei.Status != "completed" || nuclei.Checksum != "immutable" {
		t.Fatalf("reused run mutated: %#v", *nuclei)
	}
}

func TestPipelineResumeScansUnstartedDiscoveredHost(t *testing.T) {
	seen := []string{}
	p := &Pipeline{Runners: []Runner{
		fakeRunner{name: "nuclei", seen: &seen, applies: appliesToHost},
	}}
	p.reconFn = func(context.Context, Request, Config, EmitFunc) ([]Scope, []Run) {
		t.Error("reconFn must not run when the discovered scope set is persisted")
		return nil, nil
	}
	scanDir := t.TempDir()
	// recon discovered TWO hosts; only host a has a completed scan run so far.
	saveReconScopes(scanDir, []Scope{HostScope("a.example.com"), HostScope("b.example.com")})
	existing := []Run{
		{Scanner: "subfinder", Scope: reconScopeKey("example.com"), Status: "completed"},
		{Scanner: "nuclei", Scope: "host:a.example.com", Target: "a.example.com", Status: "completed", Checksum: "immutable"},
	}
	runs := p.Run(context.Background(), Request{Target: "example.com", ScanDir: scanDir}, existing, nil)
	// host a is reused (not re-run); host b — discovered but unstarted — is scanned.
	if !reflect.DeepEqual(seen, []string{"nuclei"}) {
		t.Fatalf("executed %v, want only b's nuclei (a reused, b scanned)", seen)
	}
	byScope := map[string]Run{}
	for _, r := range runs {
		if r.Scanner == "nuclei" {
			byScope[r.Scope] = r
		}
	}
	a, okA := byScope["host:a.example.com"]
	b, okB := byScope["host:b.example.com"]
	if !okA || !okB {
		t.Fatalf("missing a host: got scopes %v (unstarted host b must not be dropped)", byScope)
	}
	if a.Status != "completed" || a.Checksum != "immutable" {
		t.Fatalf("host a run not reused immutably: %#v", a)
	}
	if b.Status != "completed" || b.Target != "b.example.com" {
		t.Fatalf("host b run not freshly scanned: %#v", b)
	}
}

func TestPipelineResumePreservesPerHostNmapRuns(t *testing.T) {
	p := &Pipeline{Runners: nil}
	// Resume must never re-invoke recon when a prior scan already completed it.
	p.reconFn = func(context.Context, Request, Config, EmitFunc) ([]Scope, []Run) {
		t.Error("reconFn must not run on resume with persisted per-host recon runs")
		return nil, nil
	}
	scanDir := t.TempDir()
	// recon discovered two hosts; both host scopes are persisted for lossless resume.
	saveReconScopes(scanDir, []Scope{HostScope("a.example.com"), HostScope("b.example.com")})
	// The prior recon produced one singleton subfinder run plus one nmap run per
	// host, each on its OWN host-unique recon scope and its own artifact path.
	existing := []Run{
		{Scanner: "subfinder", Scope: reconScopeKey("example.com"), Status: "completed"},
		{Scanner: "nmap", Scope: reconHostScopeKey("example.com", "a.example.com"), Target: "a.example.com", Status: "completed", ArtifactPath: "/scan/nmap/a/nmap.xml", Checksum: "chk-a"},
		{Scanner: "nmap", Scope: reconHostScopeKey("example.com", "b.example.com"), Target: "b.example.com", Status: "completed", ArtifactPath: "/scan/nmap/b/nmap.xml", Checksum: "chk-b"},
	}
	runs := p.Run(context.Background(), Request{Target: "example.com", ScanDir: scanDir}, existing, nil)

	// Both per-host nmap runs must survive resume exactly once — neither dropped
	// (host A lost) nor duplicated (host B doubled), which is what a shared resume
	// key would cause.
	byScope := map[string]int{}
	var artifacts []string
	for _, r := range runs {
		if r.Scanner == "nmap" {
			byScope[r.Scope]++
			artifacts = append(artifacts, r.ArtifactPath)
		}
	}
	keyA := reconHostScopeKey("example.com", "a.example.com")
	keyB := reconHostScopeKey("example.com", "b.example.com")
	if byScope[keyA] != 1 || byScope[keyB] != 1 {
		t.Fatalf("per-host nmap runs = %v, want each of %q and %q exactly once", byScope, keyA, keyB)
	}
	if len(artifacts) != 2 || artifacts[0] == artifacts[1] {
		t.Fatalf("nmap artifact paths = %v, want two distinct per-host artifacts", artifacts)
	}
}

func TestPipelineClassifierGatesTracks(t *testing.T) {
	var seen []string
	// nuclei is web-track, vuls is server-track (real descriptors via NewPipeline).
	p := NewPipeline(Config{})
	// Keep only nuclei (web) and vuls (server) to make assertions crisp.
	var runners []Runner
	for _, r := range p.Runners {
		switch r.Name() {
		case "nuclei":
			runners = append(runners, fakeRunner{name: r.Name(), seen: &seen, tracks: []Track{TrackWeb}, applies: appliesToHost})
		case "vuls":
			runners = append(runners, fakeRunner{name: r.Name(), seen: &seen, tracks: []Track{TrackServer}, applies: appliesToHost})
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
		if r.Scope == sourceScopeID { // host-track assertions ignore the source scope
			continue
		}
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

func TestPipelineFailOpenEmptyEvidence(t *testing.T) {
	var seen []string
	// nuclei is web-track, vuls is server-track (real descriptors via NewPipeline).
	p := NewPipeline(Config{})
	var runners []Runner
	for _, r := range p.Runners {
		switch r.Name() {
		case "nuclei":
			runners = append(runners, fakeRunner{name: r.Name(), seen: &seen, tracks: []Track{TrackWeb}, applies: appliesToHost})
		case "vuls":
			runners = append(runners, fakeRunner{name: r.Name(), seen: &seen, tracks: []Track{TrackServer}, applies: appliesToHost})
		}
	}
	p2 := &Pipeline{Runners: runners}
	// One host with no recon evidence at all (recon degraded/absent).
	p2.reconFn = func(context.Context, Request, Config, EmitFunc) ([]Scope, []Run) {
		return []Scope{HostScope("x")}, nil
	}
	runs := p2.Run(context.Background(), Request{Target: "x", ScanDir: t.TempDir()}, nil, nil)
	byScanner := map[string]string{}
	for _, r := range runs {
		if r.Scope == sourceScopeID { // fail-open assertions concern the host scope only
			continue
		}
		byScanner[r.Scanner] = r.Status
	}
	// Fail open: both web and server tracks are scanned, so neither is
	// not_applicable and both actually executed.
	if byScanner["nuclei"] == "not_applicable" {
		t.Errorf("nuclei status = %q, want not not_applicable (fail open)", byScanner["nuclei"])
	}
	if byScanner["vuls"] == "not_applicable" {
		t.Errorf("vuls status = %q, want not not_applicable (fail open)", byScanner["vuls"])
	}
	sawNuclei, sawVuls := false, false
	for _, n := range seen {
		if n == "nuclei" {
			sawNuclei = true
		}
		if n == "vuls" {
			sawVuls = true
		}
	}
	if !sawNuclei {
		t.Errorf("nuclei should have executed for a host with empty evidence (fail open)")
	}
	if !sawVuls {
		t.Errorf("vuls should have executed for a host with empty evidence (fail open)")
	}
}

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

func TestApplyDefaultsMaxWorkers(t *testing.T) {
	if got := NewPipeline(Config{}).Config.MaxWorkers; got != 3 {
		t.Fatalf("MaxWorkers default = %d, want 3", got)
	}
	if got := NewPipeline(Config{MaxWorkers: 8}).Config.MaxWorkers; got != 8 {
		t.Fatalf("MaxWorkers override = %d, want 8", got)
	}
}

func TestEmittedEventsCarryScope(t *testing.T) {
	var seen []string
	var events []Event
	p := &Pipeline{Runners: []Runner{fakeRunner{name: "nuclei", seen: &seen, applies: appliesToHost}}}
	p.reconFn = func(context.Context, Request, Config, EmitFunc) ([]Scope, []Run) {
		return []Scope{HostScope("a.example.com")}, nil
	}
	_ = p.Run(context.Background(), Request{Target: "a.example.com", ScanDir: t.TempDir()}, nil, func(e Event) {
		events = append(events, e)
	})
	// The fakeRunner emits an event on the host scope; assert it carries the host
	// scope. (nuclei is also emitted not_applicable on the source scope, which
	// carries the source scope — that is expected and not what this test asserts.)
	found := false
	for _, e := range events {
		if e.Scanner == "nuclei" && e.Run.Scope == "host:a.example.com" {
			found = true
		}
	}
	if !found {
		t.Fatal("no host-scoped nuclei event observed")
	}
}

func TestFailedServiceRunCarriesScope(t *testing.T) {
	var got Event
	r := failedServiceRun("zap", Request{Target: "x", Scope: "host:x", ScanDir: t.TempDir()}, "boom", func(e Event) { got = e })
	if r.Scope != "host:x" {
		t.Fatalf("returned run scope = %q, want host:x", r.Scope)
	}
	if got.Run.Scope != "host:x" {
		t.Fatalf("emitted event scope = %q, want host:x", got.Run.Scope)
	}
}

// TestScanPhaseResultOrderStable locks the scope-major, runner-minor ordering of
// scan-phase results. Task 4 parallelizes execution but MUST keep this order.
func TestScanPhaseResultOrderStable(t *testing.T) {
	var seen []string
	p := &Pipeline{Runners: []Runner{
		fakeRunner{name: "nuclei", seen: &seen}, fakeRunner{name: "vuls", seen: &seen},
	}}
	p.reconFn = func(context.Context, Request, Config, EmitFunc) ([]Scope, []Run) {
		return []Scope{HostScope("a"), HostScope("b")}, nil
	}
	runs := p.Run(context.Background(), Request{Target: "t", ScanDir: t.TempDir()}, nil, nil)
	// Expect scope-major, runner-minor order across host scopes then the appended
	// source scope: (a,nuclei),(a,vuls),(b,nuclei),(b,vuls),(source,nuclei),(source,vuls).
	var got []string
	for _, r := range runs {
		got = append(got, r.Scope+"/"+r.Scanner)
	}
	want := []string{"host:a/nuclei", "host:a/vuls", "host:b/nuclei", "host:b/vuls", "source:main/nuclei", "source:main/vuls"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

// concGauge records max observed concurrency (overall and heavy-only) so the
// scheduler's worker bound and heavy-tool exclusivity can be asserted
// deterministically without -race.
type concGauge struct {
	mu       sync.Mutex
	cur, max int
	heavyCur int
	heavyMax int
}

func (g *concGauge) enter(heavy bool) {
	g.mu.Lock()
	g.cur++
	if g.cur > g.max {
		g.max = g.cur
	}
	if heavy {
		g.heavyCur++
		if g.heavyCur > g.heavyMax {
			g.heavyMax = g.heavyCur
		}
	}
	g.mu.Unlock()
}

func (g *concGauge) leave(heavy bool) {
	g.mu.Lock()
	g.cur--
	if heavy {
		g.heavyCur--
	}
	g.mu.Unlock()
}

type gaugeRunner struct {
	name  string
	heavy bool
	g     *concGauge
}

func (r gaugeRunner) Name() string { return r.name }
func (r gaugeRunner) Descriptor() Descriptor {
	w := WeightLight
	if r.heavy {
		w = WeightHeavy
	}
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
	// 3 host scopes + 1 appended source scope = 4 scopes; gaugeRunners have no
	// Applies predicate, so they run on every scope.
	if len(runs) != 4*len(runners) {
		t.Errorf("runs = %d, want %d", len(runs), 4*len(runners))
	}
}

// TestEmitCallbackNeverInvokedConcurrently proves the pipeline serializes every
// emit invocation across the concurrent scan-phase workers. Real emit sinks (the
// web session record) mutate shared state per event with no locking of their own,
// so a concurrent entry would corrupt scan.json or panic. The callback widens its
// window with a small sleep so overlap is observed deterministically at 3 workers
// without -race (which cannot run on this Darwin host).
func TestEmitCallbackNeverInvokedConcurrently(t *testing.T) {
	var active, raced int32
	emit := func(Event) {
		if n := atomic.AddInt32(&active, 1); n > 1 {
			atomic.StoreInt32(&raced, 1)
		}
		time.Sleep(2 * time.Millisecond)
		atomic.AddInt32(&active, -1)
	}
	var s1, s2, s3 []string
	p := &Pipeline{Config: Config{MaxWorkers: 3}, Runners: []Runner{
		fakeRunner{name: "r1", seen: &s1},
		fakeRunner{name: "r2", seen: &s2},
		fakeRunner{name: "r3", seen: &s3},
	}}
	p.reconFn = func(context.Context, Request, Config, EmitFunc) ([]Scope, []Run) {
		return []Scope{HostScope("a")}, nil
	}
	p.Run(context.Background(), Request{Target: "t", ScanDir: t.TempDir()}, nil, emit)
	if atomic.LoadInt32(&raced) != 0 {
		t.Fatalf("emit callback was invoked concurrently across scan-phase workers")
	}
}
