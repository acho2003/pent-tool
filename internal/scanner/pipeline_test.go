package scanner

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	name   string
	seen   *[]string
	status string
	cancel context.CancelFunc
}

func (f fakeRunner) Name() string { return f.name }
func (f fakeRunner) Descriptor() Descriptor {
	return Descriptor{Name: f.name, Phase: PhaseWeb, Weight: WeightLight}
}
func (f fakeRunner) Run(_ context.Context, req Request, _ Config, emit EmitFunc) Run {
	*f.seen = append(*f.seen, f.name)
	if f.cancel != nil {
		f.cancel()
	}
	r := Run{Scanner: f.name, Target: req.Target, Status: f.status}
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
	p := &Pipeline{Runners: []Runner{
		fakeRunner{name: "nuclei", seen: &seen},
		fakeRunner{name: "zap", seen: &seen, status: "failed"},
		fakeRunner{name: "openvas", seen: &seen},
		fakeRunner{name: "trivy", seen: &seen, status: "not_applicable"},
		fakeRunner{name: "vuls", seen: &seen, status: "not_applicable"},
	}}
	runs := p.Run(context.Background(), Request{Target: "example.com"}, nil, nil)
	if !reflect.DeepEqual(seen, OrderedNames) {
		t.Fatalf("order = %v, want %v", seen, OrderedNames)
	}
	if len(runs) != 5 || runs[1].Status != "failed" || runs[2].Status != "completed" {
		t.Fatalf("unexpected runs: %#v", runs)
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
		fakeRunner{name: "nuclei", seen: &seen}, fakeRunner{name: "zap", seen: &seen},
		fakeRunner{name: "openvas", seen: &seen}, fakeRunner{name: "trivy", seen: &seen}, fakeRunner{name: "vuls", seen: &seen},
	}}
	runs := p.Run(context.Background(), Request{Target: "example.com", Scanners: []string{"nuclei", "trivy"}}, nil,
		func(e Event) { events = append(events, e) })

	if !reflect.DeepEqual(seen, []string{"nuclei", "trivy"}) {
		t.Fatalf("executed %v, want only the selected scanners", seen)
	}
	// Every scanner still reports a terminal status, in pipeline order.
	if len(runs) != len(OrderedNames) {
		t.Fatalf("runs = %d, want %d", len(runs), len(OrderedNames))
	}
	for i, run := range runs {
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
	if skippedEvents != 3 {
		t.Errorf("scanner_skipped events = %d, want 3", skippedEvents)
	}
}

func TestPipelineResumeKeepsTerminalRunImmutable(t *testing.T) {
	var seen []string
	p := &Pipeline{Runners: []Runner{
		fakeRunner{name: "nuclei", seen: &seen}, fakeRunner{name: "zap", seen: &seen},
		fakeRunner{name: "openvas", seen: &seen}, fakeRunner{name: "trivy", seen: &seen}, fakeRunner{name: "vuls", seen: &seen},
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
	if len(runs) != 5 {
		t.Fatalf("got %d statuses, want five", len(runs))
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
