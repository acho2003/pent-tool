package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Pipeline struct {
	Config  Config
	Runners []Runner
	// reconFn discovers host scopes and returns the recon-phase runs. NewPipeline
	// wires the real runRecon; a hand-built &Pipeline{} leaves it nil, which Run
	// falls back to singleScopeRecon so tests keep their single implicit scope.
	reconFn func(context.Context, Request, Config, EmitFunc) ([]Scope, []Run)
}

func NewPipeline(cfg Config) *Pipeline {
	applyDefaults(&cfg)
	return &Pipeline{Config: cfg, reconFn: runRecon, Runners: []Runner{
		commandRunner{name: "nuclei", desc: Descriptor{Name: "nuclei", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightLight}, build: buildNuclei},
		zapRunner{},
		openVASRunner{},
		commandRunner{name: "trivy", desc: Descriptor{Name: "trivy", Phase: PhaseSAST, Weight: WeightLight}, build: buildTrivy},
		vulsRunner{},
	}}
}

// singleScopeRecon is the nil-reconFn fallback: it discovers no new hosts and
// runs no recon commands, so Run scans the single implicit host scope exactly as
// it did before recon fan-out existed.
func singleScopeRecon(_ context.Context, req Request, _ Config, _ EmitFunc) ([]Scope, []Run) {
	return []Scope{HostScope(req.Target)}, nil
}

func applyDefaults(cfg *Config) {
	if cfg.NucleiPath == "" {
		cfg.NucleiPath = "nuclei"
	}
	if cfg.TrivyPath == "" {
		cfg.TrivyPath = "trivy"
	}
	if cfg.VulsPath == "" {
		cfg.VulsPath = "vuls"
	}
	if cfg.SubfinderPath == "" {
		cfg.SubfinderPath = "subfinder"
	}
	if cfg.HttpxPath == "" {
		cfg.HttpxPath = "httpx"
	}
	if cfg.NmapPath == "" {
		cfg.NmapPath = "nmap"
	}
	if cfg.GVMPort == 0 {
		cfg.GVMPort = 9390
	}
	if cfg.RateRPS <= 0 {
		cfg.RateRPS = 10
	}
	if cfg.MaxOutputBytes <= 0 {
		cfg.MaxOutputBytes = 100 << 20
	}
	if cfg.NucleiTimeout <= 0 {
		cfg.NucleiTimeout = time.Hour
	}
	if cfg.ZAPTimeout <= 0 {
		cfg.ZAPTimeout = 2 * time.Hour
	}
	if cfg.OpenVASTimeout <= 0 {
		cfg.OpenVASTimeout = 4 * time.Hour
	}
	if cfg.TrivyTimeout <= 0 {
		cfg.TrivyTimeout = time.Hour
	}
	if cfg.VulsTimeout <= 0 {
		cfg.VulsTimeout = time.Hour
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
}

// Run executes the five scanner attempts in a stable order. Existing terminal
// runs are reused, which makes queue resume continue at the first incomplete
// scanner without mutating immutable raw artifacts.
func (p *Pipeline) Run(ctx context.Context, req Request, existing []Run, emit EmitFunc) []Run {
	recon := p.reconFn
	if recon == nil {
		recon = singleScopeRecon
	}
	byKey := indexTerminal(existing, HostScope(req.Target).Key())
	out := make([]Run, 0, len(p.Runners))

	// Recon phase runs first. Its runs carry their own recon:<target> scope and
	// are reused on resume by (scope, scanner) just like scan runs. On resume we
	// reconstruct scopes from the prior run rather than re-invoking the real recon
	// tools, which would waste work and could drop a host (and its completed scan
	// evidence) that recon no longer reports.
	var scopes []Scope
	var reconRuns []Run
	if hasTerminalReconRuns(existing) {
		scopes, reconRuns = reusePriorRecon(existing)
	}
	if len(scopes) == 0 {
		scopes, reconRuns = recon(ctx, req, p.Config, emit)
	}
	for _, rr := range reconRuns {
		if old, ok := byKey[resumeKey(rr.Scope, rr.Scanner)]; ok {
			out = append(out, old)
			continue
		}
		out = append(out, rr)
	}
	if len(scopes) == 0 {
		scopes = []Scope{HostScope(req.Target)} // degrade: scan the single implicit host
	}

	// Scan phase, fanned out per discovered host scope in discovery order.
	for _, sc := range scopes {
		scopeKey := sc.Key()
		hostReq := req
		hostReq.Target = sc.Target
		// Isolate each host's scanner artifacts. Every scan runner derives its
		// output base from req.ScanDir alone, so two scopes writing under one
		// ScanDir would clobber each other's results and break VerifyChecksum.
		hostReq.ScanDir = filepath.Join(req.ScanDir, "hosts", sanitizeHost(sc.Target))
		for i, runner := range p.Runners {
			if old, ok := byKey[resumeKey(scopeKey, runner.Name())]; ok {
				out = append(out, old)
				continue
			}
			// A deselected scanner still produces an explicit terminal record, so
			// the scan's evidence shows what was not attempted and why.
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

// indexTerminal maps each existing terminal run to its (scope, scanner) resume
// key. A legacy run with empty Scope predates scoping and folds to fallbackScope
// (the implicit host scope) so Increment-1 resume records still match.
func indexTerminal(existing []Run, fallbackScope string) map[string]Run {
	byKey := make(map[string]Run, len(existing))
	for _, run := range existing {
		if !run.Terminal() {
			continue
		}
		s := run.Scope
		if s == "" {
			s = fallbackScope
		}
		byKey[resumeKey(s, run.Scanner)] = run
	}
	return byKey
}

// hasTerminalReconRuns reports whether existing carries at least one terminal
// recon-phase run, i.e. a prior scan already completed the recon phase.
func hasTerminalReconRuns(existing []Run) bool {
	for _, run := range existing {
		if run.Terminal() && strings.HasPrefix(run.Scope, "recon:") {
			return true
		}
	}
	return false
}

// reusePriorRecon reconstructs the recon result from a prior run so a resume does
// not re-invoke the real recon tools. It returns the terminal recon runs and the
// host scopes rebuilt from the distinct host:<target> scan-run scopes seen in
// existing, in first-seen order.
func reusePriorRecon(existing []Run) (scopes []Scope, reconRuns []Run) {
	seen := make(map[string]bool)
	for _, run := range existing {
		if !run.Terminal() {
			continue
		}
		switch {
		case strings.HasPrefix(run.Scope, "recon:"):
			reconRuns = append(reconRuns, run)
		case strings.HasPrefix(run.Scope, "host:"):
			if seen[run.Scope] {
				continue
			}
			seen[run.Scope] = true
			scopes = append(scopes, HostScope(strings.TrimPrefix(run.Scope, "host:")))
		}
	}
	return scopes, reconRuns
}

// skippedRun builds the terminal record for a scanner deselected from this scan,
// scoped to scopeKey and emitting the matching skip event.
func skippedRun(name, scopeKey string, req Request, emit EmitFunc) Run {
	now := time.Now().Format(time.RFC3339Nano)
	r := Run{Scanner: name, Target: req.Target, Status: "skipped", Reason: "not selected for this scan", StartedAt: now, FinishedAt: now, Scope: scopeKey}
	if emit != nil {
		emit(Event{Type: "scanner_skipped", Scanner: name, Run: r, Output: r.Reason})
	}
	return r
}

// cancelledRun builds the terminal record for a scanner not attempted because the
// context was cancelled, scoped to scopeKey and emitting the failure event.
func cancelledRun(name, scopeKey string, req Request, reason error, emit EmitFunc) Run {
	now := time.Now().Format(time.RFC3339Nano)
	r := Run{Scanner: name, Target: req.Target, Status: "cancelled", Reason: reason.Error(), StartedAt: now, FinishedAt: now, Scope: scopeKey}
	if emit != nil {
		emit(Event{Type: "scanner_failed", Scanner: name, Run: r, Output: r.Reason})
	}
	return r
}

func resumeKey(scope, scanner string) string { return scope + "\x00" + scanner }

func runAttempt(ctx context.Context, runner Runner, req Request, cfg Config, emit EmitFunc) (run Run) {
	defer func() {
		if recovered := recover(); recovered != nil {
			run = failedServiceRun(runner.Name(), req, fmt.Sprintf("scanner panic: %v", recovered), emit)
		}
		if !run.Terminal() {
			run.Scanner, run.Target, run.Status = runner.Name(), req.Target, "failed"
			run.Reason, run.FinishedAt = "scanner returned without a terminal status", time.Now().Format(time.RFC3339Nano)
			run = finalizeRun(run)
			if emit != nil {
				emit(Event{Type: "scanner_failed", Scanner: runner.Name(), Run: run, Output: run.Reason})
			}
		}
	}()
	return runner.Run(ctx, req, cfg, emit)
}

type commandSpec struct {
	path     string
	args     []string
	artifact string
	timeout  time.Duration
	notApp   string
	// outputSubdir nests this run's stdout/stderr logs under
	// scanner-output/<name>/<outputSubdir> so several invocations that share a
	// scanner name (e.g. per-host nmap) do not append to one another's sealed
	// logs. Empty keeps the default scanner-output/<name> layout.
	outputSubdir string
	prepare      func() error
	findOutput   func() string
}

type commandBuilder func(Request, Config) commandSpec

type commandRunner struct {
	name  string
	desc  Descriptor
	build commandBuilder
}

func (r commandRunner) Name() string           { return r.name }
func (r commandRunner) Descriptor() Descriptor { return r.desc }
func (r commandRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	spec := r.build(req, cfg)
	return executeSpec(ctx, r.name, req, cfg, spec, emit)
}

func executeSpec(ctx context.Context, name string, req Request, cfg Config, spec commandSpec, emit EmitFunc) Run {
	now := time.Now()
	run := Run{Scanner: name, Target: req.Target, Status: "running", StartedAt: now.Format(time.RFC3339Nano), ExitCode: -1}
	base := filepath.Join(req.ScanDir, "scanner-output", name)
	if spec.outputSubdir != "" {
		base = filepath.Join(base, spec.outputSubdir)
	}
	_ = os.MkdirAll(base, 0o700)
	run.StdoutPath = filepath.Join(base, "stdout.log")
	run.StderrPath = filepath.Join(base, "stderr.log")
	run.ArtifactPath = spec.artifact
	if spec.notApp != "" {
		run.Status, run.Reason, run.FinishedAt = "not_applicable", spec.notApp, time.Now().Format(time.RFC3339Nano)
		_ = os.WriteFile(run.StdoutPath, []byte(spec.notApp+"\n"), 0o600)
		if emit != nil {
			emit(Event{Type: "scanner_not_applicable", Scanner: name, Run: run, Output: spec.notApp})
		}
		return finalizeRun(run)
	}
	if spec.prepare != nil {
		if err := spec.prepare(); err != nil {
			run.Status, run.Reason, run.FinishedAt = "failed", err.Error(), time.Now().Format(time.RFC3339Nano)
			_ = os.WriteFile(run.StderrPath, []byte(err.Error()+"\n"), 0o600)
			if emit != nil {
				emit(Event{Type: "scanner_failed", Scanner: name, Run: run, Output: err.Error()})
			}
			return finalizeRun(run)
		}
	}
	if _, err := exec.LookPath(spec.path); err != nil {
		run.Status, run.Reason, run.FinishedAt = "failed", fmt.Sprintf("scanner binary unavailable: %s", spec.path), time.Now().Format(time.RFC3339Nano)
		_ = os.WriteFile(run.StderrPath, []byte(run.Reason+"\n"), 0o600)
		if emit != nil {
			emit(Event{Type: "scanner_failed", Scanner: name, Run: run, Output: run.Reason})
		}
		return finalizeRun(run)
	}
	if emit != nil {
		emit(Event{Type: "scanner_started", Scanner: name, Run: run})
	}
	cmdCtx, cancel := context.WithTimeout(ctx, spec.timeout)
	defer cancel()
	stdout, err := os.OpenFile(run.StdoutPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		run.Status, run.Reason = "failed", err.Error()
		return finalizeRun(run)
	}
	defer stdout.Close()
	stderr, err := os.OpenFile(run.StderrPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		run.Status, run.Reason = "failed", err.Error()
		return finalizeRun(run)
	}
	defer stderr.Close()
	secrets := secretValues(req, cfg)
	var seq atomic.Int64
	// os/exec drains stdout and stderr concurrently. Serialize callbacks so
	// persistence and WebSocket consumers observe a race-free total sequence.
	var emitMu sync.Mutex
	safeEmit := emit
	if emit != nil {
		safeEmit = func(event Event) {
			emitMu.Lock()
			defer emitMu.Unlock()
			emit(event)
		}
	}
	outW := newOutputWriter(stdout, "stdout", name, cfg.MaxOutputBytes, secrets, &seq, safeEmit)
	errW := newOutputWriter(stderr, "stderr", name, cfg.MaxOutputBytes, secrets, &seq, safeEmit)
	cmd := exec.CommandContext(cmdCtx, spec.path, spec.args...)
	cmd.Dir, cmd.Stdout, cmd.Stderr = req.ScanDir, outW, errW
	err = cmd.Run()
	run.Truncated = outW.Truncated() || errW.Truncated()
	run.ExitCode = 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			run.ExitCode = ee.ExitCode()
		}
		switch {
		case ctx.Err() != nil:
			run.Status, run.Reason = "cancelled", ctx.Err().Error()
		case errors.Is(cmdCtx.Err(), context.DeadlineExceeded):
			run.Status, run.Reason = "failed", "scanner timeout exceeded"
		default:
			run.Status, run.Reason = "failed", err.Error()
		}
	} else {
		run.Status = "completed"
	}
	if spec.findOutput != nil {
		if found := spec.findOutput(); found != "" {
			run.ArtifactPath = found
		}
	}
	if spec.artifact != "" && truncateArtifact(run.ArtifactPath, cfg.MaxOutputBytes) {
		run.Truncated = true
	}
	_ = redactArtifact(run.ArtifactPath, secrets)
	if run.Truncated && run.Reason == "" {
		run.Reason = fmt.Sprintf("output truncated at configured %d-byte limit", cfg.MaxOutputBytes)
	}
	run.FinishedAt = time.Now().Format(time.RFC3339Nano)
	run = finalizeRun(run)
	if emit != nil {
		t := "scanner_completed"
		if run.Status == "failed" {
			t = "scanner_failed"
		}
		if run.Status == "cancelled" {
			t = "scanner_failed"
		}
		emit(Event{Type: t, Scanner: name, Run: run, Output: run.Reason})
	}
	return run
}

func finalizeRun(run Run) Run {
	if run.FinishedAt == "" {
		run.FinishedAt = time.Now().Format(time.RFC3339Nano)
	}
	run.Checksum = CalculateChecksum(run)
	return run
}

// CalculateChecksum seals the append-only raw streams and native artifact for
// a scanner run into one stable digest.
func CalculateChecksum(run Run) string {
	h := sha256.New()
	for _, path := range []string{run.StdoutPath, run.StderrPath, run.ArtifactPath} {
		if path == "" {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		_, _ = io.Copy(h, f)
		_ = f.Close()
	}
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyChecksum prevents report regeneration from consuming scanner files
// that differ from the immutable files recorded when execution completed.
func VerifyChecksum(run Run) error {
	if strings.TrimSpace(run.Checksum) == "" {
		return fmt.Errorf("%s scanner checksum is missing", run.Scanner)
	}
	if current := CalculateChecksum(run); current != run.Checksum {
		return fmt.Errorf("%s scanner artifacts changed: checksum mismatch", run.Scanner)
	}
	return nil
}

func truncateArtifact(path string, limit int64) bool {
	if path == "" || limit <= 0 {
		return false
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= limit {
		return false
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return false
	}
	defer f.Close()
	return f.Truncate(limit) == nil
}

func redactArtifact(path string, secrets []string) error {
	if path == "" || len(secrets) == 0 {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	clean := []byte(redact(string(data), secrets))
	if bytes.Equal(data, clean) {
		return nil
	}
	return os.WriteFile(path, clean, 0o600)
}

type outputWriter struct {
	mu              sync.Mutex
	dst             io.Writer
	stream, scanner string
	max, written    int64
	secrets         []string
	seq             *atomic.Int64
	emit            EmitFunc
	truncated       bool
}

func newOutputWriter(dst io.Writer, stream, scanner string, max int64, secrets []string, seq *atomic.Int64, emit EmitFunc) *outputWriter {
	return &outputWriter{dst: dst, stream: stream, scanner: scanner, max: max, secrets: secrets, seq: seq, emit: emit}
}
func (w *outputWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	rawLen := len(p)
	clean := redact(string(p), w.secrets)
	b := []byte(clean)
	if w.max > 0 && w.written+int64(len(b)) > w.max {
		remain := w.max - w.written
		if remain > 0 {
			b = b[:remain]
		} else {
			b = nil
		}
		w.truncated = true
	}
	if len(b) > 0 {
		_, _ = w.dst.Write(b)
		w.written += int64(len(b))
	}
	if w.emit != nil && len(b) > 0 {
		w.emit(Event{Type: "scanner_output", Scanner: w.scanner, Stream: w.stream, Sequence: w.seq.Add(1), Output: string(b)})
	}
	return rawLen, nil
}
func (w *outputWriter) Truncated() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.truncated }

func redact(s string, secrets []string) string {
	for _, secret := range secrets {
		if len(secret) >= 4 {
			s = strings.ReplaceAll(s, secret, "[REDACTED]")
		}
	}
	return s
}
func secretValues(req Request, cfg Config) []string {
	vals := []string{cfg.ZAPAPIKey, cfg.GVMPass}
	headers := append([]string(nil), cfg.ScanHeaders...)
	headers = append(headers, strings.FieldsFunc(req.TargetAuth, func(r rune) bool { return r == '\n' || r == ';' })...)
	for _, part := range headers {
		if i := strings.Index(part, ":"); i >= 0 {
			vals = append(vals, strings.TrimSpace(part[i+1:]))
		}
	}
	return vals
}

func buildNuclei(req Request, cfg Config) commandSpec {
	if strings.HasPrefix(strings.TrimSpace(req.Target), "artifact://") {
		return commandSpec{notApp: "Nuclei requires a submitted host or URL", timeout: cfg.NucleiTimeout}
	}
	artifact := filepath.Join(req.ScanDir, "scanner-output", "nuclei", "results.jsonl")
	args := []string{"-u", req.Target, "-jle", artifact, "-nc", "-duc", "-dut", "-rl", strconv.Itoa(cfg.RateRPS), "-ot"}
	for _, h := range cfg.ScanHeaders {
		args = append(args, "-H", h)
	}
	for _, h := range strings.Split(req.TargetAuth, "\n") {
		if strings.TrimSpace(h) != "" {
			args = append(args, "-H", strings.TrimSpace(h))
		}
	}
	return commandSpec{path: cfg.NucleiPath, args: args, artifact: artifact, timeout: cfg.NucleiTimeout}
}

func buildTrivy(req Request, cfg Config) commandSpec {
	kind := strings.ToLower(strings.TrimSpace(req.Artifact.Kind))
	ref := strings.TrimSpace(req.Artifact.Ref)
	if kind == "" || ref == "" {
		return commandSpec{notApp: "Trivy requires artifact.kind and artifact.ref", timeout: cfg.TrivyTimeout}
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

func buildVuls(req Request, cfg Config) commandSpec {
	host := strings.TrimSpace(req.VulsSSHHost)
	if host == "" {
		return commandSpec{notApp: "Vuls requires vuls_ssh_host referencing an operator-managed SSH alias", timeout: cfg.VulsTimeout}
	}
	base := filepath.Join(req.ScanDir, "scanner-output", "vuls")
	configPath := filepath.Join(base, "config.toml")
	results := filepath.Join(base, "results")
	prepare := func() error {
		if err := os.MkdirAll(results, 0o700); err != nil {
			return err
		}
		content := vulsConfig(host, cfg.VulsSSHConfigPath)
		return os.WriteFile(configPath, []byte(content), 0o600)
	}
	// A small wrapper mode implemented by vuls itself is not available, so run
	// scan and report through /bin/sh would violate the no-shell invariant.
	// The pipeline therefore invokes scan here; report JSON is generated by the
	// report stage in the parser if the installed Vuls supports scan JSON.
	args := []string{"scan", "-config=" + configPath, "-results-dir=" + results}
	find := func() string {
		matches, _ := filepath.Glob(filepath.Join(results, "**", "*.json"))
		if len(matches) > 0 {
			return matches[len(matches)-1]
		}
		return results
	}
	return commandSpec{path: cfg.VulsPath, args: args, artifact: results, timeout: cfg.VulsTimeout, prepare: prepare, findOutput: find}
}
func safeTOMLKey(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s)
}

func normalizedWebTarget(target string) (string, bool) {
	t := strings.TrimSpace(target)
	if t == "" {
		return "", false
	}
	u, err := url.Parse(t)
	if err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
		return u.String(), true
	}
	if strings.Contains(t, "://") {
		return "", false
	}
	return "https://" + strings.TrimRight(t, "/"), true
}
