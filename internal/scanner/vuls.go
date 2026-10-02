package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type vulsRunner struct{}

func (vulsRunner) Name() string { return "vuls" }

func (vulsRunner) Descriptor() Descriptor {
	return Descriptor{Name: "vuls", Summary: "Host CVE audit — needs an SSH alias", Phase: PhaseServer, Tracks: []Track{TrackServer}, Weight: WeightLight, Applies: appliesToHost}
}

func (vulsRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	host := strings.TrimSpace(req.VulsSSHHost)
	if host == "" {
		return notApplicableRun("vuls", req, cfg, "Vuls requires vuls_ssh_host referencing an operator-managed SSH alias", emit)
	}
	if _, err := exec.LookPath(cfg.VulsPath); err != nil {
		return failedServiceRun("vuls", req, "scanner binary unavailable: "+cfg.VulsPath, emit)
	}
	base := filepath.Join(req.ScanDir, "scanner-output", "vuls")
	results := filepath.Join(base, "results")
	_ = os.MkdirAll(results, 0o700)
	configPath := filepath.Join(base, "config.toml")
	if err := os.WriteFile(configPath, []byte(vulsConfig(host, cfg.VulsSSHConfigPath)), 0o600); err != nil {
		return failedServiceRun("vuls", req, err.Error(), emit)
	}
	run := Run{Scanner: "vuls", Target: req.Target, Scope: req.Scope, Status: "running", ExitCode: -1, StartedAt: time.Now().Format(time.RFC3339Nano), StdoutPath: filepath.Join(base, "stdout.log"), StderrPath: filepath.Join(base, "stderr.log"), ArtifactPath: results}
	if emit != nil {
		emit(Event{Type: "scanner_started", Scanner: "vuls", Run: run})
	}
	cctx, cancel := context.WithTimeout(ctx, cfg.VulsTimeout)
	defer cancel()
	sequence := int64(0)
	stage := func(name string, args ...string) error {
		cmd := exec.CommandContext(cctx, cfg.VulsPath, args...)
		cmd.Dir = req.ScanDir
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		for _, item := range []struct{ stream, path, text string }{{"stdout", run.StdoutPath, stdout.String()}, {"stderr", run.StderrPath, stderr.String()}} {
			clean := redact(item.text, secretValues(req, cfg))
			data := appendCappedPath(item.path, append([]byte("["+name+"]\n"), []byte(clean)...), cfg.MaxOutputBytes, &run.Truncated)
			if len(data) == 0 {
				continue
			}
			sequence++
			if emit != nil {
				emit(Event{Type: "scanner_output", Scanner: "vuls", Stream: item.stream, Sequence: sequence, Output: string(data)})
			}
		}
		return err
	}
	fail := func(err error) Run {
		run.Status, run.Reason, run.FinishedAt = "failed", err.Error(), time.Now().Format(time.RFC3339Nano)
		if ctx.Err() != nil || errors.Is(cctx.Err(), context.Canceled) {
			run.Status, run.Reason = "cancelled", firstNonEmptyError(ctx.Err(), cctx.Err()).Error()
		}
		run = finalizeRun(run)
		if emit != nil {
			emit(Event{Type: "scanner_failed", Scanner: "vuls", Run: run, Output: run.Reason})
		}
		return run
	}
	if err := stage("scan", "scan", "-config="+configPath, "-results-dir="+results); err != nil {
		return fail(fmt.Errorf("vuls scan: %w", err))
	}
	if err := stage("report", "report", "-format-json", "-config="+configPath, "-results-dir="+results); err != nil {
		return fail(fmt.Errorf("vuls report: %w", err))
	}
	var candidates []string
	_ = filepath.WalkDir(results, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(strings.ToLower(path), ".json") {
			candidates = append(candidates, path)
		}
		return nil
	})
	sort.Strings(candidates)
	if len(candidates) == 0 {
		return fail(fmt.Errorf("Vuls completed without a JSON report"))
	}
	run.ArtifactPath, run.Status, run.ExitCode, run.FinishedAt = candidates[len(candidates)-1], "completed", 0, time.Now().Format(time.RFC3339Nano)
	_ = redactArtifact(run.ArtifactPath, secretValues(req, cfg))
	if truncateArtifact(run.ArtifactPath, cfg.MaxOutputBytes) {
		run.Truncated = true
		run.Reason = fmt.Sprintf("artifact truncated at configured %d-byte limit", cfg.MaxOutputBytes)
	}
	run = finalizeRun(run)
	if emit != nil {
		emit(Event{Type: "scanner_completed", Scanner: "vuls", Run: run})
	}
	return run
}

func vulsConfig(host, sshConfigPath string) string {
	config := fmt.Sprintf("[servers]\n[servers.%q]\nhost = %q\nscanMode = [\"fast\"]\n", safeTOMLKey(host), host)
	if strings.TrimSpace(sshConfigPath) != "" {
		config += fmt.Sprintf("sshConfigPath = %q\n", sshConfigPath)
	}
	return config
}
