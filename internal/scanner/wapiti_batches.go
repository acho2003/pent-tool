package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/xalgord/xalgorix/v4/internal/storage"
	"os"
	"path/filepath"
	"time"
)

func runWapitiBatches(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	duration := cfg.WapitiTimeout
	if duration <= 0 || duration > wapitiMaxDuration {
		duration = wapitiMaxDuration
	}
	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	parent := Run{Scanner: "wapiti", Target: req.Target, Scope: req.Scope, Status: "running", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), AttemptID: req.AttemptID, PlanFingerprint: req.PlanFingerprint}
	if emit != nil {
		emit(Event{Type: "scanner_started", Scanner: "wapiti", Run: parent})
	}
	report := wapitiReport{Vulnerabilities: map[string][]wapitiEntry{}, Classifications: map[string]wapitiClass{}}
	targets := append([]string(nil), req.EndpointTargets...)
	failures, successes := 0, 0
	for start := 0; start < len(targets); start += 50 {
		end := start + 50
		if end > len(targets) {
			end = len(targets)
		}
		batch := req
		batch.EndpointTargets = targets[start:end]
		batch.ScanDir = filepath.Join(req.ScanDir, "batches", fmt.Sprintf("%04d", start/50))
		if ctx.Err() != nil {
			failures++
			for _, raw := range batch.EndpointTargets {
				parent.Submissions = append(parent.Submissions, wapitiSubmission(req, raw, "skipped", "Wapiti batch time budget exhausted"))
			}
			continue
		}
		childCfg := cfg
		remaining := time.Until(time.Now().Add(duration))
		if deadline, ok := ctx.Deadline(); ok {
			remaining = time.Until(deadline)
		}
		childCfg.WapitiTimeout = remaining
		childEmit := func(e Event) {
			if emit != nil && e.Type == "scanner_output" {
				emit(e)
			}
		}
		child := executePolicySpec(ctx, "wapiti", batch, childCfg, buildWapiti(batch, childCfg), childEmit)
		parent.BatchRuns = append(parent.BatchRuns, child)
		if child.Status == "completed" {
			successes++
		}
		status, reason := "submitted", "input batch supplied to scanner; endpoint execution not proven"
		if child.Status != "completed" {
			failures++
			status, reason = "failed", child.Reason
		}
		for _, raw := range batch.EndpointTargets {
			parent.Submissions = append(parent.Submissions, wapitiSubmission(req, raw, status, reason))
		}
		data, err := os.ReadFile(child.ArtifactPath)
		var parsed wapitiReport
		if err == nil && json.Unmarshal(data, &parsed) == nil {
			for category, entries := range parsed.Vulnerabilities {
				report.Vulnerabilities[category] = append(report.Vulnerabilities[category], entries...)
			}
			for category, class := range parsed.Classifications {
				report.Classifications[category] = class
			}
		}
		if child.AuthState == "expired" {
			break
		}
	}
	parent.ArtifactPath = filepath.Join(req.ScanDir, "scanner-output", "wapiti", "results.json")
	if err := storage.EnsureSecureDir(filepath.Dir(parent.ArtifactPath)); err != nil {
		parent.Status, parent.Reason = "failed", err.Error()
		return finalizeRun(parent)
	}
	data, err := json.Marshal(report)
	if err == nil {
		err = storage.WriteAtomic(parent.ArtifactPath, data)
	}
	parent.Status = "completed"
	if err != nil {
		parent.Status, parent.Reason = "failed", err.Error()
	}
	if failures > 0 {
		parent.Completeness, parent.Outcome, parent.Reason = "partial", "PARTIAL", "one or more Wapiti batches failed or were not attempted"
	}
	if successes == 0 && failures > 0 {
		parent.Status = "failed"
		parent.Outcome = "FAILED"
	}
	if ctx.Err() == context.Canceled {
		parent.Status = "cancelled"
	}
	validateWebResult(&parent)
	parent = finalizeRun(parent)
	if emit != nil {
		emit(Event{Type: "scanner_completed", Scanner: "wapiti", Run: parent})
	}
	return parent
}
func wapitiSubmission(req Request, raw, status, reason string) EndpointSubmission {
	result := EndpointSubmission{URL: SafeTelemetryURL(raw), Method: "GET", Status: status, Reason: reason, At: time.Now().UTC().Format(time.RFC3339Nano)}
	for _, input := range req.InputRequests {
		if input.URL == raw {
			result.EndpointID = input.EndpointID
			result.Method = input.Method
		}
	}
	return result
}
