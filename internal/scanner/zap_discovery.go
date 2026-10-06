package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/storage"
)

// ZAP spider settings are daemon-global: snapshot before mutating and restore
// under the existing exclusive daemon lease, even on cancellation.
func configureSafeZAPSpider(cfg Config, call zapCallFunc) (func() error, error) {
	settings := []struct{ name, parameter, value string }{
		{"ProcessForm", "Boolean", "false"}, {"PostForm", "Boolean", "false"},
		{"MaxDepth", "Integer", strconv.Itoa(katanaDefaultDepth)},
		{"ThreadCount", "Integer", "1"}, {"MaxDuration", "Integer", "5"},
	}
	restoreSteps := []struct{ name, parameter, value string }{}
	restore := func() error {
		var failure error
		for i := len(restoreSteps) - 1; i >= 0; i-- {
			step := restoreSteps[i]
			if err := zapPost(cfg, "/JSON/spider/action/setOption"+step.name+"/", url.Values{step.parameter: {step.value}}); err != nil {
				failure = err
			}
		}
		return failure
	}
	for _, step := range settings {
		state, err := call("/JSON/spider/view/option"+step.name+"/", url.Values{})
		if err != nil {
			return restore, err
		}
		prior := valueString(state, step.name)
		if step.parameter == "Boolean" {
			if prior != "true" && prior != "false" {
				return restore, fmt.Errorf("ZAP spider %s snapshot unavailable", step.name)
			}
		} else if n, err := strconv.Atoi(prior); err != nil || n < 0 {
			return restore, fmt.Errorf("ZAP spider %s snapshot unavailable", step.name)
		}
		restoreSteps = append(restoreSteps, struct{ name, parameter, value string }{step.name, step.parameter, prior})
		if _, err := call("/JSON/spider/action/setOption"+step.name+"/", url.Values{step.parameter: {step.value}}); err != nil {
			return restore, err
		}
	}
	return restore, nil
}

// Only actual gateway responses become observations. The spider's candidate
// URL list cannot prove that a request was sent or that an endpoint was live.
func saveZAPDiscoveryArtifact(req Request, run *Run, cfg Config) error {
	events, err := ReadCoverageEvents(run.CoverageEventsPath)
	if err != nil {
		return err
	}
	bound, err := assessment.ParseApprovedOrigin("", req.Target)
	if err != nil {
		return err
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	seen := map[string]bool{}
	limit := cfg.WebMaxEndpoints
	if limit <= 0 {
		limit = 500
	}
	for _, event := range events {
		if (event.Kind != "observed" && event.Kind != "blocked" && event.Kind != "failed") || event.Phase != "discovery" {
			continue
		}
		key := event.Method + " " + event.URL
		if seen[key] {
			continue
		}
		if len(seen) >= limit {
			run.Completeness, run.Outcome = "partial", "PARTIAL"
			run.Reason = "supplemental discovery endpoint budget reached"
			break
		}
		seen[key] = true
		origin, err := assessment.ParseApprovedOrigin("", event.URL)
		if err != nil {
			continue
		}
		authenticated := event.Kind == "observed" && strings.TrimSpace(req.TargetAuth) != "" && origin.Origin() == bound.Origin()
		kind := "observed"
		if event.Kind != "observed" {
			kind = "candidate"
		}
		record := map[string]any{"request": map[string]any{"endpoint": event.URL, "method": event.Method, "source": "zap-discovery", "authenticated": authenticated, "auth_context_id": req.AuthContextID, "observation_kind": kind, "disposition_reason": event.Reason}, "response": map[string]any{"status_code": event.ResponseCode}, "timestamp": event.At}
		var row bytes.Buffer
		if err = json.NewEncoder(&row).Encode(record); err != nil {
			return err
		}
		if cfg.MaxOutputBytes > 0 && int64(output.Len()+row.Len()) > cfg.MaxOutputBytes {
			run.Truncated, run.Completeness, run.Outcome = true, "partial", "PARTIAL"
			run.Reason = "supplemental discovery evidence budget reached"
			break
		}
		if err = encoder.Encode(record); err != nil {
			return err
		}
	}
	run.ArtifactPath = filepath.Join(req.ScanDir, "zap-discovery.jsonl")
	if err = storage.WriteAtomic(run.ArtifactPath, output.Bytes()); err != nil {
		return err
	}
	run.Status, run.ExitCode, run.FinishedAt = "completed", 0, time.Now().UTC().Format(time.RFC3339Nano)
	run.ExecutionOutcome, run.ParserOutcome = "SUCCESS", "SUCCESS"
	if len(seen) == 0 {
		run.Completeness, run.Outcome = "partial", "PARTIAL"
		run.Reason = "ZAP supplemental discovery recorded no response evidence"
	}
	return nil
}
