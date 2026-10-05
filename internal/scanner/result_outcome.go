package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func scannerUsesWebAuth(name string) bool {
	switch name {
	case "zap", "nuclei", "wapiti", "dalfox", "apiwrites", "katana":
		return true
	}
	return false
}

// validateWebResult distinguishes child-process success from usable findings.
// Empty JSONL is valid for Nuclei; empty JSON objects are not valid reports.
func validateWebResult(run *Run) {
	switch run.Scanner {
	case "zap", "wapiti", "dalfox", "nuclei", "nikto", "testssl", "sslyze":
	default:
		return
	}
	if run.Status != "completed" {
		return
	}
	run.ExecutionOutcome = "SUCCESS"
	if run.ArtifactPath == "" {
		run.Outcome = "PARTIAL"
		run.Completeness = "unknown"
		return
	}
	data, err := os.ReadFile(run.ArtifactPath)
	if err == nil && (run.Scanner == "zap" || run.Scanner == "wapiti") {
		var root map[string]json.RawMessage
		err = json.Unmarshal(data, &root)
		if err == nil {
			key := "alerts"
			if run.Scanner == "wapiti" {
				key = "vulnerabilities"
			}
			if _, ok := root[key]; !ok {
				if _, grouped := root["site"]; !grouped || run.Scanner != "zap" {
					err = fmt.Errorf("required %s field missing", key)
				}
			}
		}
	}
	if err == nil && run.Scanner == "nuclei" {
		for _, line := range bytes.Split(data, []byte("\n")) {
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			var record map[string]any
			if json.Unmarshal(line, &record) != nil || strings.TrimSpace(str(record["template-id"])) == "" {
				err = fmt.Errorf("invalid Nuclei finding record")
				break
			}
		}
	}
	if err == nil && (run.Scanner == "zap" || run.Scanner == "wapiti") {
		var root map[string]json.RawMessage
		_ = json.Unmarshal(data, &root)
		key := "alerts"
		if run.Scanner == "wapiti" {
			key = "vulnerabilities"
		} else if _, exists := root[key]; !exists {
			key = "site"
		}
		value := bytes.TrimSpace(root[key])
		expected := byte('[')
		if run.Scanner == "wapiti" {
			expected = '{'
		}
		if len(value) == 0 || value[0] != expected {
			err = fmt.Errorf("invalid %s records", key)
		}
	}
	var findings []Finding
	if err == nil {
		findings, err = ParseRun(*run)
	}
	if err != nil {
		run.ParserOutcome, run.Outcome, run.Completeness = "FAILED", "PARSER_FAILED", "unknown"
		run.Status, run.Reason = "failed", "scanner results unavailable or invalid: "+err.Error()
		return
	}
	wasPartial := run.Completeness == "partial"
	run.ParserOutcome, run.Completeness = "SUCCESS", "complete"
	run.Outcome = "SUCCESS_NO_FINDINGS"
	if len(findings) > 0 {
		run.Outcome = "SUCCESS_WITH_FINDINGS"
	}
	if wasPartial || run.Truncated || len(run.Limitations) > 0 {
		run.Outcome, run.Completeness = "PARTIAL", "partial"
	}
}

// monitorCommandAuth cannot change argv of a running scanner. Stop rather than
// continue with an expired or rotated identity. A new attempt uses fresh headers.
func monitorCommandAuth(ctx context.Context, req Request, cancel context.CancelFunc, done <-chan struct{}, result chan<- error) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			result <- nil
			return
		case <-done:
			result <- nil
			return
		case <-ticker.C:
			headers, err := req.AuthRefresh(ctx, strings.Split(req.TargetAuth, "\n"))
			if err != nil || strings.Join(headers, "\n") != req.TargetAuth {
				cancel()
				result <- fmt.Errorf("authenticated session expired or rotated; retry with verified credentials")
				return
			}
		}
	}
}

func markAuthExpired(run *Run) {
	run.Status, run.Authenticated, run.AuthState, run.GapKind = "failed", false, assessment.StateExpired, GapAuthExpired
	run.Outcome, run.Completeness = "AUTH_FAILED", "partial"
}

// A target binding authorizes credentials for that target origin, not aliases.
func constrainCredentialTargets(req *Request, surface *AttackSurface, scanner string) {
	if req.TargetAuth == "" || req.AppScope == nil {
		return
	}
	bound, err := assessment.ParseApprovedOrigin("", req.Target)
	if err != nil {
		req.EndpointTargets = nil
		return
	}
	allowed := req.EndpointTargets[:0]
	for _, raw := range req.EndpointTargets {
		origin, e := assessment.ParseApprovedOrigin("", raw)
		if e == nil && origin.Scheme == bound.Scheme && origin.Host == bound.Host && origin.Port == bound.Port {
			allowed = append(allowed, raw)
			continue
		}
		if surface != nil {
			for i := range surface.Endpoints {
				ep := &surface.Endpoints[i]
				if ep.URL == raw {
					setEndpointCoverage(ep, EndpointScannerCoverage{Scanner: scanner, Status: "skipped", Reason: "credential binding does not authorize this origin"})
				}
			}
		}
	}
	req.EndpointTargets = allowed
}
