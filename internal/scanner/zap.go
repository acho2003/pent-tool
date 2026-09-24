package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// zapDomXSSPluginID is ZAP's DOM XSS active scan rule (from the "domxss"
// add-on). It is disabled per scan because it launches headless Firefox, which
// OOM-kills the daemon on a memory-constrained host.
const zapDomXSSPluginID = "40026"

type zapRunner struct{}

func (zapRunner) Name() string { return "zap" }

func (zapRunner) Descriptor() Descriptor {
	return Descriptor{Name: "zap", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightHeavy}
}

func (zapRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	target, ok := normalizedWebTarget(req.Target)
	if !ok {
		return notApplicableRun("zap", req, cfg, "ZAP requires an HTTP or HTTPS target", emit)
	}
	if strings.TrimSpace(cfg.ZAPURL) == "" {
		return failedServiceRun("zap", req, "ZAP service URL is not configured", emit)
	}
	base := filepath.Join(req.ScanDir, "scanner-output", "zap")
	_ = os.MkdirAll(base, 0o700)
	run := Run{Scanner: "zap", Target: req.Target, Status: "running", StartedAt: time.Now().Format(time.RFC3339Nano), ExitCode: -1, StdoutPath: filepath.Join(base, "stdout.log"), StderrPath: filepath.Join(base, "stderr.log"), ArtifactPath: filepath.Join(base, "results.json")}
	logFile, _ := os.OpenFile(run.StdoutPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if logFile != nil {
		defer logFile.Close()
	}
	seq := int64(0)
	logLine := func(s string) {
		clean := redact(s, secretValues(req, cfg))
		data := []byte(clean + "\n")
		if logFile != nil {
			data = appendCappedFile(logFile, data, cfg.MaxOutputBytes, &run.Truncated)
		}
		if len(data) == 0 {
			return
		}
		seq++
		if emit != nil {
			emit(Event{Type: "scanner_output", Scanner: "zap", Stream: "stdout", Sequence: seq, Output: string(data)})
		}
	}
	if emit != nil {
		emit(Event{Type: "scanner_started", Scanner: "zap", Run: run})
	}
	cctx, cancel := context.WithTimeout(ctx, cfg.ZAPTimeout)
	defer cancel()
	client := &http.Client{}
	// Every exchange with ZAP is a plain HTTP API call: the daemon is reached
	// over cfg.ZAPURL and nothing is handed to it through the filesystem, so a
	// ZAP running in another container (or on another host) needs no shared
	// volume, matching uid, or readable scan directory.
	fetch := func(path string, q url.Values, timeout time.Duration) ([]byte, error) {
		rctx, rcancel := context.WithTimeout(cctx, timeout)
		defer rcancel()
		q.Set("apikey", cfg.ZAPAPIKey)
		endpoint := strings.TrimRight(cfg.ZAPURL, "/") + path + "?" + q.Encode()
		hreq, err := http.NewRequestWithContext(rctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(hreq)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 512<<20))
		if err != nil {
			return nil, err
		}
		if resp.StatusCode/100 != 2 {
			return nil, fmt.Errorf("ZAP API %s: %s", resp.Status, strings.TrimSpace(string(body)))
		}
		return body, nil
	}
	call := func(path string, q url.Values) (map[string]any, error) {
		body, err := fetch(path, q, 60*time.Second)
		if err != nil {
			return nil, err
		}
		var out map[string]any
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, err
		}
		return out, nil
	}
	secrets := secretValues(req, cfg)
	if _, err := call("/JSON/core/view/version/", url.Values{}); err != nil {
		return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
	}
	// Apply configured scan and per-target authentication headers through
	// deterministic ZAP replacer rules before crawling. No model interprets
	// authentication material.
	headers := append([]string(nil), cfg.ScanHeaders...)
	headers = append(headers, strings.Split(req.TargetAuth, "\n")...)
	var rules []string
	// ZAP replacer rules live in the daemon, not in the scan: leaving them
	// behind would replay this target's credentials onto the next one.
	defer func() {
		// Detached from cctx on purpose: the rules must come off even when the
		// scan was cancelled or timed out.
		for _, description := range rules {
			zapRemoveRule(cfg, description)
		}
	}()
	for i, raw := range headers {
		name, value, ok := strings.Cut(strings.TrimSpace(raw), ":")
		if !ok || strings.TrimSpace(name) == "" || strings.TrimSpace(value) == "" {
			continue
		}
		description := fmt.Sprintf("xalgorix-%s-%d", filepath.Base(req.ScanDir), i)
		_, err := call("/JSON/replacer/action/addRule/", url.Values{
			"description": {description},
			"enabled":     {"true"}, "matchType": {"REQ_HEADER"}, "matchRegex": {"false"},
			"matchString": {strings.TrimSpace(name)}, "replacement": {strings.TrimSpace(value)},
		})
		if err != nil {
			return finishServiceFailure(run, fmt.Errorf("configure ZAP header %s: %w", strings.TrimSpace(name), err), secrets, cfg.MaxOutputBytes, emit)
		}
		rules = append(rules, description)
	}

	// Fixed pipeline: spider the target, drain the passive scanner, then active
	// scan what was discovered. The stages and their parameters are constant —
	// nothing about them is model-generated.
	spider, err := call("/JSON/spider/action/scan/", url.Values{"url": {target}, "recurse": {"true"}})
	if err != nil {
		return finishServiceFailure(run, fmt.Errorf("start ZAP spider: %w", err), secrets, cfg.MaxOutputBytes, emit)
	}
	spiderID := valueString(spider, "scan")
	if spiderID == "" || spiderID == "<nil>" {
		return finishServiceFailure(run, fmt.Errorf("ZAP did not return a spider scan id"), secrets, cfg.MaxOutputBytes, emit)
	}
	logLine("ZAP spider started: " + spiderID)
	if err := zapWaitScan(cctx, call, "/JSON/spider/view/status/", spiderID, "spider", logLine); err != nil {
		zapStopScan(cfg, "/JSON/spider/action/stop/", spiderID)
		return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
	}
	if err := zapWaitPassive(cctx, call, logLine); err != nil {
		return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
	}
	// Disable the DOM XSS active scan rule (plugin 40026). It drives headless
	// Firefox through Selenium, whose memory lands on top of the JVM heap and
	// exceeds ZAP's container limit mid-scan; the browser child is OOM-killed and
	// the daemon comes down (surfacing as "connection refused" on the next poll).
	// Reflected and persistent XSS over HTTP stay covered by the other XSS rules.
	// Best-effort: a ZAP build without the DOM XSS add-on has nothing to disable,
	// so a failure here is logged, not fatal.
	if _, err := call("/JSON/ascan/action/disableScanners/", url.Values{"ids": {zapDomXSSPluginID}}); err != nil {
		logLine("could not disable ZAP DOM XSS scan rule: " + err.Error())
	} else {
		logLine("ZAP DOM XSS scan rule disabled (avoids headless-browser OOM)")
	}
	active, err := call("/JSON/ascan/action/scan/", url.Values{"url": {target}, "recurse": {"true"}, "inScopeOnly": {"false"}})
	if err != nil {
		return finishServiceFailure(run, fmt.Errorf("start ZAP active scan: %w", err), secrets, cfg.MaxOutputBytes, emit)
	}
	activeID := valueString(active, "scan")
	if activeID == "" || activeID == "<nil>" {
		return finishServiceFailure(run, fmt.Errorf("ZAP did not return an active scan id"), secrets, cfg.MaxOutputBytes, emit)
	}
	logLine("ZAP active scan started: " + activeID)
	if err := zapWaitScan(cctx, call, "/JSON/ascan/view/status/", activeID, "active scan", logLine); err != nil {
		zapStopScan(cfg, "/JSON/ascan/action/stop/", activeID)
		return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
	}
	if err := zapWaitPassive(cctx, call, logLine); err != nil {
		return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
	}
	// Scope the export to this target. The ZAP daemon is long-lived and shared
	// by every scan, so a session-wide report would fold alerts raised against
	// previously scanned hosts into this scan's artifact.
	report, err := fetch("/JSON/core/view/alerts/", url.Values{"baseurl": {target}}, 10*time.Minute)
	if err != nil {
		return finishServiceFailure(run, fmt.Errorf("export ZAP alerts: %w", err), secrets, cfg.MaxOutputBytes, emit)
	}
	if err := os.WriteFile(run.ArtifactPath, report, 0o600); err != nil {
		return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
	}
	logLine(fmt.Sprintf("ZAP alerts exported for %s (%d bytes)", target, len(report)))
	if err := redactArtifact(run.ArtifactPath, secrets); err != nil {
		return finishServiceFailure(run, err, secrets, cfg.MaxOutputBytes, emit)
	}
	if truncateArtifact(run.ArtifactPath, cfg.MaxOutputBytes) {
		run.Truncated = true
		run.Reason = fmt.Sprintf("artifact truncated at configured %d-byte limit", cfg.MaxOutputBytes)
	}
	run.Status, run.ExitCode, run.FinishedAt = "completed", 0, time.Now().Format(time.RFC3339Nano)
	run = finalizeRun(run)
	if emit != nil {
		emit(Event{Type: "scanner_completed", Scanner: "zap", Run: run})
	}
	return run
}

type zapCallFunc func(string, url.Values) (map[string]any, error)

// zapWaitScan polls a spider or active-scan job until ZAP reports 100%.
func zapWaitScan(ctx context.Context, call zapCallFunc, statusPath, scanID, label string, log func(string)) error {
	last := ""
	for {
		resp, err := call(statusPath, url.Values{"scanId": {scanID}})
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("poll ZAP %s: %w", label, err)
		}
		status := valueString(resp, "status")
		if status != last {
			log("ZAP " + label + " progress: " + status + "%")
			last = status
		}
		if status == "100" {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// zapWaitPassive drains the passive scan queue so alerts raised against
// already-crawled messages are in the report. A ZAP without the passive-scan
// add-on answers with an error; that is not a scan failure.
func zapWaitPassive(ctx context.Context, call zapCallFunc, log func(string)) error {
	for {
		resp, err := call("/JSON/pscan/view/recordsToScan/", url.Values{})
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return nil
		}
		remaining := valueString(resp, "recordsToScan")
		if remaining == "0" || remaining == "" || remaining == "<nil>" {
			return nil
		}
		log("ZAP passive scan queue: " + remaining + " record(s)")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func zapRemoveRule(cfg Config, description string) {
	zapPost(cfg, "/JSON/replacer/action/removeRule/", url.Values{"description": {description}})
}

func zapStopScan(cfg Config, path, scanID string) {
	zapPost(cfg, path, url.Values{"scanId": {scanID}})
}

// zapPost issues a best-effort ZAP API call on its own short-lived context, for
// teardown that has to outlive a cancelled scan.
func zapPost(cfg Config, path string, q url.Values) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	q.Set("apikey", cfg.ZAPAPIKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(cfg.ZAPURL, "/")+path+"?"+q.Encode(), nil)
	if err == nil {
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}
}

func valueString(m map[string]any, key string) string {
	v := m[key]
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.Itoa(int(x))
	default:
		return fmt.Sprint(x)
	}
}
func notApplicableRun(name string, req Request, cfg Config, reason string, emit EmitFunc) Run {
	return executeSpec(context.Background(), name, req, cfg, commandSpec{notApp: reason}, emit)
}
func failedServiceRun(name string, req Request, reason string, emit EmitFunc) Run {
	base := filepath.Join(req.ScanDir, "scanner-output", name)
	_ = os.MkdirAll(base, 0o700)
	now := time.Now().Format(time.RFC3339Nano)
	r := Run{Scanner: name, Target: req.Target, Status: "failed", Reason: reason, StartedAt: now, FinishedAt: now, ExitCode: -1, StdoutPath: filepath.Join(base, "stdout.log"), StderrPath: filepath.Join(base, "stderr.log")}
	_ = os.WriteFile(r.StdoutPath, nil, 0o600)
	_ = os.WriteFile(r.StderrPath, []byte(reason+"\n"), 0o600)
	r = finalizeRun(r)
	if emit != nil {
		emit(Event{Type: "scanner_failed", Scanner: name, Run: r, Output: reason})
	}
	return r
}
func finishServiceFailure(run Run, err error, secrets []string, limit int64, emit EmitFunc) Run {
	run.Status = "failed"
	if errors.Is(err, context.Canceled) {
		run.Status = "cancelled"
	}
	run.Reason = redact(err.Error(), secrets)
	run.FinishedAt = time.Now().Format(time.RFC3339Nano)
	data := []byte(run.Reason + "\n")
	if limit > 0 && int64(len(data)) > limit {
		data = data[:limit]
		run.Truncated = true
	}
	_ = appendFile(run.StderrPath, data)
	run = finalizeRun(run)
	if emit != nil {
		emit(Event{Type: "scanner_failed", Scanner: run.Scanner, Run: run, Output: run.Reason})
	}
	return run
}
