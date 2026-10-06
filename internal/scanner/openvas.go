package scanner

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type openVASRunner struct{}

// Kept separate from the overall scan timeout so a responding but stalled
// Greenbone task cannot hold the rest of an assessment indefinitely.
var openVASIdleTimeout = 5 * time.Minute
var openVASPollInterval = 10 * time.Second

var gvmSSHCredentialPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func (openVASRunner) Name() string { return "openvas" }

func (openVASRunner) Descriptor() Descriptor {
	return Descriptor{Name: "openvas", Summary: "Greenbone network scan of each server host", Phase: PhaseServer, Tracks: []Track{TrackServer}, Weight: WeightHeavy, Applies: appliesToHost}
}

func (openVASRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	host := hostOnly(req.Target)
	if host == "" {
		return notApplicableRun("openvas", req, cfg, "OpenVAS requires a host, IP address, or URL", emit)
	}
	if (cfg.GVMHost == "" && cfg.GVMSocket == "") || cfg.GVMUser == "" || cfg.GVMPass == "" {
		return failedServiceRun("openvas", req, "Greenbone GMP endpoint or credentials are not configured", emit)
	}
	if req.GVMSSHCredentialID != "" && (!req.TypedAssessment || !gvmSSHCredentialPattern.MatchString(req.GVMSSHCredentialID) || req.GVMSSHPort < 1 || req.GVMSSHPort > 65535) {
		return failedServiceRun("openvas", req, "invalid target-bound Greenbone SSH credential reference", emit)
	}

	base := filepath.Join(req.ScanDir, "scanner-output", "openvas")
	_ = os.MkdirAll(base, 0o700)
	run := Run{
		Scanner: "openvas", Target: req.Target, Scope: req.Scope, Status: "running", ExitCode: -1,
		StartedAt:  time.Now().Format(time.RFC3339Nano),
		StdoutPath: filepath.Join(base, "stdout.log"), StderrPath: filepath.Join(base, "stderr.log"),
		ArtifactPath: filepath.Join(base, "results.xml"),
	}
	if emit != nil {
		emit(Event{Type: "scanner_started", Scanner: run.Scanner, Run: run})
	}

	cmdCtx, cancel := context.WithTimeout(ctx, cfg.OpenVASTimeout)
	defer cancel()
	var sequence int64
	logStage := func(stage, stream, path string, data []byte) {
		if len(data) == 0 {
			return
		}
		data = appendCappedPath(path, append([]byte("["+stage+"]\n"), data...), cfg.MaxOutputBytes, &run.Truncated)
		if len(data) == 0 {
			return
		}
		sequence++
		if emit != nil {
			emit(Event{Type: "scanner_output", Scanner: run.Scanner, Stream: stream, Sequence: sequence, Output: string(data)})
		}
	}
	// One authenticated GMP connection carries the whole scan; it is redialed
	// transparently if gvmd drops it during the multi-hour poll loop.
	var conn *gmpConn
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	call := func(stage, command string, timeout time.Duration) ([]byte, error) {
		stageCtx, stageCancel := context.WithTimeout(cmdCtx, timeout)
		defer stageCancel()
		stageErr := func(err error) error {
			if errors.Is(stageCtx.Err(), context.DeadlineExceeded) && cmdCtx.Err() == nil {
				err = fmt.Errorf("%s timed out", stage)
			} else {
				err = fmt.Errorf("%s: %w", stage, err)
			}
			logStage(stage, "stderr", run.StderrPath, []byte(redact(err.Error(), secretValues(req, cfg))+"\n"))
			return err
		}
		for attempt := 0; ; attempt++ {
			if conn == nil {
				c, err := dialGMP(stageCtx, cfg)
				if err != nil {
					return nil, stageErr(err)
				}
				if err := c.authenticate(stageCtx, cfg.GVMUser, cfg.GVMPass); err != nil {
					_ = c.Close()
					return nil, stageErr(fmt.Errorf("GMP authentication failed: %w", err))
				}
				conn = c
			}
			out, err := conn.exec(stageCtx, command)
			if err != nil {
				_ = conn.Close()
				conn = nil
				if attempt == 0 && stageCtx.Err() == nil {
					continue
				}
				return nil, stageErr(err)
			}
			out = []byte(redact(string(out), secretValues(req, cfg)))
			if stage == "export-report" {
				// The report body is the artifact; mirroring megabytes of XML
				// into the log and the live feed helps nobody.
				logStage(stage, "stdout", run.StdoutPath, fmt.Appendf(nil, "report XML received (%d bytes)\n", len(out)))
			} else {
				logStage(stage, "stdout", run.StdoutPath, out)
			}
			if err := gmpStatusError(out); err != nil {
				return out, stageErr(err)
			}
			return out, nil
		}
	}

	// startedTaskID is set once gvmd accepts start_task. Any failure or
	// cancellation after that stops the task in Greenbone; otherwise it keeps
	// scanning the target with nothing tracking it.
	startedTaskID := ""
	fail := func(err error) Run {
		if startedTaskID != "" {
			stopErr := stopGreenboneTask(cfg, startedTaskID)
			note := "Greenbone task stop requested\n"
			if stopErr != nil {
				note = "Greenbone task stop failed: " + redact(stopErr.Error(), secretValues(req, cfg)) + "\n"
				err = fmt.Errorf("%w; %s; remote task may still be running", err, strings.TrimSpace(note))
			}
			_ = appendFile(run.StderrPath, []byte(note))
		}
		run.FinishedAt = time.Now().Format(time.RFC3339Nano)
		run.Status, run.Reason = "failed", err.Error()
		if ctx.Err() != nil || cmdCtx.Err() == context.Canceled {
			run.Status, run.Reason = "cancelled", firstNonEmptyError(ctx.Err(), cmdCtx.Err()).Error()
		}
		_ = appendFile(run.StderrPath, []byte(run.Reason+"\n"))
		run = finalizeRun(run)
		if emit != nil {
			typ := "scanner_failed"
			if run.Status == "cancelled" {
				typ = "scanner_failed"
			}
			emit(Event{Type: typ, Scanner: run.Scanner, Run: run, Output: run.Reason})
		}
		return run
	}

	// The GMP filter language treats bare "and" as a boolean operator, so the
	// multi-word names have to be quoted inside the filter attribute.
	configData, err := call("resolve-config", `<get_configs filter="name=&quot;Full and fast&quot;"/>`, 2*time.Minute)
	if err != nil {
		return fail(err)
	}
	configID := xmlIDByExactName(configData, "config", "Full and fast")
	if configID == "" {
		return fail(fmt.Errorf("Greenbone Full and fast scan config not found; feed may still be syncing"))
	}
	scannerData, err := call("resolve-scanner", `<get_scanners filter="name=&quot;OpenVAS Default&quot;"/>`, 2*time.Minute)
	if err != nil {
		return fail(err)
	}
	scannerID := xmlIDByExactName(scannerData, "scanner", "OpenVAS Default")
	if scannerID == "" {
		return fail(fmt.Errorf("Greenbone default scanner not found"))
	}

	// A recorded explicit policy uses an inline range and must not depend on
	// an unrelated feed-provided default port list being present.
	name := "xalgorix-" + filepath.Base(req.ScanDir)
	portSpec := ""
	if len(req.NetworkPorts) > 0 {
		var ports []string
		seen := map[int]bool{}
		for _, port := range req.NetworkPorts {
			if port <= 0 || port > 65535 {
				return fail(fmt.Errorf("approved port policy contains invalid port %d", port))
			}
			if !seen[port] {
				ports = append(ports, strconv.Itoa(port))
				run.NetworkPorts = append(run.NetworkPorts, port)
				seen[port] = true
			}
		}
		portSpec = `<port_range>T:` + strings.Join(ports, ",") + `</port_range>`
	} else {
		portListData, err := call("resolve-port-list", `<get_port_lists filter="name=&quot;All IANA assigned TCP&quot;"/>`, 2*time.Minute)
		if err != nil {
			return fail(err)
		}
		portListID := xmlIDByExactName(portListData, "port_list", "All IANA assigned TCP")
		if portListID == "" {
			return fail(fmt.Errorf("Greenbone port list not found; feed may still be syncing"))
		}
		portSpec = fmt.Sprintf(`<port_list id="%s"/>`, portListID)
	}
	sshCredential := ""
	if req.GVMSSHCredentialID != "" {
		sshCredential = fmt.Sprintf(`<ssh_credential id="%s"><port>%d</port></ssh_credential>`, req.GVMSSHCredentialID, req.GVMSSHPort)
	}
	targetData, err := call("create-target", fmt.Sprintf(`<create_target><name>%s</name><hosts>%s</hosts>%s%s</create_target>`, xmlEscape(name), xmlEscape(host), sshCredential, portSpec), 2*time.Minute)
	if err != nil {
		return fail(err)
	}
	targetID := responseID(targetData)
	if targetID == "" {
		return fail(fmt.Errorf("Greenbone did not return a target id"))
	}
	taskData, err := call("create-task", fmt.Sprintf(`<create_task><name>%s</name><config id="%s"/><target id="%s"/><scanner id="%s"/></create_task>`, xmlEscape(name), configID, targetID, scannerID), 2*time.Minute)
	if err != nil {
		return fail(err)
	}
	taskID := responseID(taskData)
	if taskID == "" {
		return fail(fmt.Errorf("Greenbone did not return a task id"))
	}
	startData, err := call("start-task", fmt.Sprintf(`<start_task task_id="%s"/>`, taskID), 2*time.Minute)
	if err != nil {
		return fail(err)
	}
	startedTaskID = taskID
	reportID := firstXMLText(startData, "report_id")

	lastProgress := -1
	lastAdvance := time.Now()
	for {
		pollData, pollErr := call("poll-task", fmt.Sprintf(`<get_tasks task_id="%s" details="1"/>`, taskID), 2*time.Minute)
		if pollErr != nil {
			return fail(pollErr)
		}
		status := strings.ToLower(firstXMLText(pollData, "status"))
		// gvmd reports the task's completion as <progress>; -1 means not started.
		if pct, convErr := strconv.Atoi(strings.TrimSpace(firstXMLText(pollData, "progress"))); convErr == nil && pct >= 0 && pct <= 100 {
			if pct > lastProgress {
				lastAdvance = time.Now()
			}
			if pct != lastProgress {
				lastProgress = pct
				run.Progress, run.ProgressStage = pct, "scan"
				if emit != nil {
					emit(Event{Type: "scanner_progress", Scanner: run.Scanner, Run: run})
				}
			}
		}
		if reportID == "" {
			reportID = firstXMLAttr(pollData, "report", "id")
		}
		if status == "done" {
			break
		}
		if status == "stopped" || status == "interrupted" {
			startedTaskID = "" // already stopped in gvmd
			return fail(fmt.Errorf("Greenbone task ended with status %s", status))
		}
		if time.Since(lastAdvance) >= openVASIdleTimeout {
			return fail(fmt.Errorf("Greenbone task made no progress for %s", openVASIdleTimeout))
		}
		select {
		case <-cmdCtx.Done():
			return fail(cmdCtx.Err())
		case <-time.After(openVASPollInterval):
		}
	}
	// The task has finished in gvmd; later failures (export) need no stop.
	startedTaskID = ""
	if reportID == "" {
		return fail(fmt.Errorf("Greenbone report id unavailable"))
	}
	// Without an explicit filter gvmd applies its default results view, which
	// pages at rows=10 — every result after the first page was silently lost.
	// Fetch all results (no pagination) at Greenbone's standard QoD floor.
	reportData, err := call("export-report", fmt.Sprintf(`<get_reports report_id="%s" details="1" ignore_pagination="1" filter="apply_overrides=0 min_qod=70 levels=hmlg first=1 rows=-1"/>`, reportID), 5*time.Minute)
	if err != nil {
		return fail(err)
	}
	if err := os.WriteFile(run.ArtifactPath, reportData, 0o600); err != nil {
		return fail(err)
	}
	if err := redactArtifact(run.ArtifactPath, secretValues(req, cfg)); err != nil {
		invalidateUnsafeArtifact(&run)
		return fail(fmt.Errorf("scanner artifact redaction failed; artifact is unavailable"))
	}
	bounded, boundErr := boundWebArtifact(run.ArtifactPath, "openvas", cfg.MaxOutputBytes)
	if boundErr != nil {
		run.ExecutionOutcome, run.Outcome, run.ParserOutcome, run.Completeness = "SUCCESS", "PARSER_FAILED", "FAILED", "partial"
		return fail(fmt.Errorf("could not retain usable bounded scanner artifact: %w", boundErr))
	}
	if bounded {
		run.Truncated = true
		run.Outcome, run.Completeness = "PARTIAL", "partial"
		run.Reason = fmt.Sprintf("complete result records retained within configured %d-byte limit", cfg.MaxOutputBytes)
	}
	run.ExitCode, run.Status, run.FinishedAt = 0, "completed", time.Now().Format(time.RFC3339Nano)
	run.Progress, run.ProgressStage = 0, ""
	run = finalizeRun(run)
	if emit != nil {
		emit(Event{Type: "scanner_completed", Scanner: run.Scanner, Run: run})
	}
	return run
}

func appendFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

func appendCappedPath(path string, data []byte, limit int64, truncated *bool) []byte {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil
	}
	defer f.Close()
	return appendCappedFile(f, data, limit, truncated)
}

func appendCappedFile(f *os.File, data []byte, limit int64, truncated *bool) []byte {
	if f == nil {
		return nil
	}
	if limit > 0 {
		written := int64(0)
		if info, err := f.Stat(); err == nil {
			written = info.Size()
		}
		remaining := limit - written
		if remaining <= 0 {
			*truncated = true
			return nil
		}
		if int64(len(data)) > remaining {
			data = data[:remaining]
			*truncated = true
		}
	}
	if len(data) > 0 {
		_, _ = f.Write(data)
	}
	return data
}
func capOutput(data []byte, limit int64, truncated *bool) []byte {
	if limit > 0 && int64(len(data)) > limit {
		*truncated = true
		return data[:limit]
	}
	return data
}
func firstNonEmptyError(values ...error) error {
	for _, err := range values {
		if err != nil {
			return err
		}
	}
	return errors.New("cancelled")
}

func hostOnly(target string) string {
	t := strings.TrimSpace(target)
	if t == "" || strings.HasPrefix(t, "code://") || strings.HasPrefix(t, "artifact://") {
		return ""
	}
	if u, ok := normalizedWebTarget(t); ok {
		u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
		if i := strings.IndexAny(u, "/:?"); i >= 0 {
			return u[:i]
		}
		return u
	}
	parts := strings.FieldsFunc(t, func(r rune) bool { return r == '/' || r == ':' })
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}
func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
func responseID(data []byte) string {
	var v struct {
		ID string `xml:"id,attr"`
	}
	_ = xml.Unmarshal(data, &v)
	if v.ID != "" {
		return v.ID
	}
	if id := firstXMLAttr(data, "create_target_response", "id"); id != "" {
		return id
	}
	return firstXMLAttr(data, "create_task_response", "id")
}
func firstXMLAttr(data []byte, element, attr string) string {
	d := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := d.Token()
		if err != nil {
			return ""
		}
		if s, ok := tok.(xml.StartElement); ok && s.Name.Local == element {
			for _, a := range s.Attr {
				if a.Name.Local == attr {
					return a.Value
				}
			}
		}
	}
}
func firstXMLText(data []byte, element string) string {
	d := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := d.Token()
		if err != nil {
			return ""
		}
		if s, ok := tok.(xml.StartElement); ok && s.Name.Local == element {
			var v string
			if d.DecodeElement(&v, &s) == nil {
				return strings.TrimSpace(v)
			}
		}
	}
}

var greenboneTaskID = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// stopGreenboneTask asks gvmd to stop a running task on a fresh, short-lived
// connection: the scan's own context is usually already cancelled when this
// runs, so the scan's GMP connection cannot carry the request.
func stopGreenboneTask(cfg Config, taskID string) error {
	if !greenboneTaskID.MatchString(taskID) {
		return fmt.Errorf("invalid Greenbone task id")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := dialGMP(ctx, cfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.authenticate(ctx, cfg.GVMUser, cfg.GVMPass); err != nil {
		return fmt.Errorf("GMP authentication failed: %w", err)
	}
	out, err := conn.exec(ctx, fmt.Sprintf(`<stop_task task_id="%s"/>`, taskID))
	if err != nil {
		return err
	}
	return gmpStatusError(out)
}
