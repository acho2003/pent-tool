package scanner

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type openVASRunner struct{}

func (openVASRunner) Name() string { return "openvas" }

func (openVASRunner) Descriptor() Descriptor {
	return Descriptor{Name: "openvas", Phase: PhaseServer, Tracks: []Track{TrackServer}, Weight: WeightHeavy}
}

func (openVASRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	host := hostOnly(req.Target)
	if host == "" {
		return notApplicableRun("openvas", req, cfg, "OpenVAS requires a host, IP address, or URL", emit)
	}
	if (cfg.GVMHost == "" && cfg.GVMSocket == "") || cfg.GVMUser == "" || cfg.GVMPass == "" {
		return failedServiceRun("openvas", req, "Greenbone GMP endpoint or credentials are not configured", emit)
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

	fail := func(err error) Run {
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

	// gvmd rejects create_target unless it carries a port list (or an inline
	// port range): "One of PORT_LIST and PORT_RANGE are required". Resolve the
	// built-in "All IANA assigned TCP" list by name, matching how the config and
	// scanner above are resolved, and fall back to the first list the feed ships
	// so a renamed default still yields a usable target.
	portListData, err := call("resolve-port-list", `<get_port_lists filter="name=&quot;All IANA assigned TCP&quot;"/>`, 2*time.Minute)
	if err != nil {
		return fail(err)
	}
	portListID := xmlIDByExactName(portListData, "port_list", "All IANA assigned TCP")
	if portListID == "" {
		return fail(fmt.Errorf("Greenbone port list not found; feed may still be syncing"))
	}

	name := "xalgorix-" + filepath.Base(req.ScanDir)
	targetData, err := call("create-target", fmt.Sprintf(`<create_target><name>%s</name><hosts>%s</hosts><port_list id="%s"/></create_target>`, xmlEscape(name), xmlEscape(host), portListID), 2*time.Minute)
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
	reportID := firstXMLText(startData, "report_id")

	for {
		pollData, pollErr := call("poll-task", fmt.Sprintf(`<get_tasks task_id="%s" details="1"/>`, taskID), 2*time.Minute)
		if pollErr != nil {
			return fail(pollErr)
		}
		status := strings.ToLower(firstXMLText(pollData, "status"))
		if reportID == "" {
			reportID = firstXMLAttr(pollData, "report", "id")
		}
		if status == "done" {
			break
		}
		if status == "stopped" || status == "interrupted" {
			return fail(fmt.Errorf("Greenbone task ended with status %s", status))
		}
		select {
		case <-cmdCtx.Done():
			return fail(cmdCtx.Err())
		case <-time.After(10 * time.Second):
		}
	}
	if reportID == "" {
		return fail(fmt.Errorf("Greenbone report id unavailable"))
	}
	reportData, err := call("export-report", fmt.Sprintf(`<get_reports report_id="%s" details="1"/>`, reportID), 5*time.Minute)
	if err != nil {
		return fail(err)
	}
	if err := os.WriteFile(run.ArtifactPath, reportData, 0o600); err != nil {
		return fail(err)
	}
	_ = redactArtifact(run.ArtifactPath, secretValues(req, cfg))
	if truncateArtifact(run.ArtifactPath, cfg.MaxOutputBytes) {
		run.Truncated = true
		run.Reason = fmt.Sprintf("artifact truncated at configured %d-byte limit", cfg.MaxOutputBytes)
	}
	run.ExitCode, run.Status, run.FinishedAt = 0, "completed", time.Now().Format(time.RFC3339Nano)
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
