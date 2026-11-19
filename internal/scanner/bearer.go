package scanner

import (
	"fmt"
	"path/filepath"
	"strings"
)

// buildBearer runs Bearer's static security/privacy analysis over a source
// checkout. Bearer bundles its own rules in the binary (no registry fetch), so
// it works offline. --exit-code 0 keeps a findings-present run from exiting
// non-zero (which the command framework would read as failure).
func buildBearer(req Request, cfg Config) commandSpec {
	src := strings.TrimSpace(req.Target)
	if src == "" {
		return commandSpec{notApp: "bearer requires a source path", timeout: cfg.BearerTimeout}
	}
	artifact := filepath.Join(req.ScanDir, "scanner-output", "bearer", "results.json")
	args := []string{
		"scan", src,
		"--format", "json",
		"--output", artifact,
		"--exit-code", "0",
		"--quiet",
		"--disable-version-check",
		"--no-color",
	}
	return commandSpec{path: cfg.BearerPath, args: args, artifact: artifact, timeout: cfg.BearerTimeout, classify: bearerFailure}
}

func bearerFailure(exitCode int, output string) (string, string, bool) {
	text := strings.ToLower(output)
	if strings.Contains(text, "no supported languages") || strings.Contains(text, "no files to scan") {
		return "not_applicable", "Bearer found no supported source files in the target", false
	}
	return "failed", fmt.Sprintf("Bearer exited with code %d; see scanner stderr for details", exitCode), true
}

// parseBearer reads Bearer's JSON report. The top-level keys are severity
// buckets ("critical","high","medium","low","warning"), each a list of
// findings carrying a rule id, title, CWE list and file:line location.
func parseBearer(path string) ([]Finding, error) {
	var root map[string]any
	if err := readJSON(path, &root); err != nil {
		return nil, err
	}
	var out []Finding
	for _, severity := range []string{"critical", "high", "medium", "low", "warning"} {
		for _, fv := range array(root[severity]) {
			f, _ := fv.(map[string]any)
			if f == nil {
				continue
			}
			rule := str(f["id"])
			file := firstNonEmpty(str(f["filename"]), str(f["full_filename"]))
			line := str(f["line_number"])
			location := file
			if line != "" {
				location = file + ":" + line
			}
			out = append(out, Finding{
				SourceID:       "bearer:" + rule + ":" + location,
				Scanner:        "bearer",
				RuleID:         rule,
				Title:          firstNonEmpty(str(f["title"]), rule, "bearer finding"),
				Severity:       bearerSeverity(severity),
				Target:         file,
				Endpoint:       location,
				SourceLocation: location,
				CWE:            bearerCWE(f["cwe_ids"]),
				Description:    bearerSummary(str(f["description"])),
			})
		}
	}
	return out, nil
}

// bearerSeverity maps Bearer's buckets to the shared scale. Bearer's "warning"
// is advisory, so it lands at low.
func bearerSeverity(bucket string) string {
	switch strings.ToLower(strings.TrimSpace(bucket)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "low"
	}
}

func bearerCWE(v any) string {
	var ids []string
	for _, id := range array(v) {
		if s := str(id); s != "" {
			if !strings.HasPrefix(strings.ToUpper(s), "CWE-") {
				s = "CWE-" + s
			}
			ids = append(ids, s)
		}
	}
	return strings.Join(ids, ", ")
}

// bearerSummary trims Bearer's long markdown description to its "## Description"
// text, so the finding carries a concise explanation rather than the full
// remediation/reference body.
func bearerSummary(description string) string {
	description = strings.TrimSpace(description)
	if description == "" {
		return ""
	}
	// Drop a leading "## Description" heading and stop at the next heading.
	body := description
	if idx := strings.Index(body, "## Description"); idx >= 0 {
		body = body[idx+len("## Description"):]
	}
	if idx := strings.Index(body, "\n## "); idx >= 0 {
		body = body[:idx]
	}
	body = strings.TrimSpace(body)
	if body == "" {
		body = description
	}
	if len(body) > 600 {
		body = strings.TrimSpace(body[:600]) + "…"
	}
	return body
}
