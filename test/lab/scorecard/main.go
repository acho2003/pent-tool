package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type findingLabel struct {
	Class    string `json:"class"`
	Path     string `json:"path"`
	Severity string `json:"severity"`
}

type labApplication struct {
	ID                string         `json:"id"`
	BaseURL           string         `json:"base_url"`
	ExpectedEndpoints []string       `json:"expected_endpoints"`
	ExpectedFindings  []findingLabel `json:"expected_findings"`
}

type labManifest struct {
	SchemaVersion int              `json:"schema_version"`
	Applications  []labApplication `json:"applications"`
}

type observedRun struct {
	ApplicationID   string `json:"application_id"`
	ResultPath      string `json:"result_path"`
	MetricsPath     string `json:"metrics_path"`
	DurationMS      int64  `json:"duration_ms"`
	PeakMemoryBytes int64  `json:"peak_memory_bytes"`
}

type observationManifest struct {
	SchemaVersion int           `json:"schema_version"`
	Runs          []observedRun `json:"runs"`
}

type observedFinding struct {
	Title    string `json:"title"`
	Endpoint string `json:"endpoint"`
	Target   string `json:"target"`
	CWE      string `json:"cwe"`
}

type scanResult struct {
	State      string             `json:"state"`
	Assessment *scanCoverageState `json:"assessment_coverage"`
	Findings   []observedFinding  `json:"findings"`
}

type scanCoverageState struct {
	State string `json:"state"`
}

type labMetrics struct {
	Requests int            `json:"request_count"`
	Paths    map[string]int `json:"paths"`
}

type classScore struct {
	Expected int `json:"expected"`
	TP       int `json:"true_positives"`
	FP       int `json:"false_positives"`
	FN       int `json:"false_negatives"`
}

type applicationScore struct {
	ID                string `json:"id"`
	State             string `json:"coverage_state"`
	EndpointsFound    int    `json:"endpoints_found"`
	EndpointsExpected int    `json:"endpoints_expected"`
	Requests          int    `json:"request_count"`
	DurationMS        int64  `json:"duration_ms"`
	PeakMemoryBytes   int64  `json:"peak_memory_bytes"`
	TP                int    `json:"true_positives"`
	FP                int    `json:"false_positives"`
	FN                int    `json:"false_negatives"`
}

type scorecard struct {
	SchemaVersion     int                   `json:"schema_version"`
	Applications      []applicationScore    `json:"applications"`
	Classes           map[string]classScore `json:"classes"`
	EndpointsFound    int                   `json:"endpoints_found"`
	EndpointsExpected int                   `json:"endpoints_expected"`
	TP                int                   `json:"true_positives"`
	FP                int                   `json:"false_positives"`
	FN                int                   `json:"false_negatives"`
	Precision         float64               `json:"precision"`
	Recall            float64               `json:"recall"`
	GatePassed        bool                  `json:"gate_passed"`
	GateFailures      []string              `json:"gate_failures,omitempty"`
}

func main() {
	manifestPath := flag.String("manifest", "test/lab/manifest.v1.json", "versioned lab expectations")
	observationsPath := flag.String("observations", "", "JSON paths to real scan results and lab metrics")
	gate := flag.Bool("gate", false, "exit nonzero unless initial lab gates pass")
	flag.Parse()
	if *observationsPath == "" {
		fmt.Fprintln(os.Stderr, "--observations is required")
		os.Exit(2)
	}
	var manifest labManifest
	if err := readJSON(*manifestPath, &manifest); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var observations observationManifest
	if err := readJSON(*observationsPath, &observations); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	result, err := evaluate(manifest, observations, filepath.Dir(*observationsPath))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *gate && !result.GatePassed {
		os.Exit(1)
	}
}

func readJSON(path string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func evaluate(manifest labManifest, observations observationManifest, baseDir string) (scorecard, error) {
	out := scorecard{SchemaVersion: 1, Classes: make(map[string]classScore)}
	if manifest.SchemaVersion != 1 || observations.SchemaVersion != 1 {
		return out, errors.New("unsupported manifest or observation schema version")
	}
	byID := make(map[string]observedRun, len(observations.Runs))
	for _, run := range observations.Runs {
		if run.ApplicationID == "" || byID[run.ApplicationID].ApplicationID != "" {
			return out, fmt.Errorf("missing or duplicate application ID %q", run.ApplicationID)
		}
		byID[run.ApplicationID] = run
	}
	for _, app := range manifest.Applications {
		run, ok := byID[app.ID]
		if !ok {
			return out, fmt.Errorf("missing scan result for %s", app.ID)
		}
		delete(byID, app.ID)
		var result scanResult
		if err := readJSON(resolvePath(baseDir, run.ResultPath), &result); err != nil {
			return out, err
		}
		var metrics labMetrics
		if err := readJSON(resolvePath(baseDir, run.MetricsPath), &metrics); err != nil {
			return out, err
		}
		item := scoreApplication(app, run, result, metrics, out.Classes)
		out.Applications = append(out.Applications, item)
		out.EndpointsFound += item.EndpointsFound
		out.EndpointsExpected += item.EndpointsExpected
		out.TP, out.FP, out.FN = out.TP+item.TP, out.FP+item.FP, out.FN+item.FN
		if item.State != "complete" {
			out.GateFailures = append(out.GateFailures, app.ID+": assessment coverage is "+item.State)
		}
		if item.DurationMS <= 0 || item.DurationMS > 30*60*1000 {
			out.GateFailures = append(out.GateFailures, app.ID+": duration missing or exceeds the gentle profile budget")
		}
		if item.PeakMemoryBytes <= 0 || item.PeakMemoryBytes > 8<<30 {
			out.GateFailures = append(out.GateFailures, app.ID+": peak memory missing or exceeds the reference-server limit")
		}
	}
	if len(byID) != 0 {
		return out, fmt.Errorf("observations contain %d unknown application(s)", len(byID))
	}
	if out.TP+out.FP > 0 {
		out.Precision = float64(out.TP) / float64(out.TP+out.FP)
	}
	if out.TP+out.FN > 0 {
		out.Recall = float64(out.TP) / float64(out.TP+out.FN)
	}
	if out.EndpointsFound != out.EndpointsExpected {
		out.GateFailures = append(out.GateFailures, "not every expected endpoint was requested")
	}
	if out.Precision < 0.95 {
		out.GateFailures = append(out.GateFailures, "precision is below 95%")
	}
	if out.Recall < 0.90 {
		out.GateFailures = append(out.GateFailures, "recall is below 90%")
	}
	for class, score := range out.Classes {
		if score.Expected > 0 && score.FN > 0 {
			out.GateFailures = append(out.GateFailures, class+": designated high-severity regression case was missed")
		}
	}
	sort.Strings(out.GateFailures)
	out.GatePassed = len(out.GateFailures) == 0
	return out, nil
}

func resolvePath(baseDir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}

func scoreApplication(app labApplication, run observedRun, result scanResult, metrics labMetrics, classes map[string]classScore) applicationScore {
	state := "unknown"
	if result.Assessment != nil {
		state = result.Assessment.State
	}
	if state == "" {
		state = "unknown"
	}
	item := applicationScore{ID: app.ID, State: state, EndpointsExpected: len(app.ExpectedEndpoints), Requests: metrics.Requests, DurationMS: run.DurationMS, PeakMemoryBytes: run.PeakMemoryBytes}
	for _, path := range app.ExpectedEndpoints {
		if metrics.Paths[path] > 0 {
			item.EndpointsFound++
		}
	}
	expected := make(map[string]bool, len(app.ExpectedFindings))
	for _, finding := range app.ExpectedFindings {
		key := finding.Class + "\x00" + finding.Path
		expected[key] = true
		score := classes[finding.Class]
		score.Expected++
		classes[finding.Class] = score
	}
	seen := map[string]bool{}
	for _, finding := range result.Findings {
		path := findingPath(app.BaseURL, finding)
		class := classifyFinding(path, finding)
		key := class + "\x00" + path
		if class != "" && expected[key] && !seen[key] {
			seen[key] = true
			item.TP++
			score := classes[class]
			score.TP++
			classes[class] = score
		} else {
			item.FP++
			if class == "" {
				class = "unclassified"
			}
			score := classes[class]
			score.FP++
			classes[class] = score
		}
	}
	for key := range expected {
		if !seen[key] {
			item.FN++
			class, _, _ := strings.Cut(key, "\x00")
			score := classes[class]
			score.FN++
			classes[class] = score
		}
	}
	return item
}

func findingPath(baseURL string, finding observedFinding) string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	for _, raw := range []string{finding.Endpoint, finding.Target} {
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		if u.IsAbs() {
			if !strings.EqualFold(u.Scheme, base.Scheme) || !strings.EqualFold(u.Host, base.Host) {
				return ""
			}
			return u.Path
		}
		if strings.HasPrefix(raw, "/") {
			return u.Path
		}
	}
	return ""
}

func classifyFinding(path string, finding observedFinding) string {
	title := strings.ToLower(finding.Title)
	switch path {
	case "/search":
		if hasCWE(finding.CWE, "79") || strings.Contains(title, "xss") || strings.Contains(title, "cross-site scripting") {
			return "reflected_xss"
		}
	case "/js/profile":
		if hasCWE(finding.CWE, "79") || strings.Contains(title, "dom xss") || strings.Contains(title, "cross-site scripting") {
			return "dom_xss"
		}
	case "/items":
		if hasCWE(finding.CWE, "89") || strings.Contains(title, "sql injection") {
			return "sql_injection"
		}
	case "/file":
		if hasCWE(finding.CWE, "22") || strings.Contains(title, "path traversal") || strings.Contains(title, "directory traversal") {
			return "path_traversal"
		}
	case "/.env":
		if hasCWE(finding.CWE, "538") || strings.Contains(title, "exposed file") || strings.Contains(title, "sensitive file") || strings.Contains(title, ".env") {
			return "exposed_file"
		}
	}
	return ""
}

func hasCWE(raw, want string) bool {
	for _, part := range strings.FieldsFunc(strings.ToLower(raw), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	}) {
		if part == want {
			return true
		}
	}
	return false
}
