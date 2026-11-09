package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// CodeQL is not bundled with Xalgorix. Its CLI terms allow free use only for
// open-source code, research and demonstration, and do not allow
// redistribution, while this repository publishes images. An operator who is
// entitled to use it supplies the CLI bundle (XALGORIX_CODEQL_PATH) and
// confirms that entitlement (XALGORIX_CODEQL_LICENSE_ACCEPTED=1); without both
// the adapter is unavailable and the planner says why.
const (
	codeqlDefaultTimeout = 60 * time.Minute
	codeqlMaxFiles       = 200000
	codeqlMaxSARIF       = 256 << 20
	codeqlMaxFindings    = 5000
)

// codeqlLanguages maps CodeQL language IDs to the source extensions that
// detect them. Only languages CodeQL extracts with --build-mode=none are run:
// the slim runtime has no compilers or language toolchains.
var codeqlLanguages = []struct {
	id         string
	extensions []string
}{
	{"actions", nil}, // detected by .github/workflows
	{"csharp", []string{".cs"}},
	{"java-kotlin", []string{".java"}},
	{"javascript-typescript", []string{".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}},
	{"python", []string{".py"}},
	{"ruby", []string{".rb"}},
}

// codeqlBuildRequired lists detected languages CodeQL can analyze only by
// building them, which the runtime cannot do; each becomes an explicit gap.
var codeqlBuildRequired = []struct {
	name       string
	extensions []string
}{
	{"C/C++", []string{".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}},
	{"Go", []string{".go"}},
	{"Kotlin", []string{".kt", ".kts"}},
	{"Swift", []string{".swift"}},
	{"Rust", []string{".rs"}},
}

var codeqlSkippedDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true, ".venv": true, "venv": true, "__pycache__": true, "target": true, "third_party": true, ".next": true}

// CodeQLUnavailableReason explains why the adapter cannot be planned, or
// returns "" when it can.
func CodeQLUnavailableReason(path string, licenseAccepted bool, lookPath func(string) (string, error)) string {
	if strings.TrimSpace(path) == "" {
		return "CodeQL is not bundled; supply the CLI bundle and set XALGORIX_CODEQL_PATH"
	}
	if _, err := lookPath(path); err != nil {
		return "CodeQL is not bundled; the configured XALGORIX_CODEQL_PATH executable was not found"
	}
	if !licenseAccepted {
		return "CodeQL's terms allow free use only for open-source code, research and demonstration; set XALGORIX_CODEQL_LICENSE_ACCEPTED=1 only if this deployment is entitled to analyze its code"
	}
	return ""
}

type codeqlRunner struct{}

func (codeqlRunner) Name() string { return "codeql" }
func (codeqlRunner) Descriptor() Descriptor {
	return Descriptor{Name: "codeql", Summary: "CodeQL security queries for languages extracted without a build", Phase: PhaseSAST, Weight: WeightHeavy, Applies: appliesToSource}
}

// codeqlDetection counts detected source files per language.
type codeqlDetection struct {
	Supported map[string]int `json:"supported"`
	Gaps      map[string]int `json:"needs_build"`
	Truncated bool           `json:"truncated,omitempty"`
}

func detectCodeQLLanguages(root string) codeqlDetection {
	detection := codeqlDetection{Supported: map[string]int{}, Gaps: map[string]int{}}
	byExtension := map[string]string{}
	for _, language := range codeqlLanguages {
		for _, extension := range language.extensions {
			byExtension[extension] = language.id
		}
	}
	gapByExtension := map[string]string{}
	for _, language := range codeqlBuildRequired {
		for _, extension := range language.extensions {
			gapByExtension[extension] = language.name
		}
	}
	files := 0
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			if path != root && codeqlSkippedDirs[entry.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		files++
		if files > codeqlMaxFiles {
			detection.Truncated = true
			return filepath.SkipAll
		}
		relative, _ := filepath.Rel(root, path)
		relative = filepath.ToSlash(relative)
		extension := strings.ToLower(filepath.Ext(entry.Name()))
		if strings.HasPrefix(relative, ".github/workflows/") && (extension == ".yml" || extension == ".yaml") {
			detection.Supported["actions"]++
		}
		if id := byExtension[extension]; id != "" {
			detection.Supported[id]++
		} else if name := gapByExtension[extension]; name != "" {
			detection.Gaps[name]++
		}
		return nil
	})
	return detection
}

func (codeqlRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	run := Run{Scanner: "codeql", Target: req.Target, Scope: req.Scope, Status: "running", StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	finish := func(status, reason string) Run {
		run.Status, run.Reason = status, reason
		run.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return finalizeRun(run)
	}
	if reason := CodeQLUnavailableReason(cfg.CodeQLPath, cfg.CodeQLLicenseAccepted, exec.LookPath); reason != "" {
		run.GapKind = GapToolUnavailable
		return finish("not_applicable", reason)
	}
	source := strings.TrimSpace(req.Target)
	if info, err := os.Stat(source); source == "" || err != nil || !info.IsDir() {
		return finish("not_applicable", "CodeQL requires a prepared source directory")
	}
	detection := detectCodeQLLanguages(source)
	var languages []string
	for id := range detection.Supported {
		languages = append(languages, id)
	}
	sort.Strings(languages)
	var gaps []string
	for name, count := range detection.Gaps {
		gaps = append(gaps, fmt.Sprintf("%s (%d files) needs a build toolchain the runtime does not include", name, count))
	}
	sort.Strings(gaps)
	if detection.Truncated {
		gaps = append(gaps, fmt.Sprintf("language detection stopped after %d files", codeqlMaxFiles))
	}
	if len(languages) == 0 {
		reason := "no language CodeQL can analyze without a build was found"
		if len(gaps) > 0 {
			reason += ": " + strings.Join(gaps, "; ")
		}
		run.GapKind = GapEmptyInput
		return finish("not_applicable", reason)
	}

	base := filepath.Join(req.ScanDir, "scanner-output", "codeql")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return finish("failed", "create CodeQL output directory: "+err.Error())
	}
	duration := cfg.CodeQLTimeout
	if duration <= 0 {
		duration = codeqlDefaultTimeout
	}
	deadline := time.Now().Add(duration)
	if emit != nil {
		emit(Event{Type: "scanner_started", Scanner: run.Scanner, Run: run})
	}
	var findings []Finding
	analyzed := 0
	var log []string
	log = append(log, fmt.Sprintf("Detected languages for CodeQL: %s", strings.Join(languages, ", ")))
	log = append(log, gaps...)
	for _, language := range languages {
		if ctx.Err() != nil {
			gaps = append(gaps, language+" was not analyzed: the run was stopped")
			continue
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			gaps = append(gaps, language+" was not analyzed: the CodeQL time budget was spent")
			continue
		}
		database := filepath.Join(base, "db-"+language)
		sarif := filepath.Join(base, language+".sarif.json")
		create := commandSpec{path: cfg.CodeQLPath, timeout: remaining, outputSubdir: language + "-create",
			args: []string{"database", "create", database, "--language=" + language, "--source-root=" + source, "--build-mode=none", "--overwrite", "--threads=1"}}
		step := executeSpec(ctx, "codeql", req, cfg, create, emit)
		log = append(log, fmt.Sprintf("%s database create: %s %s", language, step.Status, step.Reason))
		if step.Status != "completed" {
			gaps = append(gaps, fmt.Sprintf("%s database creation %s: %s", language, step.Status, firstNonEmpty(step.Reason, "see stderr")))
			_ = os.RemoveAll(database)
			continue
		}
		analyze := commandSpec{path: cfg.CodeQLPath, timeout: time.Until(deadline), outputSubdir: language + "-analyze",
			args: []string{"database", "analyze", database, "--format=sarif-latest", "--output=" + sarif, "--sarif-category=" + language, "--threads=1"}}
		step = executeSpec(ctx, "codeql", req, cfg, analyze, emit)
		log = append(log, fmt.Sprintf("%s database analyze: %s %s", language, step.Status, step.Reason))
		_ = os.RemoveAll(database) // databases hold a full source copy; keep only results
		if step.Status != "completed" {
			gaps = append(gaps, fmt.Sprintf("%s analysis %s: %s", language, step.Status, firstNonEmpty(step.Reason, "see stderr")))
			continue
		}
		if err := redactArtifact(sarif, req.Secrets); err != nil {
			_ = os.Remove(sarif)
			gaps = append(gaps, language+" results could not be sanitized and were discarded")
			continue
		}
		parsed, err := parseCodeQLSARIF(sarif, source)
		if err != nil {
			gaps = append(gaps, fmt.Sprintf("%s results could not be parsed: %v", language, err))
			continue
		}
		findings = append(findings, parsed...)
		analyzed++
	}

	run.ArtifactPath = filepath.Join(base, "findings.jsonl")
	file, err := os.OpenFile(run.ArtifactPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return finish("failed", "create CodeQL findings artifact: "+err.Error())
	}
	if len(findings) > codeqlMaxFindings {
		gaps = append(gaps, fmt.Sprintf("only the first %d of %d CodeQL results were kept", codeqlMaxFindings, len(findings)))
		findings = findings[:codeqlMaxFindings]
	}
	encoder := json.NewEncoder(file)
	for _, finding := range findings {
		if err := encoder.Encode(finding); err != nil {
			file.Close()
			return finish("failed", "write CodeQL findings artifact: "+err.Error())
		}
	}
	if err := file.Close(); err != nil {
		return finish("failed", "close CodeQL findings artifact: "+err.Error())
	}
	if err := redactArtifact(run.ArtifactPath, req.Secrets); err != nil {
		invalidateUnsafeArtifact(&run)
		return finish("failed", "CodeQL artifact redaction failed; artifact is unavailable")
	}
	run.StdoutPath = filepath.Join(base, "stdout.log")
	log = append(log, fmt.Sprintf("Findings retained: %d", len(findings)))
	_ = os.WriteFile(run.StdoutPath, []byte(strings.Join(log, "\n")+"\n"), 0o600)
	for _, gap := range gaps {
		run.Limitations = append(run.Limitations, RunLimitation{Kind: "language_not_analyzed", Reason: gap})
	}
	run.ParserOutcome = "SUCCESS"
	switch {
	case ctx.Err() != nil:
		run.ExecutionOutcome, run.Outcome, run.Completeness = "CANCELLED", "PARTIAL", "partial"
		return finish("cancelled", "CodeQL stopped; completed language results were retained")
	case analyzed == 0:
		run.Outcome, run.Completeness = "FAILED", "partial"
		return finish("failed", "no detected language could be analyzed: "+strings.Join(gaps, "; "))
	}
	run.ExecutionOutcome, run.Completeness, run.Outcome = "SUCCESS", "complete", "SUCCESS_NO_FINDINGS"
	if len(findings) > 0 {
		run.Outcome = "SUCCESS_WITH_FINDINGS"
	}
	if len(gaps) > 0 {
		run.Completeness, run.Outcome = "partial", "PARTIAL"
	}
	return finish("completed", "CodeQL analyzed "+strings.Join(analyzedLanguages(languages, gaps), ", ")+" with the default code-scanning suites")
}

// analyzedLanguages lists the languages without a recorded gap.
func analyzedLanguages(languages, gaps []string) []string {
	var out []string
	for _, language := range languages {
		failed := false
		for _, gap := range gaps {
			if strings.HasPrefix(gap, language+" ") {
				failed = true
			}
		}
		if !failed {
			out = append(out, language)
		}
	}
	return out
}

type codeqlSARIF struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Rules []codeqlRule `json:"rules"`
			} `json:"driver"`
			Extensions []struct {
				Rules []codeqlRule `json:"rules"`
			} `json:"extensions"`
		} `json:"tool"`
		Results []struct {
			RuleID    string `json:"ruleId"`
			RuleIndex *int   `json:"ruleIndex"`
			Rule      *struct {
				ID    string `json:"id"`
				Index *int   `json:"index"`
			} `json:"rule"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

type codeqlRule struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
	FullDescription struct {
		Text string `json:"text"`
	} `json:"fullDescription"`
	Properties struct {
		SecuritySeverity string   `json:"security-severity"`
		Precision        string   `json:"precision"`
		Tags             []string `json:"tags"`
	} `json:"properties"`
}

// parseCodeQLSARIF maps CodeQL SARIF results to findings. Severity follows the
// rule's security-severity score (the same thresholds GitHub code scanning
// uses); results of rules without one fall back to their SARIF level.
func parseCodeQLSARIF(path, sourceRoot string) ([]Finding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, codeqlMaxSARIF+1))
	if err != nil {
		return nil, err
	}
	if len(data) > codeqlMaxSARIF {
		return nil, fmt.Errorf("SARIF exceeds %d bytes", codeqlMaxSARIF)
	}
	var document codeqlSARIF
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("invalid SARIF: %w", err)
	}
	var out []Finding
	for _, sarifRun := range document.Runs {
		rules := map[string]codeqlRule{}
		var ordered []codeqlRule
		ordered = append(ordered, sarifRun.Tool.Driver.Rules...)
		for _, rule := range sarifRun.Tool.Driver.Rules {
			rules[rule.ID] = rule
		}
		for _, extension := range sarifRun.Tool.Extensions {
			for _, rule := range extension.Rules {
				if _, exists := rules[rule.ID]; !exists {
					rules[rule.ID] = rule
				}
			}
		}
		for _, result := range sarifRun.Results {
			ruleID := result.RuleID
			if ruleID == "" && result.Rule != nil {
				ruleID = result.Rule.ID
			}
			rule, ok := rules[ruleID]
			if !ok && result.RuleIndex != nil && *result.RuleIndex >= 0 && *result.RuleIndex < len(ordered) {
				rule = ordered[*result.RuleIndex]
				ruleID = rule.ID
			}
			location, line := "", 0
			if len(result.Locations) > 0 {
				location = result.Locations[0].PhysicalLocation.ArtifactLocation.URI
				line = result.Locations[0].PhysicalLocation.Region.StartLine
			}
			location = strings.TrimPrefix(location, "file://"+filepath.ToSlash(sourceRoot)+"/")
			sourceLocation := location
			if line > 0 {
				sourceLocation = location + ":" + strconv.Itoa(line)
			}
			title := firstNonEmpty(rule.ShortDescription.Text, rule.Name, ruleID, "CodeQL result")
			out = append(out, Finding{
				SourceID:       "codeql:" + ruleID + ":" + sourceLocation,
				Scanner:        "codeql",
				RuleID:         ruleID,
				Title:          title,
				Severity:       codeqlSeverity(rule.Properties.SecuritySeverity, result.Level),
				Target:         location,
				Endpoint:       sourceLocation,
				SourceLocation: sourceLocation,
				Description:    strings.TrimSpace(result.Message.Text),
				Evidence:       strings.TrimSpace(firstNonEmpty(rule.FullDescription.Text, rule.ShortDescription.Text)),
				CWE:            codeqlCWE(rule.Properties.Tags),
				Confidence:     rule.Properties.Precision,
				EvidenceRef:    path,
			})
		}
	}
	return out, nil
}

func codeqlSeverity(securitySeverity, level string) string {
	if score, err := strconv.ParseFloat(strings.TrimSpace(securitySeverity), 64); err == nil {
		switch {
		case score >= 9:
			return "critical"
		case score >= 7:
			return "high"
		case score >= 4:
			return "medium"
		case score > 0:
			return "low"
		}
	}
	switch strings.ToLower(level) {
	case "error":
		return "medium"
	case "warning":
		return "low"
	default:
		return "info"
	}
}

func codeqlCWE(tags []string) string {
	for _, tag := range tags {
		if number, ok := strings.CutPrefix(strings.ToLower(tag), "external/cwe/cwe-"); ok {
			if value, err := strconv.Atoi(number); err == nil {
				return "CWE-" + strconv.Itoa(value)
			}
		}
	}
	return ""
}

func parseCodeQL(path string) ([]Finding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var findings []Finding
	decoder := json.NewDecoder(file)
	for {
		var finding Finding
		if err := decoder.Decode(&finding); err == io.EOF {
			return findings, nil
		} else if err != nil {
			return findings, fmt.Errorf("parse CodeQL findings: %w", err)
		}
		if finding.Scanner == "codeql" && finding.SourceID != "" {
			findings = append(findings, finding)
		}
	}
}

var _ Runner = codeqlRunner{}
