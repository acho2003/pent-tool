package scanner

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

//go:embed rules/nextjs.yaml
var nextjsSASTRules []byte

const nextjsSASTVersion = "nextjs-sast-v1"
const nextjsSASTMaxFile = 1 << 20
const nextjsSASTMaxBytes = 32 << 20
const nextjsSASTMaxFiles = 5000
const nextjsSASTMaxEntries = 20000

type nextjsSASTRunner struct{}

func (nextjsSASTRunner) Name() string { return "nextjs-sast" }
func (nextjsSASTRunner) Descriptor() Descriptor {
	return Descriptor{Name: "nextjs-sast", Summary: "Offline Next.js configuration and local request-to-sink source checks", Phase: PhaseSAST, Applies: appliesToSource, Weight: WeightLight}
}

type nextjsSASTFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}
type nextjsSASTManifest struct {
	SchemaVersion  int              `json:"schema_version"`
	Catalog        string           `json:"catalog"`
	RulesSHA256    string           `json:"rules_sha256"`
	Files          []nextjsSASTFile `json:"files"`
	Entries        int              `json:"entries"`
	Symlinks       int              `json:"symlinks_skipped"`
	Oversized      int              `json:"oversized_skipped"`
	ReadErrors     int              `json:"read_errors"`
	Bounded        bool             `json:"limit_reached"`
	NextjsDetected bool             `json:"nextjs_detected"`
	EngineScanned  int              `json:"engine_scanned"`
	EngineErrors   int              `json:"engine_errors"`
}

func nextjsSASTConfig(name string) bool {
	return name == "next.config.js" || name == "next.config.mjs" || name == "next.config.cjs" || name == "next.config.ts"
}
func nextjsSASTTarget(name string) bool {
	base := filepath.Base(name)
	if nextjsSASTConfig(base) {
		return true
	}
	path := "/" + filepath.ToSlash(name)
	if strings.Contains(path, "/app/") && (base == "route.js" || base == "route.ts") {
		return true
	}
	ext := filepath.Ext(name)
	return strings.Contains(path, "/pages/api/") && (ext == ".js" || ext == ".jsx" || ext == ".ts" || ext == ".tsx" || ext == ".mjs" || ext == ".cjs")
}
func snapshotNextjsSAST(ctx context.Context, source, destination string) (nextjsSASTManifest, error) {
	sum := sha256.Sum256(nextjsSASTRules)
	manifest := nextjsSASTManifest{SchemaVersion: 1, Catalog: nextjsSASTVersion, RulesSHA256: hex.EncodeToString(sum[:]), Files: []nextjsSASTFile{}}
	root, err := os.OpenRoot(source)
	if err != nil {
		return manifest, fmt.Errorf("source directory cannot be opened")
	}
	defer root.Close()
	copied := 0
	err = fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			manifest.ReadErrors++
			return nil
		}
		manifest.Entries++
		if manifest.Entries > nextjsSASTMaxEntries {
			manifest.Bounded = true
			return fs.SkipAll
		}
		if d.Type()&os.ModeSymlink != 0 {
			manifest.Symlinks++
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", ".git", ".next", "out", "dist", "build", "coverage", "vendor":
				return fs.SkipDir
			}
			if strings.HasPrefix(d.Name(), ".next-") {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if filepath.Base(path) == "package.json" {
			file, err := root.Open(path)
			if err != nil {
				manifest.ReadErrors++
				return nil
			}
			body, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
			file.Close()
			if err == nil && len(body) <= 64<<10 {
				var pkg struct {
					Dependencies    map[string]json.RawMessage `json:"dependencies"`
					DevDependencies map[string]json.RawMessage `json:"devDependencies"`
				}
				if json.Unmarshal(body, &pkg) == nil && (pkg.Dependencies["next"] != nil || pkg.DevDependencies["next"] != nil) {
					manifest.NextjsDetected = true
				}
			}
		}
		if !nextjsSASTTarget(path) {
			return nil
		}
		if nextjsSASTConfig(filepath.Base(path)) {
			manifest.NextjsDetected = true
		}
		if len(manifest.Files) >= nextjsSASTMaxFiles {
			manifest.Bounded = true
			return fs.SkipAll
		}
		file, err := root.Open(path)
		if err != nil {
			manifest.ReadErrors++
			return nil
		}
		body, err := io.ReadAll(io.LimitReader(file, nextjsSASTMaxFile+1))
		file.Close()
		if err != nil {
			manifest.ReadErrors++
			return nil
		}
		if len(body) > nextjsSASTMaxFile {
			manifest.Oversized++
			return nil
		}
		if copied+len(body) > nextjsSASTMaxBytes {
			manifest.Bounded = true
			return fs.SkipAll
		}
		output := filepath.Join(destination, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(output), 0700); err != nil {
			return fmt.Errorf("create source snapshot directory failed")
		}
		if err := os.WriteFile(output, body, 0600); err != nil {
			return fmt.Errorf("copy bounded source snapshot failed")
		}
		copied += len(body)
		digest := sha256.Sum256(body)
		manifest.Files = append(manifest.Files, nextjsSASTFile{Path: filepath.ToSlash(path), SHA256: hex.EncodeToString(digest[:]), Bytes: len(body)})
		return nil
	})
	return manifest, err
}

type nextjsSASTRule struct{ title, severity, cwe, confidence, remediation string }

var nextjsSASTCatalog = map[string]nextjsSASTRule{
	"nextjs-config-private-env-inline":      {"Potential private value exported through Next.js env configuration", "medium", "CWE-200", "static_configuration", "Keep private values out of next.config env; use server-only environment access and minimal response data."},
	"nextjs-config-local-image-fetch":       {"Local-IP image optimization enabled", "low", "CWE-918", "static_configuration", "Review whether local-IP image optimization is required and constrain fetch destinations and redirects."},
	"nextjs-config-wildcard-action-origins": {"Global wildcard in Server Action origin configuration", "medium", "CWE-346", "static_configuration", "Use explicit intended Server Action origins and verify the deployed framework's origin behavior."},
	"nextjs-route-query-redirect":           {"Request-derived redirect destination in a Next.js handler", "medium", "CWE-601", "local_dataflow", "Normalize redirect destinations and enforce an explicit local-path or destination allowlist."},
	"nextjs-route-query-fetch":              {"Request-derived server-side fetch destination in a Next.js handler", "medium", "CWE-918", "local_dataflow", "Enforce destination and redirect allowlists before server-side fetching, then verify the policy with a controlled callback."},
	"nextjs-route-private-env-response":     {"Potential private environment value serialized to a response", "medium", "CWE-200", "local_dataflow", "Return minimal authorized data and keep private environment values out of response serialization."},
}

type nextjsSemgrepResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
	} `json:"start"`
}

func normalizeNextjsSAST(raw []byte, snapshot, evidence string, files []nextjsSASTFile) ([]Finding, int, int, error) {
	var report struct {
		Results json.RawMessage `json:"results"`
		Errors  json.RawMessage `json:"errors"`
		Paths   struct {
			Scanned []string `json:"scanned"`
		} `json:"paths"`
	}
	if !json.Valid(raw) || json.Unmarshal(raw, &report) != nil || len(report.Results) == 0 || report.Results[0] != '[' || len(report.Errors) == 0 || report.Errors[0] != '[' || report.Paths.Scanned == nil {
		return nil, 0, 0, fmt.Errorf("Semgrep report is missing required result, error, or scanned-path arrays")
	}
	var results []nextjsSemgrepResult
	var problems []json.RawMessage
	if json.Unmarshal(report.Results, &results) != nil || json.Unmarshal(report.Errors, &problems) != nil {
		return nil, 0, 0, fmt.Errorf("Semgrep result schema is invalid")
	}
	known := map[string]bool{}
	for _, file := range files {
		known[filepath.Clean(filepath.FromSlash(file.Path))] = true
	}
	relative := func(path string) (string, error) {
		if filepath.IsAbs(path) {
			value, err := filepath.Rel(snapshot, path)
			if err != nil {
				return "", fmt.Errorf("source result path is invalid")
			}
			path = value
		}
		path = filepath.Clean(path)
		if !known[path] || path == "." || filepath.IsAbs(path) || path == ".." || strings.HasPrefix(path, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("Semgrep report referenced a file outside the selected snapshot")
		}
		return filepath.ToSlash(path), nil
	}
	seenScanned := map[string]bool{}
	for _, path := range report.Paths.Scanned {
		rel, err := relative(path)
		if err != nil {
			return nil, 0, 0, err
		}
		if seenScanned[rel] {
			return nil, 0, 0, fmt.Errorf("Semgrep repeated a scanned-file acknowledgement")
		}
		seenScanned[rel] = true
	}
	var findings []Finding
	for _, result := range results {
		rule, ok := nextjsSASTCatalog[result.CheckID]
		if !ok || result.Start.Line < 1 {
			return nil, 0, 0, fmt.Errorf("Semgrep report referenced an unsupported rule or location")
		}
		path, err := relative(result.Path)
		if err != nil {
			return nil, 0, 0, err
		}
		location := fmt.Sprintf("%s:%d", path, result.Start.Line)
		findings = append(findings, Finding{SourceID: nextjsSourceID(result.CheckID, location), Scanner: "nextjs-sast", RuleID: result.CheckID, Title: rule.title, Severity: rule.severity, Target: path, Endpoint: location, SourceLocation: location, CWE: rule.cwe, Confidence: rule.confidence, Description: "The bundled offline rule matched a configuration or local source-to-sink pattern. Deployed values, complete authorization logic, and exploitability were not verified.", Evidence: "rule " + result.CheckID + "; source location " + location + "; source text and matched values not retained", EvidenceRef: evidence, Remediation: rule.remediation, EvidenceCompleteness: "rule_and_snapshot_source_location"})
	}
	return findings, len(report.Paths.Scanned), len(problems), nil
}

func (nextjsSASTRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) (run Run) {
	run = Run{Scanner: "nextjs-sast", Target: req.Target, Scope: req.Scope, Variant: nextjsSASTVersion, Status: "running", StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	finish := func(status, reason string) Run {
		run.Status, run.Reason, run.FinishedAt = status, reason, time.Now().UTC().Format(time.RFC3339Nano)
		return finalizeRun(run)
	}
	if !req.TypedAssessment || !filepath.IsAbs(req.Target) {
		return finish("failed", "Next.js source checks require a typed assessment and prepared absolute source directory")
	}
	if info, err := os.Stat(req.Target); err != nil || !info.IsDir() {
		return finish("failed", "prepared source directory is unavailable")
	}
	binary, err := exec.LookPath(cfg.SemgrepPath)
	if err != nil {
		run.GapKind = GapToolUnavailable
		return finish("failed", "Semgrep is unavailable for the bundled Next.js source rules")
	}
	workspace, err := os.MkdirTemp("", "xalgorix-nextjs-sast-")
	if err != nil {
		return finish("failed", "private source-analysis workspace could not be created")
	}
	defer func() {
		if err := os.RemoveAll(workspace); err != nil {
			run.Status, run.Outcome, run.Completeness = "failed", "PARTIAL", "partial"
			run.GapKind = GapInterruptedWrite
			run.Reason = "private source workspace cleanup failed; manual cleanup required: " + workspace
			run = finalizeRun(run)
		}
	}()
	snapshot := filepath.Join(workspace, "source")
	if err := os.MkdirAll(snapshot, 0700); err != nil {
		return finish("failed", "create private source snapshot failed")
	}
	manifest, err := snapshotNextjsSAST(ctx, req.Target, snapshot)
	if err != nil {
		if ctx.Err() != nil {
			run.GapKind = GapCancelled
		}
		return finish("failed", "bounded source snapshot did not complete")
	}
	if !manifest.NextjsDetected {
		if manifest.Bounded || manifest.ReadErrors > 0 {
			run.GapKind = GapBudgetExhausted
			return finish("failed", "Next.js applicability remains unknown because the bounded source inventory did not complete")
		}
		return finish("not_applicable", "no Next.js dependency or configuration was detected in the bounded source inventory")
	}
	dir := filepath.Join(req.ScanDir, "scanner-output", "nextjs-sast")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return finish("failed", "create source evidence directory failed")
	}
	run.SourceManifestPath = filepath.Join(dir, "source-manifest.json")
	persistManifest := func() error {
		body, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(run.SourceManifestPath, body, 0600)
	}
	if err := persistManifest(); err != nil {
		return finish("failed", "persist source inventory failed")
	}
	if len(manifest.Files) == 0 {
		run.GapKind = GapEmptyInput
		return finish("skipped", "Next.js was detected but no supported source targets were selected")
	}
	rulesPath, rawPath := filepath.Join(workspace, "nextjs.yaml"), filepath.Join(workspace, "raw.json")
	if err := os.WriteFile(rulesPath, nextjsSASTRules, 0600); err != nil {
		return finish("failed", "write bundled rule pack failed")
	}
	// An explicit empty ignore file prevents repository-local ignore files from
	// hiding selected targets. The original project is never executed or modified.
	if err := os.WriteFile(filepath.Join(snapshot, ".semgrepignore"), nil, 0600); err != nil {
		return finish("failed", "prepare isolated source selection failed")
	}
	timeout := cfg.SemgrepTimeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	if remaining := cfg.Budget.Remaining(); remaining < timeout {
		timeout = remaining
	}
	if timeout <= 0 {
		run.GapKind = GapBudgetExhausted
		return finish("failed", "source assessment time budget exhausted")
	}
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	args := []string{"scan", "--config", rulesPath, "--metrics", "off", "--disable-version-check", "--no-rewrite-rule-ids", "--no-git-ignore", "--disable-nosem", "--strict", "--json", "--quiet", "--jobs", "1", "--max-target-bytes", "1048576", "--timeout", "5", "--max-memory", "512", "--output", rawPath, "."}
	command := exec.CommandContext(commandCtx, binary, args...)
	command.Dir = snapshot
	command.Stdout, command.Stderr = io.Discard, io.Discard
	configureCommandCancellation(command)
	command.Env = append(command.Environ(), "SEMGREP_SEND_METRICS=off", "SEMGREP_ENABLE_VERSION_CHECK=0", "SEMGREP_SETTINGS_FILE="+filepath.Join(workspace, "settings.yml"), "SEMGREP_LOG_FILE="+filepath.Join(workspace, "semgrep.log"))
	if emit != nil {
		emit(Event{Type: "scanner_started", Scanner: run.Scanner, Run: run})
	}
	commandErr := command.Run()
	if command.ProcessState != nil {
		run.ExitCode = command.ProcessState.ExitCode()
	}
	file, err := os.Open(rawPath)
	if err != nil {
		run.ParserOutcome = "FAILED"
		return finish("failed", "Semgrep did not produce a usable report; raw tool output was not retained")
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, (16<<20)+1))
	file.Close()
	if readErr != nil || len(raw) > 16<<20 {
		run.ParserOutcome = "FAILED"
		return finish("failed", "Semgrep report was unreadable or beyond its 16 MiB limit")
	}
	findings, scanned, errors, err := normalizeNextjsSAST(raw, snapshot, run.SourceManifestPath, manifest.Files)
	if err != nil {
		run.ParserOutcome = "FAILED"
		return finish("failed", err.Error())
	}
	manifest.EngineScanned, manifest.EngineErrors = scanned, errors
	if err := persistManifest(); err != nil {
		return finish("failed", "persist source execution inventory failed")
	}
	artifact, err := os.OpenFile(filepath.Join(dir, "findings.jsonl"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return finish("failed", "create normalized source findings failed")
	}
	defer artifact.Close()
	run.ArtifactPath = artifact.Name()
	for _, finding := range findings {
		if err := json.NewEncoder(artifact).Encode(finding); err != nil {
			return finish("failed", "persist normalized source finding failed")
		}
	}
	if err := artifact.Sync(); err != nil {
		return finish("failed", "sync source findings failed")
	}
	run.ParserOutcome, run.Completeness, run.Outcome = "SUCCESS", "complete", "SUCCESS_NO_FINDINGS"
	if len(findings) > 0 {
		run.Outcome = "SUCCESS_WITH_FINDINGS"
	}
	if manifest.Bounded || manifest.ReadErrors > 0 || manifest.Symlinks > 0 || manifest.Oversized > 0 || errors > 0 || scanned < len(manifest.Files) || commandErr != nil {
		run.Completeness, run.Outcome = "partial", "PARTIAL"
		run.Limitations = append(run.Limitations, RunLimitation{Kind: "nextjs_source_partial", Reason: "source inventory limits, skipped/failed targets, engine diagnostics, or process failure left coverage incomplete"})
	}
	if commandErr != nil {
		if commandCtx.Err() != nil {
			run.GapKind = GapCancelled
			if ctx.Err() == nil {
				run.GapKind = GapBudgetExhausted
			}
		}
		return finish("failed", "Semgrep execution did not complete; validated partial findings were retained")
	}
	if scanned == 0 {
		run.GapKind = GapEmptyInput
		return finish("skipped", "Semgrep acknowledged no selected source files; no clean result can be inferred")
	}
	return finish("completed", fmt.Sprintf("offline Next.js source rules scanned %d of %d selected files; %d review findings", scanned, len(manifest.Files), len(findings)))
}
