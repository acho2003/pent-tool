package scanner

import (
	"context"
	"crypto/sha256"
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

// Bounded-snapshot limits shared by the bundled framework source checks.
const (
	bundledSASTMaxFile    = 1 << 20
	bundledSASTMaxBytes   = 32 << 20
	bundledSASTMaxFiles   = 5000
	bundledSASTMaxEntries = 20000
)

// bundledSASTSpec describes one framework-specific source check that runs
// Semgrep with a rule pack embedded in the binary (no registry download) over
// a bounded private snapshot of the selected files. Severity, CWE, confidence
// and remediation come from Catalog, never from the rule pack, and a result
// whose rule is not in Catalog fails the run.
type bundledSASTSpec struct {
	Scanner   string // registry ID, e.g. "nextjs-sast"
	Framework string // human name used in reasons, e.g. "Next.js"
	Version   string // catalog version recorded in the manifest and plan
	Rules     []byte
	Catalog   map[string]sastRule
	// IsTarget selects files (slash-separated, relative) for the snapshot.
	IsTarget func(path string) bool
	// DetectFile reports that a selected file alone proves the framework.
	DetectFile func(path string) bool
	// DetectPackage reports that a package.json dependency set proves it.
	DetectPackage func(deps map[string]json.RawMessage) bool
	// SkipDir reports an additional directory name to skip.
	SkipDir func(name string) bool
	// Postprocess may drop or adjust findings using the private snapshot
	// (for project-wide context a single-file rule cannot see).
	Postprocess func(snapshot string, files []sastFile, findings []Finding) []Finding
}

type sastRule struct{ title, severity, cwe, confidence, remediation string }

type sastFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

type sastManifest struct {
	SchemaVersion int        `json:"schema_version"`
	Catalog       string     `json:"catalog"`
	RulesSHA256   string     `json:"rules_sha256"`
	Files         []sastFile `json:"files"`
	Entries       int        `json:"entries"`
	Symlinks      int        `json:"symlinks_skipped"`
	Oversized     int        `json:"oversized_skipped"`
	ReadErrors    int        `json:"read_errors"`
	Bounded       bool       `json:"limit_reached"`
	Detected      bool       `json:"framework_detected"`
	EngineScanned int        `json:"engine_scanned"`
	EngineErrors  int        `json:"engine_errors"`
}

var bundledSASTDefaultSkipDirs = map[string]bool{"node_modules": true, ".git": true, ".next": true, "out": true, "dist": true, "build": true, "coverage": true, "vendor": true}

func snapshotBundledSAST(ctx context.Context, spec bundledSASTSpec, source, destination string) (sastManifest, error) {
	sum := sha256.Sum256(spec.Rules)
	manifest := sastManifest{SchemaVersion: 1, Catalog: spec.Version, RulesSHA256: hex.EncodeToString(sum[:]), Files: []sastFile{}}
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
		if manifest.Entries > bundledSASTMaxEntries {
			manifest.Bounded = true
			return fs.SkipAll
		}
		if d.Type()&os.ModeSymlink != 0 {
			manifest.Symlinks++
			return nil
		}
		if d.IsDir() {
			if bundledSASTDefaultSkipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".next-") || (spec.SkipDir != nil && spec.SkipDir(d.Name())) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if filepath.Base(path) == "package.json" && spec.DetectPackage != nil {
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
				if json.Unmarshal(body, &pkg) == nil && (spec.DetectPackage(pkg.Dependencies) || spec.DetectPackage(pkg.DevDependencies)) {
					manifest.Detected = true
				}
			}
		}
		slashPath := filepath.ToSlash(path)
		if !spec.IsTarget(slashPath) {
			return nil
		}
		if spec.DetectFile != nil && spec.DetectFile(slashPath) {
			manifest.Detected = true
		}
		if len(manifest.Files) >= bundledSASTMaxFiles {
			manifest.Bounded = true
			return fs.SkipAll
		}
		file, err := root.Open(path)
		if err != nil {
			manifest.ReadErrors++
			return nil
		}
		body, err := io.ReadAll(io.LimitReader(file, bundledSASTMaxFile+1))
		file.Close()
		if err != nil {
			manifest.ReadErrors++
			return nil
		}
		if len(body) > bundledSASTMaxFile {
			manifest.Oversized++
			return nil
		}
		if copied+len(body) > bundledSASTMaxBytes {
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
		manifest.Files = append(manifest.Files, sastFile{Path: slashPath, SHA256: hex.EncodeToString(digest[:]), Bytes: len(body)})
		return nil
	})
	return manifest, err
}

type bundledSemgrepResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
	} `json:"start"`
}

func normalizeBundledSAST(spec bundledSASTSpec, raw []byte, snapshot, evidence string, files []sastFile) ([]Finding, int, int, error) {
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
	var results []bundledSemgrepResult
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
		rule, ok := spec.Catalog[result.CheckID]
		if !ok || result.Start.Line < 1 {
			return nil, 0, 0, fmt.Errorf("Semgrep report referenced an unsupported rule or location")
		}
		path, err := relative(result.Path)
		if err != nil {
			return nil, 0, 0, err
		}
		location := fmt.Sprintf("%s:%d", path, result.Start.Line)
		findings = append(findings, Finding{SourceID: nextjsSourceID(result.CheckID, location), Scanner: spec.Scanner, RuleID: result.CheckID, Title: rule.title, Severity: rule.severity, Target: path, Endpoint: location, SourceLocation: location, CWE: rule.cwe, Confidence: rule.confidence, Description: "The bundled offline rule matched a configuration or local source-to-sink pattern. Deployed values, complete authorization logic, and exploitability were not verified.", Evidence: "rule " + result.CheckID + "; source location " + location + "; source text and matched values not retained", EvidenceRef: evidence, Remediation: rule.remediation, EvidenceCompleteness: "rule_and_snapshot_source_location"})
	}
	return findings, len(report.Paths.Scanned), len(problems), nil
}

func runBundledSAST(ctx context.Context, spec bundledSASTSpec, req Request, cfg Config, emit EmitFunc) (run Run) {
	run = Run{Scanner: spec.Scanner, Target: req.Target, Scope: req.Scope, Variant: spec.Version, Status: "running", StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	finish := func(status, reason string) Run {
		run.Status, run.Reason, run.FinishedAt = status, reason, time.Now().UTC().Format(time.RFC3339Nano)
		return finalizeRun(run)
	}
	if !req.TypedAssessment || !filepath.IsAbs(req.Target) {
		return finish("failed", spec.Framework+" source checks require a typed assessment and prepared absolute source directory")
	}
	if info, err := os.Stat(req.Target); err != nil || !info.IsDir() {
		return finish("failed", "prepared source directory is unavailable")
	}
	binary, err := exec.LookPath(cfg.SemgrepPath)
	if err != nil {
		run.GapKind = GapToolUnavailable
		return finish("failed", "Semgrep is unavailable for the bundled "+spec.Framework+" source rules")
	}
	workspace, err := os.MkdirTemp("", "xalgorix-"+spec.Scanner+"-")
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
	manifest, err := snapshotBundledSAST(ctx, spec, req.Target, snapshot)
	if err != nil {
		if ctx.Err() != nil {
			run.GapKind = GapCancelled
		}
		return finish("failed", "bounded source snapshot did not complete")
	}
	if !manifest.Detected {
		if manifest.Bounded || manifest.ReadErrors > 0 {
			run.GapKind = GapBudgetExhausted
			return finish("failed", spec.Framework+" applicability remains unknown because the bounded source inventory did not complete")
		}
		return finish("not_applicable", "no "+spec.Framework+" dependency or configuration was detected in the bounded source inventory")
	}
	dir := filepath.Join(req.ScanDir, "scanner-output", spec.Scanner)
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
		return finish("skipped", spec.Framework+" was detected but no supported source targets were selected")
	}
	rulesPath, rawPath := filepath.Join(workspace, "rules.yaml"), filepath.Join(workspace, "raw.json")
	if err := os.WriteFile(rulesPath, spec.Rules, 0600); err != nil {
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
	findings, scanned, errors, err := normalizeBundledSAST(spec, raw, snapshot, run.SourceManifestPath, manifest.Files)
	if err != nil {
		run.ParserOutcome = "FAILED"
		return finish("failed", err.Error())
	}
	if spec.Postprocess != nil {
		findings = spec.Postprocess(snapshot, manifest.Files, findings)
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
		run.Limitations = append(run.Limitations, RunLimitation{Kind: strings.ReplaceAll(spec.Scanner, "-sast", "") + "_source_partial", Reason: "source inventory limits, skipped/failed targets, engine diagnostics, or process failure left coverage incomplete"})
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
	return finish("completed", fmt.Sprintf("offline %s source rules scanned %d of %d selected files; %d review findings", spec.Framework, scanned, len(manifest.Files), len(findings)))
}
