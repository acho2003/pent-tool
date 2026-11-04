package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

const nextjsDepsVersion = "nextjs-deps-v2"
const nextjsDepsMaxBytes = 4 << 20
const nextjsDepsMaxPackages = 20000
const nextjsDepsMaxResolutions = 128
const nextjsDepsMaxVersionLength = 256
const nextjsDepsMaxFindings = 1000

var nextjsExactLockVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

type nextjsDepsRunner struct{}

func (nextjsDepsRunner) Name() string { return "nextjs-deps" }
func (nextjsDepsRunner) Descriptor() Descriptor {
	return Descriptor{Name: "nextjs-deps", Summary: "Offline resolved Next.js lockfile advisory matches", Phase: PhaseSAST, Applies: appliesToSource, Weight: WeightLight}
}

type nextjsLockedResolution struct {
	Path     string `json:"path"`
	Version  string `json:"version"`
	Dev      bool   `json:"dev,omitempty"`
	Optional bool   `json:"optional,omitempty"`
	Lockfile string `json:"lockfile,omitempty"`
	Location string `json:"location,omitempty"`
}
type nextjsDepsManifest struct {
	Format            string                   `json:"format,omitempty"`
	FormatVersion     string                   `json:"format_version,omitempty"`
	Formats           []string                 `json:"formats,omitempty"`
	Files             []nextjsSASTFile         `json:"files,omitempty"`
	Schema            int                      `json:"schema_version"`
	Catalog           string                   `json:"catalog"`
	AdvisorySnapshot  string                   `json:"advisory_snapshot"`
	AdvisoryRetrieved string                   `json:"advisory_retrieved"`
	AdvisorySHA256    string                   `json:"advisory_sha256"`
	File              nextjsSASTFile           `json:"file"`
	LockVersion       int                      `json:"lockfile_version"`
	Packages          int                      `json:"package_entries"`
	Resolutions       []nextjsLockedResolution `json:"resolutions"`
	Gaps              []string                 `json:"gaps,omitempty"`
}

func exactNextjsLockVersion(version string) bool {
	if len(version) > nextjsDepsMaxVersionLength || !nextjsExactLockVersion.MatchString(version) {
		return false
	}
	parsed, ok := parseSemver(version)
	if !ok {
		return false
	}
	for _, part := range parsed.pre {
		if len(part) > 1 && part[0] == '0' && strings.Trim(part, "0123456789") == "" {
			return false
		}
	}
	return true
}

func parseNextjsLock(ctx context.Context, body []byte) (nextjsDepsManifest, error) {
	result := nextjsDepsManifest{Schema: 1, Catalog: nextjsDepsVersion, Format: "npm", Resolutions: []nextjsLockedResolution{}}
	if len(body) > nextjsDepsMaxBytes {
		return result, fmt.Errorf("npm lockfile exceeds the 4 MiB limit")
	}
	var lock struct {
		Version      int                        `json:"lockfileVersion"`
		Packages     map[string]json.RawMessage `json:"packages"`
		Dependencies map[string]json.RawMessage `json:"dependencies"`
	}
	if json.Unmarshal(body, &lock) != nil {
		return result, fmt.Errorf("npm lockfile JSON could not be decoded")
	}
	result.LockVersion = lock.Version
	if lock.Version == 1 {
		return parseNextjsLegacyLock(ctx, body)
	}
	if (lock.Version != 2 && lock.Version != 3) || lock.Packages == nil {
		return result, fmt.Errorf("only npm lockfile versions 2 and 3 with package records are supported")
	}
	result.Packages = len(lock.Packages)
	gaps := map[string]bool{}
	gap := func(message string) {
		if !gaps[message] {
			gaps[message] = true
			result.Gaps = append(result.Gaps, message)
		}
	}
	keys := make([]string, 0, len(lock.Packages))
	for key := range lock.Packages {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) > nextjsDepsMaxPackages {
		keys = keys[:nextjsDepsMaxPackages]
		gap("package record count exceeded the 20000-entry limit")
	}
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return result, fmt.Errorf("lockfile analysis was cancelled")
		}
		if key == "" {
			continue
		} // Root metadata is a declaration, not a resolved package.
		raw := bytes.TrimSpace(lock.Packages[key])
		if len(raw) == 0 || raw[0] != '{' {
			gap("one or more package records could not be decoded")
			continue
		}
		var pkg struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			Link     bool   `json:"link"`
			Dev      bool   `json:"dev"`
			Optional bool   `json:"optional"`
		}
		if json.Unmarshal(lock.Packages[key], &pkg) != nil {
			gap("one or more package records could not be decoded")
			continue
		}
		namedNext := key == "node_modules/next" || strings.HasSuffix(key, "/node_modules/next")
		if pkg.Name != "next" && (!namedNext || pkg.Name != "") {
			continue
		}
		validPath := len(key) <= 1024 && !strings.ContainsAny(key, "\\:\x00") && !strings.HasPrefix(key, "../") && !path.IsAbs(key) && path.Clean(key) == key && (strings.HasPrefix(key, "node_modules/") || strings.Contains(key, "/node_modules/"))
		for _, r := range key {
			if unicode.IsControl(r) {
				validPath = false
				break
			}
		}
		if !validPath {
			gap("a Next.js package record has an unsupported relative installation path")
			continue
		}
		if pkg.Link || !exactNextjsLockVersion(pkg.Version) {
			gap("a Next.js record is linked or lacks an exact supported version")
			continue
		}
		if len(result.Resolutions) >= nextjsDepsMaxResolutions {
			gap("Next.js resolutions exceeded the 128-entry limit")
			break
		}
		result.Resolutions = append(result.Resolutions, nextjsLockedResolution{Path: key, Version: pkg.Version, Dev: pkg.Dev, Optional: pkg.Optional})
	}
	return result, nil
}

func (nextjsDepsRunner) Run(ctx context.Context, req Request, _ Config, _ EmitFunc) Run {
	run := Run{Scanner: "nextjs-deps", Target: req.Target, Scope: req.Scope, Status: "running", Variant: nextjsDepsVersion, StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	finish := func(status, reason string) Run { run.Status, run.Reason = status, reason; return finalizeRun(run) }
	if !req.TypedAssessment || !filepath.IsAbs(req.Target) {
		return finish("failed", "Next.js dependency checks require a typed assessment and prepared absolute source directory")
	}
	if ctx.Err() != nil {
		run.GapKind = GapCancelled
		return finish("cancelled", "dependency checks cancelled before source access")
	}
	root, err := os.OpenRoot(req.Target)
	if err != nil {
		return finish("failed", "prepared source directory is unavailable")
	}
	defer root.Close()
	manifest := nextjsDepsManifest{Schema: 1, Catalog: nextjsDepsVersion, Resolutions: []nextjsLockedResolution{}}
	npmShrinkwrap := false
	found := false
	for _, name := range []string{"npm-shrinkwrap.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"} {
		if name == "package-lock.json" && npmShrinkwrap {
			continue
		}
		info, err := root.Lstat(name)
		if os.IsNotExist(err) {
			continue
		}
		found = true
		if name == "npm-shrinkwrap.json" {
			npmShrinkwrap = true
		}
		if err != nil {
			nextjsLockGap(&manifest, "a root lockfile's metadata is unavailable")
			continue
		}
		if !info.Mode().IsRegular() {
			nextjsLockGap(&manifest, "root lockfiles must be regular files without symlinks")
			continue
		}
		if info.Size() > nextjsDepsMaxBytes {
			nextjsLockGap(&manifest, "a root lockfile exceeds the 4 MiB read limit")
			continue
		}
		file, err := root.Open(name)
		if err != nil {
			nextjsLockGap(&manifest, "a root lockfile could not be opened")
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(file, nextjsDepsMaxBytes+1))
		after, statErr := file.Stat()
		file.Close()
		if readErr != nil || statErr != nil || !os.SameFile(info, after) || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) || len(body) > nextjsDepsMaxBytes {
			nextjsLockGap(&manifest, "a root lockfile could not be read as a stable bounded file")
			continue
		}
		var parsed nextjsDepsManifest
		switch name {
		case "pnpm-lock.yaml":
			parsed, err = parseNextjsYAMLLock(ctx, body, true)
		case "yarn.lock":
			if bytes.Contains(body[:min(len(body), 1024)], []byte("# yarn lockfile v1")) {
				parsed, err = parseNextjsClassicLock(ctx, body)
			} else {
				parsed, err = parseNextjsYAMLLock(ctx, body, false)
			}
		default:
			parsed, err = parseNextjsLock(ctx, body)
		}
		digest := sha256.Sum256(body)
		captured := nextjsSASTFile{Path: name, SHA256: hex.EncodeToString(digest[:]), Bytes: len(body)}
		if len(manifest.Files) == 0 {
			manifest.File = captured
			manifest.Format = parsed.Format
			manifest.FormatVersion = parsed.FormatVersion
			manifest.LockVersion = parsed.LockVersion
		}
		manifest.Files = append(manifest.Files, captured)
		manifest.Formats = append(manifest.Formats, parsed.Format)
		manifest.Packages += parsed.Packages
		if err != nil {
			nextjsLockGap(&manifest, err.Error())
		}
		for _, gap := range parsed.Gaps {
			nextjsLockGap(&manifest, gap)
		}
		for _, resolution := range parsed.Resolutions {
			if len(manifest.Resolutions) >= nextjsDepsMaxResolutions {
				nextjsLockGap(&manifest, "Next.js resolutions exceeded the 128-entry limit")
				break
			}
			resolution.Lockfile = name
			manifest.Resolutions = append(manifest.Resolutions, resolution)
		}
	}
	if !found {
		run.Outcome, run.Completeness, run.GapKind = "PARTIAL", "partial", GapEmptyInput
		return finish("skipped", "no root dependency lockfile; resolved Next.js coverage is unavailable")
	}
	if len(manifest.Files) == 0 {
		run.GapKind = GapPrerequisiteFailed
		return finish("failed", "no root dependency lockfile could be safely read")
	}
	if len(manifest.Files) > 1 {
		nextjsLockGap(&manifest, "multiple package-manager lockfiles are present; the active manager is not inferred")
	}
	snapshot, err := loadNextjsAdvisories()
	if err != nil {
		return finish("failed", "bundled Next.js advisory snapshot could not be loaded")
	}
	manifest.AdvisorySnapshot, manifest.AdvisoryRetrieved = nextjsAdvisoriesVersion, snapshot.Retrieved
	advisoryHash := sha256.Sum256(nextjsAdvisoriesJSON)
	manifest.AdvisorySHA256 = hex.EncodeToString(advisoryHash[:])
	dir := filepath.Join(req.ScanDir, "scanner-output", "nextjs-deps")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return finish("failed", "dependency evidence directory could not be created")
	}
	run.SourceManifestPath = filepath.Join(dir, "source-manifest.json")
	run.ArtifactPath = filepath.Join(dir, "findings.jsonl")
	var findings []Finding
	for _, resolution := range manifest.Resolutions {
		if ctx.Err() != nil {
			break
		}
		for _, match := range matchNextjsAdvisories(snapshot, resolution.Version) {
			if len(findings) >= nextjsDepsMaxFindings {
				break
			}
			pointer := "/packages/" + strings.ReplaceAll(strings.ReplaceAll(resolution.Path, "~", "~0"), "/", "~1")
			location := resolution.Lockfile + "#" + (&url.URL{Fragment: pointer}).EscapedFragment()
			if strings.HasPrefix(resolution.Location, "#") {
				location = resolution.Lockfile + "#" + (&url.URL{Fragment: strings.TrimPrefix(resolution.Location, "#")}).EscapedFragment()
			} else if resolution.Location != "" {
				location = resolution.Lockfile + resolution.Location
			}
			advisory := match.Advisory
			cwe := ""
			if len(advisory.CWEs) > 0 {
				cwe = advisory.CWEs[0]
			}
			remediation := "Review and upgrade the locked Next.js dependency using " + advisory.URL
			if match.Range.Patched != "" {
				remediation = "Review the advisory's affected branch and upgrade to a compatible patched release (listed fix: " + match.Range.Patched + "); " + advisory.URL
			}
			findings = append(findings, Finding{SourceID: nextjsSourceID(advisory.GHSAID, location+"\x00"+resolution.Version), Scanner: "nextjs-deps", RuleID: advisory.GHSAID, Title: "Locked Next.js " + resolution.Version + ": " + advisory.Summary, Severity: advisory.Severity, Target: resolution.Lockfile, Endpoint: location, SourceLocation: location, Package: "next", PackageVersion: resolution.Version, CVE: advisory.CVEID, CWE: cwe, Confidence: "lockfile_version_match", Description: advisory.Summary + ". An exact version recorded in the selected dependency lockfile matches the bundled advisory range. Installed packages, deployed versions, backports, feature applicability, and exploitability were not verified.", Evidence: fmt.Sprintf("resolved next@%s; affected range %s; %s; advisory snapshot %s; dev flag=%t; optional flag=%t; registry URLs and lockfile contents not retained", resolution.Version, match.Range.Range, advisory.GHSAID, snapshot.Retrieved, resolution.Dev, resolution.Optional), EvidenceRef: run.SourceManifestPath, Remediation: remediation})
		}
		if len(findings) >= nextjsDepsMaxFindings {
			manifest.Gaps = append(manifest.Gaps, "advisory findings reached the 1000-record limit")
			break
		}
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil || os.WriteFile(run.SourceManifestPath, encoded, 0600) != nil {
		return finish("failed", "dependency manifest could not be persisted")
	}
	output, err := os.OpenFile(run.ArtifactPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return finish("failed", "dependency findings could not be persisted")
	}
	writer := json.NewEncoder(output)
	for _, finding := range findings {
		if err = writer.Encode(finding); err != nil {
			break
		}
	}
	if err == nil {
		err = output.Sync()
	}
	output.Close()
	if err != nil {
		run.ParserOutcome = "FAILED"
		return finish("failed", "dependency findings write did not complete")
	}
	run.ParserOutcome = "SUCCESS"
	if ctx.Err() != nil {
		run.GapKind, run.Outcome, run.Completeness = GapCancelled, "PARTIAL", "partial"
		return finish("cancelled", "dependency checks cancelled with partial evidence")
	}
	if len(manifest.Gaps) > 0 {
		for _, message := range manifest.Gaps {
			run.Limitations = append(run.Limitations, RunLimitation{Kind: "nextjs_dependency_coverage", Reason: message})
		}
		run.Outcome, run.Completeness = "PARTIAL", "partial"
		return finish("completed", "dependency lockfile coverage is incomplete; known version matches retained")
	}
	run.Outcome, run.Completeness = "SUCCESS_NO_FINDINGS", "complete"
	if len(findings) > 0 {
		run.Outcome = "SUCCESS_WITH_FINDINGS"
	}
	return finish("completed", fmt.Sprintf("checked %d locked Next.js resolutions against advisory snapshot %s; %d version matches", len(manifest.Resolutions), snapshot.Retrieved, len(findings)))
}
