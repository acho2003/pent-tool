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

const nextjsDepsVersion = "nextjs-deps-v1"
const nextjsDepsMaxBytes = 4 << 20
const nextjsDepsMaxPackages = 20000
const nextjsDepsMaxResolutions = 128
const nextjsDepsMaxVersionLength = 256
const nextjsDepsMaxFindings = 1000

var nextjsExactLockVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

type nextjsDepsRunner struct{}

func (nextjsDepsRunner) Name() string { return "nextjs-deps" }
func (nextjsDepsRunner) Descriptor() Descriptor {
	return Descriptor{Name: "nextjs-deps", Summary: "Offline resolved Next.js npm lockfile advisory matches", Phase: PhaseSAST, Applies: appliesToSource, Weight: WeightLight}
}

type nextjsLockedResolution struct {
	Path     string `json:"path"`
	Version  string `json:"version"`
	Dev      bool   `json:"dev,omitempty"`
	Optional bool   `json:"optional,omitempty"`
}
type nextjsDepsManifest struct {
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
	result := nextjsDepsManifest{Schema: 1, Catalog: nextjsDepsVersion, Resolutions: []nextjsLockedResolution{}}
	if len(body) > nextjsDepsMaxBytes {
		return result, fmt.Errorf("npm lockfile exceeds the 4 MiB limit")
	}
	var lock struct {
		Version  int                        `json:"lockfileVersion"`
		Packages map[string]json.RawMessage `json:"packages"`
	}
	if json.Unmarshal(body, &lock) != nil {
		return result, fmt.Errorf("npm lockfile JSON could not be decoded")
	}
	result.LockVersion = lock.Version
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
		result.Resolutions = append(result.Resolutions, nextjsLockedResolution{key, pkg.Version, pkg.Dev, pkg.Optional})
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
	var selected string
	var before os.FileInfo
	for _, name := range []string{"npm-shrinkwrap.json", "package-lock.json"} {
		info, err := root.Lstat(name)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return finish("failed", "npm lockfile metadata is unavailable")
		}
		if !info.Mode().IsRegular() {
			return finish("failed", "selected npm lockfile must be a regular file without symlinks")
		}
		selected, before = name, info
		break
	}
	if selected == "" {
		run.Outcome, run.Completeness, run.GapKind = "PARTIAL", "partial", GapEmptyInput
		return finish("skipped", "no root npm lockfile; resolved Next.js dependency coverage is unavailable")
	}
	if before.Size() > nextjsDepsMaxBytes {
		run.GapKind = GapBudgetExhausted
		return finish("failed", "npm lockfile exceeds the 4 MiB limit")
	}
	file, err := root.Open(selected)
	if err != nil {
		return finish("failed", "selected npm lockfile could not be opened")
	}
	body, readErr := io.ReadAll(io.LimitReader(file, nextjsDepsMaxBytes+1))
	after, statErr := file.Stat()
	file.Close()
	if readErr != nil || statErr != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return finish("failed", "npm lockfile could not be read as a stable regular file")
	}
	if len(body) > nextjsDepsMaxBytes {
		run.GapKind = GapBudgetExhausted
		return finish("failed", "npm lockfile exceeds the 4 MiB limit")
	}
	manifest, parseErr := parseNextjsLock(ctx, body)
	if parseErr != nil {
		manifest.Gaps = append(manifest.Gaps, parseErr.Error())
	}
	snapshot, err := loadNextjsAdvisories()
	if err != nil {
		return finish("failed", "bundled Next.js advisory snapshot could not be loaded")
	}
	manifest.AdvisorySnapshot, manifest.AdvisoryRetrieved = nextjsAdvisoriesVersion, snapshot.Retrieved
	advisoryHash := sha256.Sum256(nextjsAdvisoriesJSON)
	manifest.AdvisorySHA256 = hex.EncodeToString(advisoryHash[:])
	digest := sha256.Sum256(body)
	manifest.File = nextjsSASTFile{Path: selected, SHA256: hex.EncodeToString(digest[:]), Bytes: len(body)}
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
			location := selected + "#" + (&url.URL{Fragment: pointer}).EscapedFragment()
			advisory := match.Advisory
			cwe := ""
			if len(advisory.CWEs) > 0 {
				cwe = advisory.CWEs[0]
			}
			remediation := "Review and upgrade the locked Next.js dependency using " + advisory.URL
			if match.Range.Patched != "" {
				remediation = "Review the advisory's affected branch and upgrade to a compatible patched release (listed fix: " + match.Range.Patched + "); " + advisory.URL
			}
			findings = append(findings, Finding{SourceID: nextjsSourceID(advisory.GHSAID, location+"\x00"+resolution.Version), Scanner: "nextjs-deps", RuleID: advisory.GHSAID, Title: "Locked Next.js " + resolution.Version + ": " + advisory.Summary, Severity: advisory.Severity, Target: selected, Endpoint: location, SourceLocation: location, Package: "next", PackageVersion: resolution.Version, CVE: advisory.CVEID, CWE: cwe, Confidence: "lockfile_version_match", Description: advisory.Summary + ". An exact version recorded in the selected npm lockfile matches the bundled advisory range. Installed packages, deployed versions, backports, feature applicability, and exploitability were not verified.", Evidence: fmt.Sprintf("resolved next@%s; affected range %s; %s; advisory snapshot %s; dev flag=%t; optional flag=%t; registry URLs and lockfile contents not retained", resolution.Version, match.Range.Range, advisory.GHSAID, snapshot.Retrieved, resolution.Dev, resolution.Optional), EvidenceRef: run.SourceManifestPath, Remediation: remediation})
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
		return finish("completed", "npm lockfile coverage is incomplete; known version matches retained")
	}
	run.Outcome, run.Completeness = "SUCCESS_NO_FINDINGS", "complete"
	if len(findings) > 0 {
		run.Outcome = "SUCCESS_WITH_FINDINGS"
	}
	return finish("completed", fmt.Sprintf("checked %d locked Next.js resolutions against advisory snapshot %s; %d version matches", len(manifest.Resolutions), snapshot.Retrieved, len(findings)))
}
