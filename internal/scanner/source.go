package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// sourceScopeID is the stable id of the single per-scan source scope.
const sourceScopeID = "source:main"

// sourceCheckoutDir is where a cloned repository lands under the scan dir.
func sourceCheckoutDir(scanDir string) string {
	return filepath.Join(scanDir, "source", "checkout")
}

// isGitURL reports whether target is a git repository URL we should clone.
// Kept conservative so ordinary web targets are never mistaken for repos.
func isGitURL(target string) bool {
	t := strings.TrimSpace(target)
	if strings.HasPrefix(t, "git@") || strings.HasPrefix(t, "git://") {
		return true
	}
	return strings.HasSuffix(t, ".git")
}

// gitClone shallow-clones url into dir. The caller ensures dir does not already
// hold a checkout. Bounded by a fixed timeout derived from ctx.
func gitClone(ctx context.Context, url, dir string) error {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if err := os.MkdirAll(filepath.Dir(dir), 0o750); err != nil {
		return err
	}
	cmd := exec.CommandContext(cctx, "git", "clone", "--depth", "1", url, dir)
	return cmd.Run()
}

// resolveSourceScope returns the single source scope for a scan. Its Target is a
// local source path when one is resolvable — a provided filesystem dir, a
// provided repository URL, or a git-URL target (cloned) — and empty otherwise,
// in which case every SAST runner records not_applicable on it.
func resolveSourceScope(ctx context.Context, req Request, cfg Config, emit EmitFunc) Scope {
	sc := Scope{ID: sourceScopeID, Kind: ScopeSource}

	// 1. Provided local filesystem directory.
	if strings.EqualFold(req.Artifact.Kind, "filesystem") {
		if ref := strings.TrimSpace(req.Artifact.Ref); ref != "" {
			if fi, err := os.Stat(ref); err == nil && fi.IsDir() {
				sc.Target = ref
				sc.Source = SourceRef{Path: ref, Provenance: "provided:filesystem"}
				return sc
			}
		}
	}

	// 2. Repository URL (from artifact ref or a git-URL target) -> clone.
	url := ""
	if strings.EqualFold(req.Artifact.Kind, "repository") {
		url = strings.TrimSpace(req.Artifact.Ref)
	} else if isGitURL(req.Target) {
		url = strings.TrimSpace(req.Target)
	}
	if url != "" {
		dir := sourceCheckoutDir(req.ScanDir)
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			sc.Target = dir // resume: reuse existing checkout
			sc.Source = SourceRef{Path: dir, Provenance: "clone:" + url}
			return sc
		}
		if err := gitClone(ctx, url, dir); err == nil {
			sc.Target = dir
			sc.Source = SourceRef{Path: dir, Provenance: "clone:" + url}
			return sc
		}
	}

	// 3. No source resolved: Target stays empty -> SAST tools not_applicable.
	return sc
}
