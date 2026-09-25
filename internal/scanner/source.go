package scanner

import (
	"context"
	"encoding/json"
	"net/url"
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

func sourceScopePath(scanDir string) string {
	return filepath.Join(scanDir, "scanner-output", "source-scope.json")
}

// redactCloneProvenance strips embedded credentials (e.g. the token in
// "clone:https://user:tok@github.com/a/b.git") from a Source.Provenance value
// with RedactURL. Any other provenance kind (e.g. "provided:filesystem") is
// returned unchanged.
func redactCloneProvenance(prov string) string {
	u, ok := strings.CutPrefix(prov, "clone:")
	if !ok {
		return prov
	}
	return "clone:" + RedactURL(u)
}

// redactedURL replaces a URL that cannot be safely redacted.
const redactedURL = "<redacted URL>"

// RedactURL removes the parts of a URL that can carry secrets: userinfo (e.g.
// the token in https://user:tok@host/...), the query, and the fragment. It
// fails closed: a URL that has a scheme but does not parse, or an opaque one
// that carries an "@", is replaced whole with "<redacted URL>". A string
// without a scheme (e.g. scp-style git@host:path) is returned unchanged, as is
// a URL with nothing to strip, so there is no normalization drift.
func RedactURL(raw string) string {
	if !hasURLScheme(raw) {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return redactedURL
	}
	if u.Opaque != "" && strings.Contains(u.Opaque, "@") {
		return redactedURL
	}
	if u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.RawFragment == "" {
		return raw
	}
	u.User = nil
	u.RawQuery, u.ForceQuery = "", false
	u.Fragment, u.RawFragment = "", ""
	return u.String()
}

// hasURLScheme reports whether raw starts with an RFC 3986 scheme followed by
// ":" (ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )). Checked before parsing
// because net/url rejects scp-style git@host:path, which has no scheme.
func hasURLScheme(raw string) bool {
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z':
		case '0' <= c && c <= '9' || c == '+' || c == '-' || c == '.':
			if i == 0 {
				return false
			}
		case c == ':':
			return i > 0
		default:
			return false
		}
	}
	return false
}

// saveSourceScope records the resolved source scope (including its provenance)
// so the report can label it by origin rather than by the local checkout path.
// The persisted copy has any credentials embedded in a clone URL redacted; the
// caller's Scope (still used to scan) is left unmodified. A write failure is
// non-fatal.
func saveSourceScope(scanDir string, sc Scope) {
	if strings.TrimSpace(scanDir) == "" {
		return
	}
	path := sourceScopePath(scanDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	redacted := sc
	redacted.Source.Provenance = redactCloneProvenance(sc.Source.Provenance)
	data, err := json.MarshalIndent(redacted, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o600)
}

// LoadSourceScope returns the source scope persisted for a scan. ok is false for
// scans that predate it or whose file is unreadable.
func LoadSourceScope(scanDir string) (Scope, bool) {
	data, err := os.ReadFile(sourceScopePath(scanDir))
	if err != nil {
		return Scope{}, false
	}
	var sc Scope
	if err := json.Unmarshal(data, &sc); err != nil || sc.ID == "" {
		return Scope{}, false
	}
	return sc, true
}
