package sandbox

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/safe"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

// Policy is the immutable Allow_List boundary check used by every
// Filesystem_Tool. Construct it once via Default() (process-global lazy
// singleton) for normal callers; tests inject their own roots via New.
//
// The zero value is not usable — always go through New or Default.
type Policy struct {
	// roots holds canonical absolute prefixes. Each entry is the result
	// of filepath.Abs + filepath.Clean, with empty/duplicate entries
	// dropped, sorted longest-first so the prefix match is deterministic
	// when one root is nested inside another (e.g. /tmp/xalgorix vs /tmp).
	roots []string
}

// New constructs a Policy from the supplied Allow_List roots. Each
// root is canonicalized via filepath.Abs + filepath.Clean. Empty
// entries and duplicates (after canonicalization) are dropped, and
// the resulting slice is sorted by length descending so deeper roots
// match before their parents.
//
// New never touches the filesystem; missing roots are accepted and
// will simply never match. Use Default() in production code.
func New(roots ...string) *Policy {
	seen := make(map[string]struct{}, len(roots))
	canonical := make([]string, 0, len(roots))
	for _, raw := range roots {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		abs, err := filepath.Abs(raw)
		if err != nil {
			// An Abs failure is almost impossible (it only fails when
			// os.Getwd fails), but if it does happen we skip the entry
			// rather than poisoning the policy with a relative root.
			continue
		}
		clean := filepath.Clean(abs)
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		canonical = append(canonical, clean)
	}
	sort.SliceStable(canonical, func(i, j int) bool {
		return len(canonical[i]) > len(canonical[j])
	})
	return &Policy{roots: canonical}
}

var (
	defaultPolicy *Policy
	defaultOnce   sync.Once
)

// Default returns the process-global Policy assembled from the active
// configuration. The Allow_List is composed of:
//
//   - the active Data_Dir (cfg.Workspace, which mirrors Data_Dir after
//     Task 3.1 lands; before then it is the legacy $CWD-derived
//     workspace),
//   - cfg.HomeDir (~/.xalgorix),
//   - "/tmp".
//
// The first call must follow config.Get(); subsequent calls return the
// memoized instance. Tests that need a different Allow_List should
// construct their own Policy via New.
func Default() *Policy {
	defaultOnce.Do(func() {
		cfg := config.Get()
		// cfg.Workspace is the active Data_Dir (Task 3.1 reassigns
		// the field; before that landed it points at the legacy
		// $CWD-derived workspace). Either way it is the right
		// resolution root for Filesystem_Tool writes.
		defaultPolicy = New(cfg.Workspace, cfg.HomeDir, "/tmp")
	})
	return defaultPolicy
}

// Roots returns a defensive copy of the Allow_List roots used by this
// Policy. The slice is safe to mutate; modifications do not affect the
// Policy's internal state. The order is the same longest-first order
// used by Check.
func (p *Policy) Roots() []string {
	if p == nil {
		return nil
	}
	out := make([]string, len(p.roots))
	copy(out, p.roots)
	return out
}

// Resolve turns (sc, raw) into an absolute, canonical path WITHOUT
// performing the Allow_List check. Use Check or CheckResolve when the
// caller cares about boundary enforcement.
//
// Relative paths resolve under sc.ScanDir when sc is non-nil and its
// ScanDir is non-empty, otherwise under cfg.Workspace (which mirrors
// Workspace_Root / Data_Dir). Absolute inputs are honored as-is.
//
// Canonicalization rule (R5.2):
//
//   - if the joined path exists, filepath.EvalSymlinks chases the chain;
//   - if it does not, filepath.EvalSymlinks is applied to the parent
//     and joined with filepath.Base of the input so a symlinked
//     directory containing a not-yet-created leaf is honored;
//   - if EvalSymlinks fails for an unexpected reason (permissions,
//     I/O error), Resolve falls back to filepath.Clean(filepath.Abs(...)).
func (p *Policy) Resolve(sc *scanctx.ScanContext, raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("path policy: empty path")
	}

	base := resolutionBase(sc)

	var joined string
	if filepath.IsAbs(raw) {
		joined = raw
	} else {
		if base == "" {
			// No resolution root available — fall back to absolute-
			// from-CWD so we still produce a deterministic path.
			abs, err := filepath.Abs(raw)
			if err != nil {
				return "", fmt.Errorf("path policy: abs(%s): %w", raw, err)
			}
			joined = abs
		} else {
			joined = filepath.Join(base, raw)
		}
	}

	canonical, err := canonicalize(joined)
	if err != nil {
		return "", err
	}
	return canonical, nil
}

// Check applies the Allow_List boundary check to a canonical path.
// The input is canonicalized again (filepath.Abs + filepath.Clean) so
// callers that already have an absolute path (e.g. from Resolve) get
// idempotent behavior. The function is side-effect-free: it never
// touches the filesystem and never modifies counters or logs.
//
// Returns nil when canonical equals an Allow_List root or has that
// root + filepath.Separator as a prefix. Returns *PathRejectError
// otherwise; the returned error has Path and Roots populated, but the
// Tool and ScanCtxID fields remain empty — CheckResolve fills those.
func (p *Policy) Check(canonical string) error {
	abs, err := filepath.Abs(canonical)
	if err != nil {
		return fmt.Errorf("path policy: abs(%s): %w", canonical, err)
	}
	abs = filepath.Clean(abs)
	for _, root := range p.roots {
		if abs == root {
			return nil
		}
		if strings.HasPrefix(abs, root+string(filepath.Separator)) {
			return nil
		}
	}
	return &PathRejectError{
		Path:  abs,
		Roots: append([]string(nil), p.roots...),
	}
}

// CheckResolve is the common one-shot path used by Filesystem_Tools:
// Resolve + Check + (on reject) safe.IncPathReject + structured WARN
// log + populated *PathRejectError.
//
// toolName is the namespaced operation (e.g. "fileedit.replace",
// "python_action") used in both the log line and the returned error.
// On success the returned string is the canonical, allow-list-cleared
// path the caller can hand directly to os.Open / os.MkdirAll / etc.
func (p *Policy) CheckResolve(sc *scanctx.ScanContext, toolName, raw string) (string, error) {
	canonical, err := p.Resolve(sc, raw)
	if err != nil {
		return "", err
	}
	if err := p.Check(canonical); err != nil {
		// Promote into a fully-populated PathRejectError, count it,
		// and emit the WARN log line described by R5.6 / R9.1.
		var rej *PathRejectError
		if pre, ok := err.(*PathRejectError); ok {
			rej = pre
		} else {
			rej = &PathRejectError{Path: canonical, Roots: p.Roots()}
		}
		rej.Tool = toolName
		rej.ScanCtxID = scanContextID(sc)

		safe.IncPathReject()
		log.Printf("[path-policy] reject tool=%s scan=%s path=%s roots=%v",
			rej.Tool, rej.ScanCtxID, rej.Path, p.roots)

		return "", rej
	}
	return canonical, nil
}

// resolutionBase picks the directory relative paths resolve against.
// Prefers the active scan context's ScanDir (so per-scan artefacts
// stay isolated), falling back to cfg.Workspace which mirrors
// Workspace_Root / Data_Dir.
func resolutionBase(sc *scanctx.ScanContext) string {
	if sc != nil && strings.TrimSpace(sc.ScanDir) != "" {
		return sc.ScanDir
	}
	cfg := config.Get()
	if cfg != nil {
		return cfg.Workspace
	}
	return ""
}

// scanContextID returns sc.ID when available, "" otherwise. Kept as a
// helper so call sites stay readable.
func scanContextID(sc *scanctx.ScanContext) string {
	if sc == nil {
		return ""
	}
	return sc.ID
}

// canonicalize implements the R5.2 canonicalization rule.
func canonicalize(path string) (string, error) {
	abs, absErr := filepath.Abs(path)
	if absErr != nil {
		return "", fmt.Errorf("path policy: abs(%s): %w", path, absErr)
	}
	abs = filepath.Clean(abs)

	if _, statErr := os.Lstat(abs); statErr == nil {
		// Path exists — chase the symlink chain end-to-end.
		if resolved, err := filepath.EvalSymlinks(abs); err == nil {
			return filepath.Clean(resolved), nil
		}
		// EvalSymlinks failed for a reason other than non-existence
		// (permissions, broken symlink, I/O). Fall back to the
		// abs+clean form so the boundary check still runs.
		return abs, nil
	}

	// Path does not exist. EvalSymlink the parent so a symlinked
	// directory containing a not-yet-created leaf is honored.
	parent := filepath.Dir(abs)
	leaf := filepath.Base(abs)
	if resolved, err := filepath.EvalSymlinks(parent); err == nil {
		return filepath.Clean(filepath.Join(resolved, leaf)), nil
	}
	return abs, nil
}
