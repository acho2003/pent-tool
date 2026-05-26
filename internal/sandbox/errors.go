// Package sandbox owns the Path_Policy boundary check, Allow_List
// composition, and structured rejection error used by every
// Filesystem_Tool in xalgorix. See policy.go for the core type and
// API; this file defines the typed error shape.
package sandbox

import (
	"errors"
	"fmt"
)

// ErrPathReject is the sentinel returned (wrapped inside *PathRejectError)
// whenever a Filesystem_Tool attempts to write outside the Allow_List.
// Callers can match it with errors.Is:
//
//	if errors.Is(err, sandbox.ErrPathReject) { ... }
var ErrPathReject = errors.New("path-policy reject")

// PathRejectError is returned by Policy.Check and Policy.CheckResolve
// whenever the canonical form of a target path falls outside every
// configured Allow_List root. It carries enough context for both the
// agent log line (R5.6) and the structured tool result message (R5.3).
//
// Tool is the namespaced operation name supplied by the caller, e.g.
// "fileedit.replace", "python_action", or "browser". ScanCtxID is the
// owning ScanContext.ID, or "" when no scan context is active.
//
// Roots is a snapshot of the Allow_List roots active at the time of
// the decision; callers MUST treat the slice as read-only.
type PathRejectError struct {
	Tool      string
	Path      string
	Roots     []string
	ScanCtxID string
}

// Error formats the rejection in the canonical shape required by
// Requirement 5.3. The format is intentionally stable so log greps and
// tests can match it deterministically.
func (e *PathRejectError) Error() string {
	return fmt.Sprintf("path-policy reject: tool=%s scan=%s path=%s allowed=%v",
		e.Tool, e.ScanCtxID, e.Path, e.Roots)
}

// Is enables errors.Is(err, sandbox.ErrPathReject) so callers can
// special-case path rejects without unwrapping the typed error.
func (e *PathRejectError) Is(target error) bool {
	return target == ErrPathReject
}
