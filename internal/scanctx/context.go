// Package scanctx provides per-scan-session state isolation.
// Each ScanContext encapsulates the mutable state (vulnerabilities, notes,
// terminal processes, browser instance) that was previously stored in
// package-level globals. This allows multiple concurrent scan sessions
// without data corruption.
package scanctx

import (
	"context"
	"fmt"
	"log"
	"sync"
)

// ScanContext holds all mutable state for a single scan session.
// Create one per scan instance via New(), and thread it through
// the tool registry so tools read/write their own session's state.
type ScanContext struct {
	ID      string
	ScanDir string

	Vulns    *VulnStore
	Notes    *NoteStore
	Terminal *TerminalState
	Browser  *BrowserState

	// ctx/cancel for the scan's lifecycle
	Ctx    context.Context
	Cancel context.CancelFunc
}

// New creates a fresh ScanContext for an isolated scan session.
func New(id, scanDir string) *ScanContext {
	ctx, cancel := context.WithCancel(context.Background())
	return &ScanContext{
		ID:       id,
		ScanDir:  scanDir,
		Vulns:    NewVulnStore(),
		Notes:    NewNoteStore(),
		Terminal: NewTerminalState(),
		Browser:  NewBrowserState(),
		Ctx:      ctx,
		Cancel:   cancel,
	}
}

// Close tears down all resources owned by this scan context.
// Safe to call multiple times.
func (sc *ScanContext) Close() {
	if sc.Cancel != nil {
		sc.Cancel()
	}
	if sc.Terminal != nil {
		sc.Terminal.KillAll()
	}
	if sc.Browser != nil {
		sc.Browser.Close()
	}
}

// ──────────────────────────────────────────────────────────
// Active context registry — allows tool packages to access
// their session's ScanContext without changing Execute signatures.
// ──────────────────────────────────────────────────────────

var (
	activeMu   sync.RWMutex
	activeCtxs = make(map[string]*ScanContext) // instanceID → ScanContext
	defaultCtx *ScanContext                    // fallback for CLI mode (single scan)
)

// Activate registers a ScanContext as the active context for its ID.
// Also sets it as the default if no default exists (CLI mode compat).
func Activate(sc *ScanContext) {
	activeMu.Lock()
	defer activeMu.Unlock()
	activeCtxs[sc.ID] = sc
	if defaultCtx == nil {
		defaultCtx = sc
	}
}

// Deactivate removes a ScanContext from the active registry.
func Deactivate(id string) {
	activeMu.Lock()
	defer activeMu.Unlock()
	delete(activeCtxs, id)
	if defaultCtx != nil && defaultCtx.ID == id {
		defaultCtx = nil
		// Promote any remaining context as default
		for _, sc := range activeCtxs {
			defaultCtx = sc
			break
		}
	}
}

// Get returns the ScanContext for a given instance ID.
func Get(id string) *ScanContext {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return activeCtxs[id]
}

// Default returns the default (CLI-mode) ScanContext.
// If no context is active, creates and returns a temporary one.
func Default() *ScanContext {
	activeMu.RLock()
	if defaultCtx != nil {
		defer activeMu.RUnlock()
		return defaultCtx
	}
	activeMu.RUnlock()

	// Create a fallback for CLI mode
	activeMu.Lock()
	defer activeMu.Unlock()
	if defaultCtx == nil {
		defaultCtx = New("cli-default", "")
		activeCtxs[defaultCtx.ID] = defaultCtx
		log.Printf("[scanctx] Created fallback CLI context")
	}
	return defaultCtx
}

// ActiveCount returns the number of active scan contexts.
func ActiveCount() int {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return len(activeCtxs)
}



// ──────────────────────────────────────────────────────────
// Summary / debug
// ──────────────────────────────────────────────────────────

// Summary returns a human-readable summary of all active scan contexts.
func Summary() string {
	activeMu.RLock()
	defer activeMu.RUnlock()
	if len(activeCtxs) == 0 {
		return "No active scan contexts"
	}
	s := fmt.Sprintf("%d active scan context(s):\n", len(activeCtxs))
	for id, sc := range activeCtxs {
		vulnCount := sc.Vulns.Count()
		noteCount := sc.Notes.Count()
		procCount := sc.Terminal.ActiveProcessCount()
		s += fmt.Sprintf("  [%s] dir=%s vulns=%d notes=%d procs=%d\n",
			id, sc.ScanDir, vulnCount, noteCount, procCount)
	}
	return s
}

// ResetAll tears down all active contexts. Used for testing.
func ResetAll() {
	activeMu.Lock()
	defer activeMu.Unlock()
	for _, sc := range activeCtxs {
		sc.Close()
	}
	activeCtxs = make(map[string]*ScanContext)
	defaultCtx = nil
}

