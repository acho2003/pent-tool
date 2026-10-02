package scanctx

import (
	"log"
	"sync"

	"github.com/xalgord/xalgorix/v4/internal/resources"
)

// BrowserState provides per-session browser instance tracking,
// replacing the global browser/page/pages in browser.go.
// The actual rod.Browser management stays in the browser package;
// this struct just tracks ownership and session path.
//
// BrowserState also caches the Tool_Lease acquired by the browser tool
// when it launches the first browser context for a scan (Task 10.1).
// The lease is released exactly once via leaseReleaseOnce when the
// state is closed, regardless of whether Close is reached through the
// normal scan teardown path or via panic recovery (Task 10.3 / 13.3).
type BrowserState struct {
	mu          sync.RWMutex
	sessionPath string
	launched    bool
	// The actual browser/page objects are managed by the browser package
	// because they depend on rod types. This state just tracks the
	// session identity for isolation.

	// lease is the Tool_Lease acquired by the browser tool before the
	// first browser context is created for this scan. It is released
	// exactly once via leaseReleaseOnce when Close runs.
	lease            *resources.ToolLease
	leaseReleaseOnce sync.Once
}

// NewBrowserState creates a new browser state.
func NewBrowserState() *BrowserState {
	return &BrowserState{}
}

// SetSessionPath configures where session.json is saved.
func (bs *BrowserState) SetSessionPath(dir string) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.sessionPath = dir
}

// GetSessionPath returns the session path.
func (bs *BrowserState) GetSessionPath() string {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	return bs.sessionPath
}

// SetLaunched marks the browser as launched for this session.
func (bs *BrowserState) SetLaunched(v bool) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.launched = v
}

// IsLaunched returns whether the browser has been launched.
func (bs *BrowserState) IsLaunched() bool {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	return bs.launched
}

// SetLease attaches the Tool_Lease the browser tool acquired before
// launching its first browser context for this scan. It is a no-op
// when a lease is already cached so a second SetLease call cannot
// silently leak an earlier reservation — the caller is expected to
// guard the acquire on Lease() == nil. This is enforced here so the
// invariant holds even if concurrent launchers race.
func (bs *BrowserState) SetLease(l *resources.ToolLease) {
	if bs == nil || l == nil {
		return
	}
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if bs.lease != nil {
		// A lease is already attached. Release the duplicate
		// immediately rather than overwriting and leaking the
		// original. This branch should be unreachable when callers
		// guard the acquire on Lease() == nil, but the defensive
		// release keeps lease conservation intact under races.
		l.Release()
		return
	}
	bs.lease = l
}

// Lease returns the Tool_Lease cached on this BrowserState, or nil
// when none has been acquired. Callers MUST treat the returned value
// as read-only — releasing it directly bypasses the leaseReleaseOnce
// gate and can double-release.
func (bs *BrowserState) Lease() *resources.ToolLease {
	if bs == nil {
		return nil
	}
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	return bs.lease
}

// DropLease clears the cached lease pointer WITHOUT releasing it. The
// browser tool calls this from cleanupBrowserLocked after it has already
// invoked lease.Release() on the per-store copy, so the BrowserState
// cache stays in sync with the actual lease state. The next ensureBrowser
// call will re-acquire because Lease() returns nil.
//
// Coordination with Close (Task 10.3): once DropLease has been called,
// bs.lease is nil and Close's releaseLease() finds nothing to release —
// the sync.Once token is still consumed, but the inner nil-guard skips
// the redundant Release. ToolLease.Release is itself idempotent, so even
// if a future caller bypassed the nil-guard the resource accounting would
// remain correct.
func (bs *BrowserState) DropLease() {
	if bs == nil {
		return
	}
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.lease = nil
}

// releaseLease frees the cached Tool_Lease exactly once. Subsequent
// calls are no-ops thanks to leaseReleaseOnce, so it is safe to invoke
// from both BrowserState.Close and any redundant cleanup path.
func (bs *BrowserState) releaseLease() {
	if bs == nil {
		return
	}
	bs.leaseReleaseOnce.Do(func() {
		bs.mu.Lock()
		l := bs.lease
		bs.lease = nil
		bs.mu.Unlock()
		if l != nil {
			l.Release()
		}
	})
}

// Close marks the browser state as closed and releases the cached
// Tool_Lease exactly once (Task 10.3 / 13.3).
//
// The actual browser cleanup (rod.Browser MustClose, launcher Kill) is
// handled by the browser package's cleanupBrowserLocked, which runs on
// eager teardown paths (CleanupContext, BrowserClose tool call, scan
// timeout). That path calls bs.DropLease() after releasing the per-store
// copy of the lease, so by the time Close runs bs.lease is typically nil
// and releaseLease's sync.Once finds nothing to release.
//
// On the cold path — Scan_Context.Close reached without any prior browser
// cleanup — bs.lease is still set, and releaseLease performs the only
// release. The sync.Once gate guarantees the lease is freed exactly once
// regardless of which path wins; ToolLease.Release's own released flag is
// a defense-in-depth backstop.
//
// releaseLease must be invoked OUTSIDE the bs.mu critical section because
// it takes bs.mu itself to clear the cached pointer.
func (bs *BrowserState) Close() {
	bs.mu.Lock()
	bs.launched = false
	bs.sessionPath = ""
	bs.mu.Unlock()
	bs.releaseLease()
	log.Printf("[browserstate] Closed browser state")
}
