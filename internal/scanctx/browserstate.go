package scanctx

import (
	"log"
	"sync"
)

// BrowserState provides per-session browser instance tracking,
// replacing the global browser/page/pages in browser.go.
// The actual rod.Browser management stays in the browser package;
// this struct just tracks ownership and session path.
type BrowserState struct {
	mu          sync.RWMutex
	sessionPath string
	launched    bool
	// The actual browser/page objects are managed by the browser package
	// because they depend on rod types. This state just tracks the
	// session identity for isolation.
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

// Close marks the browser state as closed.
// The actual browser cleanup is handled by the browser package.
func (bs *BrowserState) Close() {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.launched = false
	bs.sessionPath = ""
	log.Printf("[browserstate] Closed browser state")
}
