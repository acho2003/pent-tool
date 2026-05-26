// Package safe provides panic-recovery and counter primitives that every
// long-running goroutine, tool invocation, and HTTP handler in xalgorix
// shares. It is the lowest layer of the stability stack: a panic in a
// recovered region produces exactly one structured log line, increments
// the appropriate counter, and (optionally) promotes the panic value to a
// typed error so callers can surface it as a tool result.
//
// The package has no internal dependencies so it can be imported from
// config, sandbox, agent, web, llm, scheduler and every tool package
// without risk of an import cycle.
package safe

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
	"sync/atomic"
)

// Counters is a snapshot of the process-global stability counters
// exposed by the health endpoint. Every field is monotonically
// non-decreasing over the lifetime of the process.
type Counters struct {
	// PanicsRecovered is the number of panics caught by Recover,
	// HTTPMiddleware, or Go since process startup.
	PanicsRecovered uint64
	// PathRejections is the number of write attempts the Path_Policy
	// has rejected since process startup.
	PathRejections uint64
	// WatchdogKills is the number of subprocesses the agent watchdog
	// has terminated since process startup.
	WatchdogKills uint64
	// AdmissionRefusals is the number of scan admission requests the
	// resource governor has refused since process startup.
	AdmissionRefusals uint64
}

// Process-global counters. All access goes through the Inc* helpers
// and Snapshot below, which use atomic operations exclusively.
var (
	panicsRecovered   uint64
	pathRejections    uint64
	watchdogKills     uint64
	admissionRefusals uint64
)

// IncPanic atomically increments the recovered-panic counter.
// Called from Recover, HTTPMiddleware, and Go.
func IncPanic() { atomic.AddUint64(&panicsRecovered, 1) }

// IncPathReject atomically increments the path-rejection counter.
// Called from sandbox.Policy.CheckResolve when a write target falls
// outside the Allow_List.
func IncPathReject() { atomic.AddUint64(&pathRejections, 1) }

// IncWatchdogKill atomically increments the watchdog-kill counter.
// Called from agent.startWatchdog when it terminates a stalled
// subprocess.
func IncWatchdogKill() { atomic.AddUint64(&watchdogKills, 1) }

// IncAdmissionRefusal atomically increments the admission-refusal
// counter. Called from the web server when resources.CanAdmitScan
// declines a scan request.
func IncAdmissionRefusal() { atomic.AddUint64(&admissionRefusals, 1) }

// Snapshot returns a consistent atomic read of every counter. The
// returned struct is a value copy; mutating it does not affect the
// underlying counters.
func Snapshot() Counters {
	return Counters{
		PanicsRecovered:   atomic.LoadUint64(&panicsRecovered),
		PathRejections:    atomic.LoadUint64(&pathRejections),
		WatchdogKills:     atomic.LoadUint64(&watchdogKills),
		AdmissionRefusals: atomic.LoadUint64(&admissionRefusals),
	}
}

// Recover is the canonical defer wrapper for every panic boundary in
// the system. It must be called from a defer statement so that
// recover() returns the panic value:
//
//	defer safe.Recover("agent.tool_exec", scanID)
//
// On panic, Recover:
//
//   - increments PanicsRecovered exactly once;
//   - emits exactly one structured log line of the form
//     "[recover] component=<comp> scan=<id> panic=<v>\n<stack>";
//   - if errp is supplied and *errp == nil at the time of the panic,
//     writes a typed error of the form
//     fmt.Errorf("panic in %s: %v", component, v) into *errp so the
//     calling function can return it as a normal error result.
//
// scanID may be empty for components that do not have a scan context
// (HTTP middleware, scheduler tick, package init goroutines).
//
// errp is variadic for convenience: callers that have no out-error
// pointer to thread can simply omit it. Only the first pointer is
// honored; additional arguments are ignored.
func Recover(component, scanID string, errp ...*error) {
	r := recover()
	if r == nil {
		return
	}
	atomic.AddUint64(&panicsRecovered, 1)
	stack := debug.Stack()
	log.Printf("[recover] component=%s scan=%s panic=%v\n%s", component, scanID, r, stack)
	if len(errp) > 0 && errp[0] != nil && *errp[0] == nil {
		*errp[0] = fmt.Errorf("panic in %s: %v", component, r)
	}
}

// Go runs fn in a new goroutine guarded by Recover. Use it instead of
// a bare `go fn()` for every goroutine that has a long lifetime or
// that may execute user-supplied code paths (heartbeats, watchdogs,
// streaming callbacks, scheduler ticks). component and scanID are
// forwarded to Recover for the structured log line.
//
// Go does not block; it returns immediately after launching the
// goroutine.
func Go(component, scanID string, fn func()) {
	go func() {
		defer Recover(component, scanID)
		fn()
	}()
}

// HTTPMiddleware wraps next in a panic-recovery boundary suitable for
// the top of an http.Handler chain. On panic it increments
// PanicsRecovered, emits the same structured log line as Recover, and
// (if the response has not already been written) responds with HTTP
// 500. The error body is intentionally generic so a panic value
// cannot leak detail to a remote caller.
//
// Use it once, around the root mux:
//
//	srv := &http.Server{Handler: safe.HTTPMiddleware(mux)}
func HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			// Suppress the synthetic panic that net/http raises when a
			// handler aborts a hijacked or already-completed request.
			// Treat every other panic as a real recovery event.
			if errors.Is(toError(rec), http.ErrAbortHandler) {
				panic(rec)
			}
			atomic.AddUint64(&panicsRecovered, 1)
			scanID := r.Header.Get("X-Scan-ID")
			stack := debug.Stack()
			log.Printf("[recover] component=http.handler scan=%s panic=%v\n%s", scanID, rec, stack)
			// Best-effort 500. If the handler already wrote a status
			// code WriteHeader is a no-op (and net/http will log).
			w.WriteHeader(http.StatusInternalServerError)
		}()
		next.ServeHTTP(w, r)
	})
}

// toError converts an arbitrary panic value into an error so callers
// can use errors.Is. Non-error values become nil so the http.ErrAbortHandler
// fast-path in HTTPMiddleware never matches them.
func toError(v any) error {
	if err, ok := v.(error); ok {
		return err
	}
	return nil
}
