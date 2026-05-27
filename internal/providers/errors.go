// Package providers — error sentinels retained from v4.4.21 for
// backwards compatibility with internal/auth.Store error wrapping.
//
// The catalog is now read-only, so the mutation-related sentinels
// (ErrIDExists, ErrIDInvalid, ErrIDMismatch, ErrCatalogCorrupt) are
// gone. ErrNotFound stays so internal/auth Store.Put can keep its
// "unknown provider" envelope, and ErrUpstream stays as a
// convenient typed error for any future remote-fetch use cases
// (today it is unused).
package providers

import "errors"

// ErrNotFound is returned by Service.Get callers when the
// requested id is not in the compiled-in catalog. Service.Get
// itself signals this case via its (Entry, false, nil) tuple; the
// sentinel is exported so other packages can errors.Is on the
// "not found" condition when they wrap the lookup.
var ErrNotFound = errors.New("provider not found")

// ErrUpstream preserves the v4.4.21 typed error shape for any
// future remote-fetch use case. Today it is unused — kept so
// downstream packages that errors.As against it continue to
// compile cleanly. Safe to delete in a future release if no
// callers materialize.
type ErrUpstream struct {
	StatusCode int
	Body       string
}

// Error implements the error interface.
func (e ErrUpstream) Error() string {
	return "upstream error"
}
