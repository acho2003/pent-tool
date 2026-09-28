// Package web — small JSON helpers shared by the /api handlers.
package web

import (
	"encoding/json"
	"net/http"
)

// jsonWriteBodyLimit caps the request body size every JSON write
// handler will read. 1 MiB is generous — the largest legitimate
// payload is a profile create with embedded credentials. Capping
// protects the dashboard from a misbehaving (or malicious) client
// sending a multi-gigabyte body that would otherwise be buffered
// into memory.
const jsonWriteBodyLimit = 1 << 20 // 1 MiB

// limitJSONBody installs an http.MaxBytesReader on r.Body so any
// downstream json.Decoder fails cleanly with an error referencing
// the limit instead of buffering arbitrarily large payloads. The
// MaxBytesReader's Close method is no-op-safe so existing
// defer r.Body.Close() lines continue to work.
func limitJSONBody(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, jsonWriteBodyLimit)
}

// writeJSONStatus is a small helper that sets the JSON content
// type, writes the status code, and JSON-encodes body.
//
// Errors from json.Encode are intentionally not surfaced — at this
// point we have already committed the status code, and the only
// realistic failure is a closed connection which the caller already
// sees through r.Context().Err().
func writeJSONStatus(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
