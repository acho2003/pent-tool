// Package iolimit provides a bounded byte buffer used to capture child-process
// stdout/stderr without allowing a runaway process to exhaust memory.
//
// The buffer satisfies io.Writer, accepts every Write call (so callers never
// see ErrShortWrite from os/exec), and silently drops bytes once a configured
// byte ceiling has been reached. Callers can inspect Truncated() afterwards to
// decide whether to surface a "(output truncated)" hint to the user.
//
// The package intentionally has no internal dependencies beyond the standard
// library so it can be reused by any subprocess-running tool (python, terminal,
// future shell variants).
package iolimit

import (
	"bytes"
	"io"
	"sync"
)

// Default per-stream byte ceilings used by NewLimited when callers pass
// non-positive sizes. These match the bounds called out in R2.4/R2.5 of the
// stability spec: 1 MiB for stdout, 512 KiB for stderr.
const (
	DefaultStdoutLimit = 1 << 20 // 1 MiB
	DefaultStderrLimit = 1 << 19 // 512 KiB
)

// LimitedBuffer is a thread-safe in-memory byte buffer that stops growing once
// its configured limit is reached. Writes past the limit are accepted (their
// length is reported as written) but the bytes are discarded and Truncated()
// will subsequently return true.
//
// The zero value is not usable; obtain a *LimitedBuffer via New or NewLimited.
type LimitedBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	limit     int
	truncated bool
}

// Compile-time guarantee that *LimitedBuffer implements io.Writer.
var _ io.Writer = (*LimitedBuffer)(nil)

// New returns a *LimitedBuffer whose capacity is capped at max bytes. A max of
// zero or less yields a buffer that drops every byte and is always Truncated()
// after the first non-empty write.
func New(max int) *LimitedBuffer {
	return &LimitedBuffer{limit: max}
}

// NewLimited is a convenience factory that returns a (stdout, stderr) pair
// pre-sized for capturing child-process output. Non-positive sizes fall back
// to DefaultStdoutLimit / DefaultStderrLimit respectively.
func NewLimited(stdoutMax, stderrMax int) (stdout, stderr *LimitedBuffer) {
	if stdoutMax <= 0 {
		stdoutMax = DefaultStdoutLimit
	}
	if stderrMax <= 0 {
		stderrMax = DefaultStderrLimit
	}
	return New(stdoutMax), New(stderrMax)
}

// Write appends p to the buffer up to the configured limit. Bytes that would
// overflow the limit are silently discarded and the truncation flag is set.
// Write always reports len(p) as the number of bytes "written" so that
// io.Copy and friends do not error out.
//
// Write is safe to call concurrently with other Write/Bytes/Len/Truncated
// calls on the same buffer.
func (b *LimitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.limit <= 0 {
		if len(p) > 0 {
			b.truncated = true
		}
		return len(p), nil
	}

	current := b.buf.Len()
	if current >= b.limit {
		if len(p) > 0 {
			b.truncated = true
		}
		return len(p), nil
	}

	remaining := b.limit - current
	if len(p) > remaining {
		// Fill exactly up to the limit and mark truncated. After this write
		// b.buf.Len() == b.limit, so the flag flips at the exact limit byte.
		_, _ = b.buf.Write(p[:remaining])
		b.truncated = true
		return len(p), nil
	}

	_, _ = b.buf.Write(p)
	return len(p), nil
}

// Bytes returns a defensive copy of the bytes captured so far. Mutating the
// returned slice does not affect the buffer.
func (b *LimitedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()

	src := b.buf.Bytes()
	if len(src) == 0 {
		return nil
	}
	out := make([]byte, len(src))
	copy(out, src)
	return out
}

// String returns the captured bytes as a string. It is primarily intended for
// tests and structured logging.
func (b *LimitedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Len returns the current number of captured bytes.
func (b *LimitedBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

// Limit returns the configured byte ceiling.
func (b *LimitedBuffer) Limit() int {
	// limit is set at construction time and never mutated; no lock needed,
	// but we take it anyway to keep the API consistent and avoid surprising
	// future maintainers who add reconfiguration.
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.limit
}

// Truncated reports whether at least one byte has been dropped because of the
// configured limit.
func (b *LimitedBuffer) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}
