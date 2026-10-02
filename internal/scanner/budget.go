package scanner

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/ratelimit"
)

// ErrBudgetExhausted is returned by AssessmentBudget.Wait once the
// assessment-wide deadline has passed or cannot be met.
var ErrBudgetExhausted = errors.New("assessment budget exhausted")

// NoBudgetDeadline is what Remaining reports for a budget without a deadline.
const NoBudgetDeadline = time.Duration(math.MaxInt64)

// budgetLimiterKey is the single limiter key: the budget throttles the whole
// assessment, not each host, so scanners and targets cannot multiply the rate.
const budgetLimiterKey = "assessment"

// AssessmentBudget is the one rate, endpoint and time budget of an assessment.
// It is created once per assessment and shared (via Config.Budget) by every
// scanner, target, discovery step, retry and validation, so the profile's
// RateRPS, MaxEndpoints and Budget bound the assessment as a whole rather than
// each scanner. All methods are concurrency-safe and nil-safe: a nil budget
// never throttles, caps or expires.
type AssessmentBudget struct {
	limiter      *ratelimit.Limiter
	maxEndpoints int
	deadline     time.Time

	mu        sync.Mutex
	endpoints map[string]struct{}
	refused   bool
}

// NewAssessmentBudget returns a budget allowing rateRPS requests per second
// across all callers (burst 1), at most maxEndpoints unique endpoints, and
// ending budget after now. A non-positive value disables that dimension.
func NewAssessmentBudget(rateRPS, maxEndpoints int, budget time.Duration) *AssessmentBudget {
	b := &AssessmentBudget{
		limiter:      ratelimit.New(float64(rateRPS), 1),
		maxEndpoints: maxEndpoints,
		endpoints:    map[string]struct{}{},
	}
	if budget > 0 {
		b.deadline = time.Now().Add(budget)
	}
	return b
}

// Wait blocks until the shared limiter grants one request. It returns ctx's
// error when the caller cancels, and ErrBudgetExhausted when the global
// deadline has passed or would pass before a token is available.
func (b *AssessmentBudget) Wait(ctx context.Context) error {
	if b == nil {
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	waitCtx := ctx
	if !b.deadline.IsZero() {
		if !time.Now().Before(b.deadline) {
			return ErrBudgetExhausted
		}
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithDeadline(ctx, b.deadline)
		defer cancel()
	}
	err := b.limiter.WaitCtx(waitCtx, budgetLimiterKey)
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if !b.deadline.IsZero() {
		return fmt.Errorf("%w: %v", ErrBudgetExhausted, err)
	}
	return err
}

// ReserveEndpoints grants endpoints against the assessment-wide unique cap and
// returns the granted subset of ids in input order, deduplicated and without
// blanks. An id already reserved (by any scanner or target) is granted again
// at no cost; a new id is granted only while the cap has room. Refusing any id
// marks the budget exhausted.
func (b *AssessmentBudget) ReserveEndpoints(ids []string) []string {
	out := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	if b != nil {
		b.mu.Lock()
		defer b.mu.Unlock()
	}
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		if b != nil {
			if _, ok := b.endpoints[id]; !ok {
				if b.maxEndpoints > 0 && len(b.endpoints) >= b.maxEndpoints {
					b.refused = true
					continue
				}
				b.endpoints[id] = struct{}{}
			}
		}
		out = append(out, id)
	}
	return out
}

// Deadline returns the global deadline, like context.Context.Deadline.
func (b *AssessmentBudget) Deadline() (time.Time, bool) {
	if b == nil || b.deadline.IsZero() {
		return time.Time{}, false
	}
	return b.deadline, true
}

// Remaining returns the time left before the global deadline: zero once it has
// passed, NoBudgetDeadline when the budget has none.
func (b *AssessmentBudget) Remaining() time.Duration {
	if b == nil || b.deadline.IsZero() {
		return NoBudgetDeadline
	}
	return max(time.Until(b.deadline), 0)
}

// Exhausted reports whether the budget can no longer deliver planned coverage:
// the deadline has passed or an endpoint was refused by the unique cap. The
// GapKind is GapBudgetExhausted when exhausted and empty otherwise.
func (b *AssessmentBudget) Exhausted() (bool, GapKind) {
	if b == nil {
		return false, ""
	}
	if !b.deadline.IsZero() && !time.Now().Before(b.deadline) {
		return true, GapBudgetExhausted
	}
	b.mu.Lock()
	refused := b.refused
	b.mu.Unlock()
	if refused {
		return true, GapBudgetExhausted
	}
	return false, ""
}
