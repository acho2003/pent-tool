package scanner

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestAssessmentBudgetSharedLimiterAcrossCallers(t *testing.T) {
	const rps, perCaller = 50, 10
	b := NewAssessmentBudget(rps, 500, 0)
	start := time.Now()
	var wg sync.WaitGroup
	errs := make(chan error, 2*perCaller)
	// Two callers (e.g. two scanners against two different hosts) draw from the
	// one assessment-wide bucket, so together they get rps, not 2*rps.
	for _, host := range []string{"https://a.example", "https://b.example"} {
		wg.Add(1)
		go func(string) {
			defer wg.Done()
			for range perCaller {
				errs <- b.Wait(context.Background())
			}
		}(host)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	// 20 requests at 50 rps with burst 1 need at least 19 intervals of 20ms.
	if elapsed, min := time.Since(start), time.Duration(2*perCaller-1)*time.Second/rps; elapsed < min*9/10 {
		t.Fatalf("callers exceeded shared rate: %d requests in %v (min %v)", 2*perCaller, elapsed, min)
	}
}

func TestAssessmentBudgetWaitHonoursCancellation(t *testing.T) {
	b := NewAssessmentBudget(1, 500, 0)
	if err := b.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait after cancel = %v, want context.Canceled", err)
	}
	var nilBudget *AssessmentBudget
	if err := nilBudget.Wait(context.Background()); err != nil {
		t.Fatalf("nil budget must not throttle: %v", err)
	}
	if got := nilBudget.ReserveEndpoints([]string{"a", "b"}); len(got) != 2 {
		t.Fatalf("nil budget must not cap endpoints: %v", got)
	}
	if exhausted, _ := nilBudget.Exhausted(); exhausted {
		t.Fatal("nil budget reported exhausted")
	}
}

func endpointIDs(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s/%d", prefix, i)
	}
	return out
}

func TestAssessmentBudgetUniqueEndpointCapIsGlobal(t *testing.T) {
	b := NewAssessmentBudget(2, 500, 30*time.Minute)
	a := b.ReserveEndpoints(endpointIDs("GET https://a.example", 300))
	if len(a) != 300 {
		t.Fatalf("target A granted %d, want 300", len(a))
	}
	if exhausted, _ := b.Exhausted(); exhausted {
		t.Fatal("budget exhausted before cap reached")
	}
	// A second scanner re-testing target A's endpoints does not consume more of
	// the cap: the cap counts unique endpoints, not scanner dispatches.
	if again := b.ReserveEndpoints(a[:50]); len(again) != 50 {
		t.Fatalf("already-reserved endpoints refused: %d", len(again))
	}
	bIDs := endpointIDs("GET https://b.example", 300)
	got := b.ReserveEndpoints(append(bIDs, bIDs[0], "")) // duplicates and blanks ignored
	if len(got) != 200 {
		t.Fatalf("target B granted %d, want the remaining 200 of the shared 500", len(got))
	}
	for i, id := range got {
		if id != bIDs[i] {
			t.Fatalf("grant order not preserved at %d: %q", i, id)
		}
	}
	if exhausted, kind := b.Exhausted(); !exhausted || kind != GapBudgetExhausted {
		t.Fatalf("Exhausted() = %v, %q after cap refusal", exhausted, kind)
	}
	if more := b.ReserveEndpoints([]string{"GET https://c.example/"}); len(more) != 0 {
		t.Fatalf("endpoint granted beyond global cap: %v", more)
	}
	if again := b.ReserveEndpoints(bIDs[:1]); len(again) != 1 {
		t.Fatal("reserved endpoint refused after cap reached")
	}
}

func TestAssessmentBudgetDeadlineExhaustion(t *testing.T) {
	b := NewAssessmentBudget(0, 0, 20*time.Millisecond)
	if exhausted, _ := b.Exhausted(); exhausted {
		t.Fatal("fresh budget exhausted")
	}
	if r := b.Remaining(); r <= 0 || r > 20*time.Millisecond {
		t.Fatalf("Remaining() = %v", r)
	}
	if _, ok := b.Deadline(); !ok {
		t.Fatal("budget with a duration has no deadline")
	}
	time.Sleep(30 * time.Millisecond)
	if exhausted, kind := b.Exhausted(); !exhausted || kind != GapBudgetExhausted {
		t.Fatalf("Exhausted() = %v, %q after deadline", exhausted, kind)
	}
	if r := b.Remaining(); r != 0 {
		t.Fatalf("Remaining() after deadline = %v, want 0", r)
	}
	if err := b.Wait(context.Background()); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("Wait after deadline = %v, want ErrBudgetExhausted", err)
	}

	// A rate-limited wait that cannot finish before the deadline also reports
	// budget exhaustion rather than a caller cancellation.
	slow := NewAssessmentBudget(1, 0, 50*time.Millisecond)
	if err := slow.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := slow.Wait(context.Background()); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("Wait beyond deadline = %v, want ErrBudgetExhausted", err)
	}

	unbounded := NewAssessmentBudget(2, 500, 0)
	if _, ok := unbounded.Deadline(); ok {
		t.Fatal("zero budget has a deadline")
	}
	if unbounded.Remaining() != NoBudgetDeadline {
		t.Fatalf("Remaining() without deadline = %v", unbounded.Remaining())
	}
	if exhausted, _ := unbounded.Exhausted(); exhausted {
		t.Fatal("unbounded budget exhausted")
	}
}
