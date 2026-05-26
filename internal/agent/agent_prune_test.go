package agent

import (
	"fmt"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/llm"
)

// TestPruneSliceCutoff_PruneMessages_DoesNotPanic exercises the bug
// condition described by Property 5 / Requirement 2.4 in the
// findings-consistency-and-pagination spec: pruneMessages must not panic
// for any message buffer of length n >= 0 (including the short-buffer
// edge cases 0 and 1) for any keepLast value the helper might compute
// internally.
//
// Validates: Requirement 2.4 (Slice-Cutoff Guard, Property 5)
//
// On the current code this test PASSES because pruneMessages already
// short-circuits on short buffers (see the early-return guards in
// internal/agent/agent.go). The test is retained as a regression
// boundary: any future refactor that drops the short-buffer guard will
// fail here before reaching production. See tasks 4.3/4.4 in the
// findings-consistency-and-pagination spec — those tasks were skipped
// once this test confirmed the behavior was already correct, so this
// file is the only artifact of that wave.
func TestPruneSliceCutoff_PruneMessages_DoesNotPanic(t *testing.T) {
	cases := []struct {
		name  string
		roles []string // empty slice = length 0
	}{
		{name: "len0_emptyBuffer", roles: nil},
		{name: "len1_systemOnly", roles: []string{"system"}},
		{name: "len1_userOnly", roles: []string{"user"}},
		{name: "len1_assistantOnly", roles: []string{"assistant"}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			a := newAgentForPruneTest(tc.roles)
			bufLen := len(a.messages)

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("pruneMessages panicked on len(messages)=%d: %v", bufLen, r)
				}
			}()

			a.pruneMessages()
		})
	}
}

// TestPruneSliceCutoff_ForcePruneMessages_DoesNotPanic mirrors the
// PruneMessages test against forcePruneMessages, the more aggressive
// helper invoked when shouldPruneBeforeLLM trips.
//
// Validates: Requirement 2.4 (Slice-Cutoff Guard, Property 5)
//
// On the current code this test PASSES for the same reason as
// TestPruneSliceCutoff_PruneMessages_DoesNotPanic: forcePruneMessages
// also short-circuits on short buffers. Retained as a regression
// boundary.
func TestPruneSliceCutoff_ForcePruneMessages_DoesNotPanic(t *testing.T) {
	cases := []struct {
		name  string
		roles []string
	}{
		{name: "len0_emptyBuffer", roles: nil},
		{name: "len1_systemOnly", roles: []string{"system"}},
		{name: "len1_userOnly", roles: []string{"user"}},
		{name: "len1_assistantOnly", roles: []string{"assistant"}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			a := newAgentForPruneTest(tc.roles)
			bufLen := len(a.messages)

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("forcePruneMessages panicked on len(messages)=%d: %v", bufLen, r)
				}
			}()

			a.forcePruneMessages()
		})
	}
}

// newAgentForPruneTest constructs an Agent populated only with what
// pruneMessages and forcePruneMessages need for the slice-cutoff
// arithmetic: the messages buffer and the embedded mutex. We
// deliberately avoid touching scanCtx, registry, llm client, or the
// hooks registry — none of those participate in the cutoff math, and
// avoiding them keeps the test focused on the panic source.
func newAgentForPruneTest(roles []string) *Agent {
	msgs := make([]llm.Message, len(roles))
	for i, r := range roles {
		msgs[i] = llm.Message{Role: r, Content: fmt.Sprintf("%s-msg-%d", r, i)}
	}
	return &Agent{
		messages: msgs,
	}
}
