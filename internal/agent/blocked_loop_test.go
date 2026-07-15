package agent

import (
	"strings"
	"testing"
)

// TestNoteBlockedToolCall_EscalatesOnSustainedBlocks verifies the blocked-call
// backstop: repeated guard-blocked calls escalate from silence → soft nudge →
// hard "stop / pivot / finish" nudge, so a model fixating on a permanently
// rejected action can't burn iterations without correction (issue #158
// follow-up: the block branches short-circuit before the normal stuck tracker).
func TestNoteBlockedToolCall_EscalatesOnSustainedBlocks(t *testing.T) {
	st := NewScanState()
	args := map[string]string{"command": "curl http://out-of-scope.example/"}

	// Below the soft threshold: no nudge yet.
	for i := 1; i < BlockedCallSoftNudge; i++ {
		if msg := noteBlockedToolCall(st, "terminal_execute", args); msg != "" {
			t.Fatalf("block #%d should not nudge yet, got %q", i, msg)
		}
	}

	// At the soft threshold: a corrective nudge appears.
	soft := noteBlockedToolCall(st, "terminal_execute", args)
	if soft == "" {
		t.Fatalf("expected a soft nudge at %d consecutive blocks", BlockedCallSoftNudge)
	}
	if strings.Contains(soft, "STOP") {
		t.Fatalf("soft nudge should not be the hard escalation yet: %q", soft)
	}

	// Keep hitting blocks until the hard threshold → strong stop/pivot/finish.
	var hard string
	for st.ConsecutiveBlockedCalls < BlockedCallHardNudge {
		hard = noteBlockedToolCall(st, "terminal_execute", args)
	}
	if !strings.Contains(hard, "STOP") || !strings.Contains(strings.ToLower(hard), "finish") {
		t.Fatalf("expected hard escalation to tell the agent to stop and finish, got %q", hard)
	}
}

// TestNoteBlockedToolCall_ResetClearsEscalation verifies that once an allowed
// call clears the counter (as the dispatch loop does on a guard-pass), the
// escalation starts over — so interleaved allowed work never trips the loop
// backstop.
func TestNoteBlockedToolCall_ResetClearsEscalation(t *testing.T) {
	st := NewScanState()
	args := map[string]string{"command": "curl http://out-of-scope.example/"}

	for i := 0; i < BlockedCallSoftNudge; i++ {
		noteBlockedToolCall(st, "terminal_execute", args)
	}
	if st.ConsecutiveBlockedCalls < BlockedCallSoftNudge {
		t.Fatalf("counter did not accumulate: %d", st.ConsecutiveBlockedCalls)
	}

	// Simulate a call that passes the guards (dispatch loop does this).
	st.ConsecutiveBlockedCalls = 0

	// The next block is treated as fresh — no immediate nudge.
	if msg := noteBlockedToolCall(st, "terminal_execute", args); msg != "" {
		t.Fatalf("after a reset the first block should not nudge, got %q", msg)
	}
}

// TestNoteBlockedToolCall_IdenticalRepeatMessaging verifies the soft nudge
// calls out an exact-repeat loop distinctly from a varied-but-all-blocked loop.
func TestNoteBlockedToolCall_IdenticalRepeatMessaging(t *testing.T) {
	st := NewScanState()
	same := map[string]string{"command": "curl http://oos.example/"}
	for i := 0; i < BlockedCallSoftNudge-1; i++ {
		noteBlockedToolCall(st, "terminal_execute", same)
	}
	msg := noteBlockedToolCall(st, "terminal_execute", same)
	if !strings.Contains(msg, "exact blocked action") {
		t.Fatalf("expected identical-repeat wording, got %q", msg)
	}
}
