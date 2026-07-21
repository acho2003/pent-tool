package agent

import (
	"strings"
	"testing"
)

// A huge tool output (e.g. cat/strings of a 500 KB minified JS bundle) must be
// capped before it enters the LLM context — otherwise it floods the window and
// the model stalls into no-tool responses until the scan force-stops
// (observed on app.joinhomebase.com).
func TestCapToolOutputForLLM(t *testing.T) {
	small := "endpoints:\n/graphql\n/api/v5/users"
	if got := capToolOutputForLLM(small); got != small {
		t.Errorf("small output should pass through unchanged, got %q", got)
	}

	big := strings.Repeat("A", 40000) + "TAIL_MARKER"
	got := capToolOutputForLLM(big)
	if len(got) >= len(big) {
		t.Fatalf("large output was not capped: in=%d out=%d", len(big), len(got))
	}
	if len(got) > maxToolResultBytes+500 {
		t.Errorf("capped output too large: %d bytes", len(got))
	}
	if !strings.Contains(got, "TOOL OUTPUT TRUNCATED") {
		t.Error("capped output missing truncation notice")
	}
	if !strings.HasPrefix(got, "AAAA") {
		t.Error("capped output should keep the head")
	}
	if !strings.HasSuffix(got, "TAIL_MARKER") {
		t.Error("capped output should keep the tail")
	}
}

// The no-tool force-stop must report the ACTUAL cause, not the old catch-all
// "refused to call tools".
func TestClassifyNoToolAbort(t *testing.T) {
	// Stall (no refusals) → generic no-tool with context-flood explanation.
	reason, detail := classifyNoToolAbort(&ScanState{NoToolCount: 15, RefusalCount: 0})
	if reason != "llm_no_tool_calls" {
		t.Errorf("reason = %q, want llm_no_tool_calls", reason)
	}
	ld := strings.ToLower(detail)
	if !strings.Contains(ld, "no tool call") || strings.Contains(ld, "refused to call tools after 15 attempts") {
		t.Errorf("stall detail should describe the stall, got %q", detail)
	}

	// Repeated refusals → safety-refusal reason.
	reason, detail = classifyNoToolAbort(&ScanState{NoToolCount: 15, RefusalCount: 5})
	if reason != "llm_safety_refusal" {
		t.Errorf("reason = %q, want llm_safety_refusal", reason)
	}
	if !strings.Contains(strings.ToLower(detail), "refusal") {
		t.Errorf("refusal detail should mention refusal, got %q", detail)
	}

	// Nil state must not panic.
	if r, _ := classifyNoToolAbort(nil); r != "llm_no_tool_calls" {
		t.Errorf("nil state reason = %q, want llm_no_tool_calls", r)
	}
}
