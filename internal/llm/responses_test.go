package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// responsesSSE builds a minimal Responses-API SSE body: a couple of text
// deltas followed by a completed event carrying usage.
func responsesSSE() string {
	return strings.Join([]string{
		`data: {"type":"response.created"}`,
		``,
		`data: {"type":"response.output_text.delta","delta":"Hello"}`,
		``,
		`data: {"type":"response.output_text.delta","delta":", world"}`,
		``,
		`data: {"type":"response.completed","response":{"output":[{"type":"message","content":[{"type":"output_text","text":"Hello, world"}]}],"usage":{"input_tokens":11,"output_tokens":3}}}`,
		``,
		`data: [DONE]`,
		``,
	}, "\n")
}

func newResponsesClient(t *testing.T, rt roundTripFunc) *Client {
	t.Helper()
	ep := Endpoint{
		URL:         "https://chatgpt.com/backend-api/codex/responses",
		Model:       "gpt-5.1-codex",
		HeaderStyle: headerStyleResponses,
		Auth:        AuthOAuthBearer,
		AccessToken: "tok_abc",
		VendorOverride: func(req *http.Request) {
			req.Header.Set("chatgpt-account-id", "acct_123")
			req.Header.Set("OpenAI-Beta", "responses=experimental")
			req.Header.Set("originator", "codex_cli_rs")
		},
	}
	c := NewClient(
		&config.Config{LLM: "codex/gpt-5.1-codex", ReasoningEffort: "high", LLMMaxRetries: 1},
		WithResolver(NewFixedResolver(ep)),
		WithHTTPClient(&http.Client{Transport: rt}),
	)
	return c
}

// TestResponses_DoChat_ParsesSSEAndHeaders verifies the non-streaming
// Responses path: correct URL, OAuth + Codex headers, a Responses-shaped
// request body, and SSE deltas assembled into the final string.
func TestResponses_DoChat_ParsesSSEAndHeaders(t *testing.T) {
	var gotURL, gotAuth, gotAccount, gotBeta, gotOriginator, gotAccept string
	var gotBody responsesRequest

	c := newResponsesClient(t, func(req *http.Request) (*http.Response, error) {
		gotURL = req.URL.String()
		gotAuth = req.Header.Get("Authorization")
		gotAccount = req.Header.Get("chatgpt-account-id")
		gotBeta = req.Header.Get("OpenAI-Beta")
		gotOriginator = req.Header.Get("originator")
		gotAccept = req.Header.Get("Accept")
		raw, _ := io.ReadAll(req.Body)
		_ = json.Unmarshal(raw, &gotBody)
		resp := jsonResponse(http.StatusOK, responsesSSE())
		resp.Header.Set("Content-Type", "text/event-stream")
		return resp, nil
	})

	out, err := c.Chat([]Message{
		{Role: "system", Content: "You are Codex."},
		{Role: "user", Content: "hi"},
	})
	if err != nil {
		t.Fatalf("Chat returned error: %v", err)
	}
	if out != "Hello, world" {
		t.Errorf("output = %q, want %q", out, "Hello, world")
	}

	// URL + headers
	if gotURL != "https://chatgpt.com/backend-api/codex/responses" {
		t.Errorf("URL = %q", gotURL)
	}
	if gotAuth != "Bearer tok_abc" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotAccount != "acct_123" {
		t.Errorf("chatgpt-account-id = %q", gotAccount)
	}
	if gotBeta != "responses=experimental" {
		t.Errorf("OpenAI-Beta = %q", gotBeta)
	}
	if gotOriginator != "codex_cli_rs" {
		t.Errorf("originator = %q", gotOriginator)
	}
	if gotAccept != "text/event-stream" {
		t.Errorf("Accept = %q", gotAccept)
	}

	// Body shape
	if gotBody.Model != "gpt-5.1-codex" {
		t.Errorf("body.model = %q", gotBody.Model)
	}
	if gotBody.Store {
		t.Errorf("body.store = true, want false")
	}
	if !gotBody.Stream {
		t.Errorf("body.stream = false, want true")
	}
	if gotBody.Instructions != "You are Codex." {
		t.Errorf("body.instructions = %q", gotBody.Instructions)
	}
	if gotBody.Reasoning == nil || gotBody.Reasoning.Effort != "high" {
		t.Errorf("body.reasoning = %+v, want effort=high", gotBody.Reasoning)
	}
	if len(gotBody.Include) == 0 || gotBody.Include[0] != "reasoning.encrypted_content" {
		t.Errorf("body.include = %v, want [reasoning.encrypted_content]", gotBody.Include)
	}
	if len(gotBody.Input) != 1 || gotBody.Input[0].Role != "user" ||
		len(gotBody.Input[0].Content) != 1 || gotBody.Input[0].Content[0].Type != "input_text" ||
		gotBody.Input[0].Content[0].Text != "hi" {
		t.Errorf("body.input = %+v, want single user input_text 'hi'", gotBody.Input)
	}

	// Usage tracked from the completed event.
	in, outTok, _ := c.GetTokens()
	if in != 11 || outTok != 3 {
		t.Errorf("tokens = (%d,%d), want (11,3)", in, outTok)
	}
}

// TestResponses_ChatStream_ForwardsDeltas verifies the streaming path emits
// each text delta then a Done chunk.
func TestResponses_ChatStream_ForwardsDeltas(t *testing.T) {
	c := newResponsesClient(t, func(req *http.Request) (*http.Response, error) {
		resp := jsonResponse(http.StatusOK, responsesSSE())
		resp.Header.Set("Content-Type", "text/event-stream")
		return resp, nil
	})

	var content strings.Builder
	var done bool
	for chunk := range c.ChatStream([]Message{{Role: "user", Content: "hi"}}) {
		if chunk.Err != nil {
			t.Fatalf("stream error: %v", chunk.Err)
		}
		content.WriteString(chunk.Content)
		if chunk.Done {
			done = true
		}
	}
	if !done {
		t.Errorf("stream never signaled Done")
	}
	if content.String() != "Hello, world" {
		t.Errorf("streamed content = %q, want %q", content.String(), "Hello, world")
	}
}

// TestResponses_ErrorEvent surfaces a response.failed SSE event as an error.
// It drives doResponses directly to avoid the retry/backoff wrapper.
func TestResponses_ErrorEvent(t *testing.T) {
	body := strings.Join([]string{
		`data: {"type":"response.created"}`,
		``,
		`data: {"type":"response.failed","error":{"message":"model produced invalid output"}}`,
		``,
	}, "\n")
	c := newResponsesClient(t, func(req *http.Request) (*http.Response, error) {
		resp := jsonResponse(http.StatusOK, body)
		resp.Header.Set("Content-Type", "text/event-stream")
		return resp, nil
	})
	ep := Endpoint{
		URL:         "https://chatgpt.com/backend-api/codex/responses",
		Model:       "gpt-5.1-codex",
		HeaderStyle: headerStyleResponses,
		Auth:        AuthOAuthBearer,
		AccessToken: "tok_abc",
	}
	_, err := c.doResponses(context.Background(), ep, []Message{{Role: "user", Content: "hi"}})
	if err == nil {
		t.Fatal("expected error from response.failed event")
	}
	if !strings.Contains(err.Error(), "model produced invalid output") {
		t.Errorf("error = %v, want it to contain the failure message", err)
	}
}

// TestResponses_UsageLimitMapsToRateLimit checks a usage-limit failure is
// surfaced with the rate-limit marker so the agent applies its backoff
// instead of aborting the scan.
func TestResponses_UsageLimitMapsToRateLimit(t *testing.T) {
	body := `data: {"type":"response.failed","error":{"message":"usage_limit_reached"}}` + "\n\n"
	err := scanResponsesSSE(strings.NewReader(body), func(*responsesEvent) {})
	if err == nil {
		t.Fatal("expected error")
	}
	if !isRateLimitError(err.Error()) {
		t.Errorf("usage-limit error %q not recognized as rate limit", err)
	}
}

// TestBuildResponsesBody_RoleMapping checks system→instructions, assistant→
// output_text, and effort normalization.
func TestBuildResponsesBody_RoleMapping(t *testing.T) {
	req := buildResponsesBody("gpt-5.1-codex", []Message{
		{Role: "system", Content: "sys"},
		{Role: "user", Content: "u1"},
		{Role: "assistant", Content: "a1"},
		{Role: "user", Content: "u2"},
	}, "minimal", false)

	if req.Instructions != "sys" {
		t.Errorf("instructions = %q, want sys", req.Instructions)
	}
	if req.Stream {
		t.Errorf("stream = true, want false")
	}
	if req.Reasoning == nil || req.Reasoning.Effort != "low" {
		t.Errorf("reasoning effort = %+v, want low (minimal→low)", req.Reasoning)
	}
	if len(req.Input) != 3 {
		t.Fatalf("input len = %d, want 3", len(req.Input))
	}
	if req.Input[0].Content[0].Type != "input_text" {
		t.Errorf("user content type = %q, want input_text", req.Input[0].Content[0].Type)
	}
	if req.Input[1].Role != "assistant" || req.Input[1].Content[0].Type != "output_text" {
		t.Errorf("assistant turn = %+v, want output_text", req.Input[1])
	}
}

// ensure context import is used (doResponses takes ctx through doChat).
var _ = context.Background
