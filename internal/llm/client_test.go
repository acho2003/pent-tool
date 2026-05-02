package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// newTestClient returns a Client wired to a minimal Config — enough for the
// SetContext/loadCtx surface without making any HTTP calls.
func newTestClient(t *testing.T) *Client {
	t.Helper()
	return NewClient(&config.Config{
		LLM:     "openai/gpt-test",
		APIBase: "https://api.openai.com/v1",
		APIKey:  "sk-test",
	})
}

// TestNewClient_DefaultContextBackground verifies that a freshly created
// client always returns a non-nil, non-cancelled context from loadCtx
// before any SetContext call. This is the contract that lets ChatStream
// run with no agent context wired up (e.g. from CLI tests).
func TestNewClient_DefaultContextBackground(t *testing.T) {
	c := newTestClient(t)
	got := c.loadCtx()
	if got == nil {
		t.Fatal("loadCtx returned nil before SetContext")
	}
	if err := got.Err(); err != nil {
		t.Fatalf("default context already cancelled: %v", err)
	}
}

// TestSetContext_NilFallsBackToBackground is the regression for the
// nil-interface bug we'd otherwise hit when storing a nil context.Context
// inside atomic.Value (storing a nil typed value panics if the underlying
// type is unset). SetContext(nil) must produce a non-nil Background-equiv.
func TestSetContext_NilFallsBackToBackground(t *testing.T) {
	c := newTestClient(t)
	//lint:ignore SA1012 intentional nil-context regression coverage
	c.SetContext(nil)
	got := c.loadCtx()
	if got == nil {
		t.Fatal("loadCtx returned nil after SetContext(nil)")
	}
	if err := got.Err(); err != nil {
		t.Fatalf("context already cancelled: %v", err)
	}
}

// TestSetContext_StoresAndReturnsSame round-trips a real context.
func TestSetContext_StoresAndReturnsSame(t *testing.T) {
	c := newTestClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.SetContext(ctx)
	got := c.loadCtx()
	if got == nil {
		t.Fatal("loadCtx returned nil after SetContext")
	}

	// Cancellation must propagate through the stored context.
	cancel()
	if err := got.Err(); err == nil {
		t.Error("expected stored context to be cancelled after cancel()")
	}
}

// TestSetContext_ConcurrentReadersAndWriters is the regression for the data
// race the review flagged on the (formerly plain) c.ctx field. With
// atomic.Value this should run cleanly. Without -race we cannot detect a
// data race directly, but we still exercise the path heavily — any panic
// from atomic.Value's "inconsistently typed value" guard would bubble up.
func TestSetContext_ConcurrentReadersAndWriters(t *testing.T) {
	c := newTestClient(t)
	c.SetContext(context.Background())

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// 4 writers swap the context rapidly.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					ctx, cancel := context.WithCancel(context.Background())
					c.SetContext(ctx)
					cancel()
				}
			}
		}()
	}

	// 16 readers loop on loadCtx — any nil return would panic under .Err().
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5000; j++ {
				if got := c.loadCtx(); got == nil {
					t.Error("loadCtx returned nil under contention")
					return
				} else {
					_ = got.Err() // exercise the interface, ignore result
				}
			}
		}()
	}

	// Let readers run for a bit, then signal stop and wait.
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Give readers enough iterations to be worthwhile.
		for i := 0; i < 200; i++ {
			c.SetContext(context.Background())
		}
		close(stop)
	}()

	wg.Wait()
}

// TestNewClient_ProviderParsedFromModel is a small sanity check that the
// "provider/model" string is split correctly — important because the URL
// switch in chatWithRetry/ChatStream branches on c.provider.
func TestNewClient_ProviderParsedFromModel(t *testing.T) {
	cases := []struct {
		llm  string
		want string
	}{
		{"openai/gpt-5.4", "openai"},
		{"anthropic/claude-sonnet", "anthropic"},
		{"google/gemini-3.1-flash", "google"},
		{"deepseek/deepseek-chat", "deepseek"},
		{"no-slash-model", ""},
	}
	for _, tc := range cases {
		t.Run(tc.llm, func(t *testing.T) {
			c := NewClient(&config.Config{LLM: tc.llm, APIKey: "k"})
			if c.provider != tc.want {
				t.Errorf("provider = %q, want %q", c.provider, tc.want)
			}
		})
	}
}

func TestResolveEndpoint_ProviderDefaultsAndCustomBases(t *testing.T) {
	cases := []struct {
		name      string
		cfg       config.Config
		wantURL   string
		wantModel string
	}{
		{
			name:      "openai default",
			cfg:       config.Config{LLM: "openai/gpt-5.4", APIKey: "k"},
			wantURL:   "https://api.openai.com/v1/chat/completions",
			wantModel: "gpt-5.4",
		},
		{
			name:      "deepseek v4 default",
			cfg:       config.Config{LLM: "deepseek/deepseek-v4-pro", APIKey: "k"},
			wantURL:   "https://api.deepseek.com/v1/chat/completions",
			wantModel: "deepseek-v4-pro",
		},
		{
			name:      "gemini default",
			cfg:       config.Config{LLM: "google/gemini-3.1-pro-preview", APIKey: "k"},
			wantURL:   "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-pro-preview:generateContent",
			wantModel: "gemini-3.1-pro-preview",
		},
		{
			name:      "anthropic default",
			cfg:       config.Config{LLM: "anthropic/claude-sonnet-4-20250514", APIKey: "k"},
			wantURL:   "https://api.anthropic.com/v1/messages",
			wantModel: "claude-sonnet-4-20250514",
		},
		{
			name:      "custom openai-compatible base",
			cfg:       config.Config{LLM: "custom/my-model", APIBase: "https://llm.example/api", APIKey: "k"},
			wantURL:   "https://llm.example/api/v1/chat/completions",
			wantModel: "my-model",
		},
		{
			name:      "explicit chat completions base",
			cfg:       config.Config{LLM: "custom/my-model", APIBase: "https://llm.example/v1/chat/completions", APIKey: "k"},
			wantURL:   "https://llm.example/v1/chat/completions",
			wantModel: "my-model",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient(&tc.cfg)
			gotURL, gotModel := c.resolveEndpoint()
			if gotURL != tc.wantURL {
				t.Fatalf("endpoint = %q, want %q", gotURL, tc.wantURL)
			}
			if gotModel != tc.wantModel {
				t.Fatalf("model = %q, want %q", gotModel, tc.wantModel)
			}
		})
	}
}

func TestDoChat_GeminiAPIBaseWithoutProviderUsesGeminiProtocol(t *testing.T) {
	c := NewClient(&config.Config{
		LLM:           "gemini-3.1-pro",
		APIBase:       "https://generativelanguage.googleapis.com/v1",
		APIKey:        "gemini-key",
		LLMMaxRetries: 3,
	})
	c.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if got := req.URL.String(); got != "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-pro:generateContent" {
			t.Errorf("URL = %q", got)
		}
		if got := req.Header.Get("x-goog-api-key"); got != "gemini-key" {
			t.Errorf("x-goog-api-key = %q, want gemini-key", got)
		}
		if got := req.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization header = %q, want empty for Gemini API key auth", got)
		}

		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("reading request body: %v", err)
		}
		bodyText := string(body)
		if !strings.Contains(bodyText, `"contents"`) {
			t.Errorf("Gemini request body missing contents: %s", bodyText)
		}
		if strings.Contains(bodyText, `"messages"`) {
			t.Errorf("Gemini request body used OpenAI messages shape: %s", bodyText)
		}

		return jsonResponse(http.StatusOK, `{"candidates":[{"content":{"parts":[{"text":"ok"}]}}]}`), nil
	})}

	got, err := c.doChat([]Message{{Role: "user", Content: "hello"}})
	if err != nil {
		t.Fatalf("doChat returned error: %v", err)
	}
	if got != "ok" {
		t.Fatalf("doChat = %q, want ok", got)
	}
}

func TestDoChat_AnthropicAPIBaseWithoutProviderUsesAnthropicProtocol(t *testing.T) {
	c := NewClient(&config.Config{
		LLM:           "claude-sonnet-4-20250514",
		APIBase:       "https://api.anthropic.com",
		APIKey:        "anthropic-key",
		LLMMaxRetries: 1,
	})
	c.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if got := req.URL.String(); got != "https://api.anthropic.com/v1/messages" {
			t.Errorf("URL = %q", got)
		}
		if got := req.Header.Get("x-api-key"); got != "anthropic-key" {
			t.Errorf("x-api-key = %q, want anthropic-key", got)
		}
		if got := req.Header.Get("anthropic-version"); got != "2023-06-01" {
			t.Errorf("anthropic-version = %q", got)
		}
		if got := req.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization header = %q, want empty for Anthropic", got)
		}

		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("reading request body: %v", err)
		}
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("unmarshal body: %v", err)
		}
		if payload["model"] != "claude-sonnet-4-20250514" || payload["system"] != "system prompt" {
			t.Fatalf("unexpected Anthropic payload: %s", string(body))
		}
		if _, ok := payload["messages"]; !ok {
			t.Fatalf("Anthropic payload missing messages: %s", string(body))
		}

		return jsonResponse(http.StatusOK, `{"message":{"content":[{"type":"text","text":"anthropic ok"}],"usage":{"input_tokens":3,"output_tokens":4}}}`), nil
	})}

	got, err := c.doChat([]Message{
		{Role: "system", Content: "system prompt"},
		{Role: "user", Content: "hello"},
	})
	if err != nil {
		t.Fatalf("doChat returned error: %v", err)
	}
	if got != "anthropic ok" {
		t.Fatalf("doChat = %q, want anthropic ok", got)
	}
	_, _, total := c.GetTokens()
	if total != 7 {
		t.Fatalf("token total = %d, want 7", total)
	}
}

func TestChatWithRetry_Gemini401IsNotRateLimited(t *testing.T) {
	c := NewClient(&config.Config{
		LLM:           "gemini-3.1-pro",
		APIBase:       "https://generativelanguage.googleapis.com/v1",
		APIKey:        "bad-key",
		LLMMaxRetries: 5,
	})

	var calls atomic.Int32
	c.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return jsonResponse(http.StatusUnauthorized, `{
			"error": {
				"code": 401,
				"message": "Request had invalid authentication credentials.",
				"status": "UNAUTHENTICATED",
				"details": [{
					"reason": "ACCESS_TOKEN_TYPE_UNSUPPORTED",
					"metadata": {
						"method": "google.ai.generativelanguage.v1beta.GenerativeService.GenerateContent"
					}
				}]
			}
		}`), nil
	})}

	_, err := c.Chat([]Message{{Role: "user", Content: "hello"}})
	if err == nil {
		t.Fatal("Chat returned nil error for 401")
	}
	if strings.Contains(strings.ToLower(err.Error()), "rate limited") {
		t.Fatalf("401 was misclassified as rate limited: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("RoundTrip calls = %d, want 1 for non-retryable 401", got)
	}
}

func TestChatWithRetry_NonRetryableStatusMatrix(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"bad request", http.StatusBadRequest, `{"error":{"message":"invalid request"}}`},
		{"unauthorized", http.StatusUnauthorized, `{"error":{"status":"UNAUTHENTICATED"}}`},
		{"forbidden", http.StatusForbidden, `{"error":{"status":"PERMISSION_DENIED"}}`},
		{"missing model", http.StatusNotFound, `{"error":{"message":"model not found"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient(&config.Config{LLM: "openai/gpt-test", APIKey: "bad", LLMMaxRetries: 5})
			var calls atomic.Int32
			c.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls.Add(1)
				return jsonResponse(tc.status, tc.body), nil
			})}
			_, err := c.Chat([]Message{{Role: "user", Content: "hello"}})
			if err == nil {
				t.Fatal("Chat returned nil error")
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("RoundTrip calls = %d, want 1", got)
			}
			if strings.Contains(strings.ToLower(err.Error()), "rate limited") {
				t.Fatalf("non-retryable error was misclassified as rate limited: %v", err)
			}
		})
	}
}

func TestRateLimitDetectionDoesNotMatchGenerateContent(t *testing.T) {
	authErr := `API returned 401: {"error":{"status":"UNAUTHENTICATED","details":[{"metadata":{"method":"google.ai.generativelanguage.v1beta.GenerativeService.GenerateContent"}}]}}`
	if isRateLimitError(authErr) {
		t.Fatal("GenerateContent auth error was classified as rate limited")
	}

	if !isRateLimitError(`API returned 429: {"error":{"status":"RESOURCE_EXHAUSTED","message":"Too Many Requests"}}`) {
		t.Fatal("429 RESOURCE_EXHAUSTED error was not classified as rate limited")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
