package llm

import (
	"context"
	"sync"
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
