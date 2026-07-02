package oob

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestMain enables OOB for the whole test binary by setting the env BEFORE
// any config.Get() runs, so Generate()/Enabled() operate against a configured
// public URL + port.
func TestMain(m *testing.M) {
	os.Setenv("XALGORIX_OOB_PUBLIC_URL", "http://oob.test.example")
	os.Setenv("XALGORIX_OOB_PORT", "0") // 0 → ensureStarted errors, but Generate registers before that only after start; see note
	os.Exit(m.Run())
}

// resetStore clears the package-global interaction store between tests.
func resetStore() {
	mu.Lock()
	interactions = map[string][]Interaction{}
	tokenOrder = nil
	mu.Unlock()
}

// registerToken mimics what Generate does to the store, without needing the
// HTTP listener (which we don't want to bind in unit tests).
func registerToken(tok string) {
	mu.Lock()
	interactions[tok] = []Interaction{}
	tokenOrder = append(tokenOrder, tok)
	for len(tokenOrder) > maxTokens {
		old := tokenOrder[0]
		tokenOrder = tokenOrder[1:]
		delete(interactions, old)
	}
	mu.Unlock()
}

// fireCallback invokes the HTTP handler directly (no network) for a path.
func fireCallback(path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rr := httptest.NewRecorder()
	handle(rr, req)
	return rr
}

func TestEnabledAndPublicBaseURL(t *testing.T) {
	if !Enabled() {
		t.Fatal("OOB should be enabled when XALGORIX_OOB_PUBLIC_URL is set")
	}
	if got := PublicBaseURL(); got != "http://oob.test.example" {
		t.Fatalf("PublicBaseURL = %q, want trimmed base", got)
	}
}

func TestHandleRecordsRegisteredToken(t *testing.T) {
	resetStore()
	tok := "xdeadbeefcafe0001"
	registerToken(tok)

	rr := fireCallback("/" + tok + "/path?probe=1")
	if rr.Code != http.StatusOK {
		t.Fatalf("handler status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "xalgorix-oob-ok:"+tok) {
		t.Fatalf("response body missing marker: %q", rr.Body.String())
	}

	hits := Poll(tok)
	if len(hits) != 1 {
		t.Fatalf("expected 1 recorded interaction, got %d", len(hits))
	}
	if hits[0].Query != "probe=1" {
		t.Fatalf("recorded query = %q, want probe=1", hits[0].Query)
	}
	if hits[0].Token != tok {
		t.Fatalf("recorded token = %q, want %q", hits[0].Token, tok)
	}
}

func TestHandleIgnoresUnregisteredToken(t *testing.T) {
	resetStore()
	// Internet noise hitting an un-minted token must NOT be recorded and must
	// NOT create a new map entry (no unbounded growth from scanner traffic).
	rr := fireCallback("/xnot-a-registered-token/favicon.ico")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (benign)", rr.Code)
	}
	mu.Lock()
	n := len(interactions)
	mu.Unlock()
	if n != 0 {
		t.Fatalf("unregistered callback must not create store entries, got %d", n)
	}
	if got := Poll("xnot-a-registered-token"); len(got) != 0 {
		t.Fatalf("unregistered token must have no interactions, got %d", len(got))
	}
}

func TestHitsCapPerToken(t *testing.T) {
	resetStore()
	tok := "xcapabcdef012345"
	registerToken(tok)
	for i := 0; i < maxHitsPerToken+25; i++ {
		fireCallback(fmt.Sprintf("/%s/%d", tok, i))
	}
	hits := Poll(tok)
	if len(hits) != maxHitsPerToken {
		t.Fatalf("interactions per token = %d, want capped at %d", len(hits), maxHitsPerToken)
	}
}

func TestTokenFIFOEviction(t *testing.T) {
	resetStore()
	first := "xfirsttoken00000"
	registerToken(first)
	// Push well past the cap so the first token gets evicted.
	for i := 0; i < maxTokens+5; i++ {
		registerToken(fmt.Sprintf("xevict%011d", i))
	}
	mu.Lock()
	total := len(interactions)
	_, firstStillThere := interactions[first]
	mu.Unlock()
	if total > maxTokens {
		t.Fatalf("registered tokens = %d, must be capped at %d", total, maxTokens)
	}
	if firstStillThere {
		t.Fatal("oldest token should have been evicted (FIFO)")
	}
}

func TestPollReturnsCopy(t *testing.T) {
	resetStore()
	tok := "xcopytoken000001"
	registerToken(tok)
	fireCallback("/" + tok + "/x")
	got := Poll(tok)
	if len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
	// Mutating the returned slice must not affect the store.
	got[0].Body = "TAMPERED"
	again := Poll(tok)
	if again[0].Body == "TAMPERED" {
		t.Fatal("Poll must return a defensive copy, store was mutated")
	}
}

func TestFirstPathSegment(t *testing.T) {
	cases := map[string]string{
		"/abc/def":   "abc",
		"abc/def":    "abc",
		"/only":      "only",
		"/":          "",
		"":           "",
		"/tok?q=1":   "tok",
		"/tok/a?q=1": "tok",
	}
	for in, want := range cases {
		if got := firstPathSegment(in); got != want {
			t.Errorf("firstPathSegment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRandTokenFormatAndUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		tok := randToken()
		if !strings.HasPrefix(tok, "x") {
			t.Fatalf("token %q must start with 'x'", tok)
		}
		if len(tok) != 17 {
			t.Fatalf("token %q len = %d, want 17", tok, len(tok))
		}
		if seen[tok] {
			t.Fatalf("duplicate token generated: %q", tok)
		}
		seen[tok] = true
	}
}
