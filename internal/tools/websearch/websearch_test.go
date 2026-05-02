package websearch

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

func TestClampMaxResultsAndCVEIDNormalization(t *testing.T) {
	maxCases := map[string]int{
		"":    10,
		"abc": 10,
		"0":   1,
		"-9":  1,
		"1":   1,
		"25":  25,
		"200": 25,
		"12":  12,
	}
	for raw, want := range maxCases {
		if got := clampMaxResults(raw); got != want {
			t.Fatalf("clampMaxResults(%q) = %d, want %d", raw, got, want)
		}
	}

	cveCases := map[string]string{
		"2024-1234":    "CVE-2024-1234",
		" cve-2025-1 ": "CVE-2025-1",
		"":             "",
	}
	for raw, want := range cveCases {
		if got := normalizeCVEID(raw); got != want {
			t.Fatalf("normalizeCVEID(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestFormatResultsAndTruncateBody(t *testing.T) {
	formatted := formatResults("xalgorix", []searchResult{
		{Title: "One", URL: "https://one.test", Snippet: "first"},
		{Title: "Two", URL: "https://two.test"},
	})
	for _, want := range []string{"Search results for: xalgorix", "1. One", "URL: https://one.test", "first", "2. Two"} {
		if !strings.Contains(formatted.Output, want) {
			t.Fatalf("formatted output missing %q:\n%s", want, formatted.Output)
		}
	}

	empty := formatResults("nothing", nil)
	if !strings.Contains(empty.Output, "No results found for: nothing") {
		t.Fatalf("empty output = %q", empty.Output)
	}

	longBody := strings.Repeat("a", 600)
	truncated := truncateSearchBody(longBody)
	if len(truncated) >= len(longBody) || !strings.Contains(truncated, "[truncated]") {
		t.Fatalf("body was not truncated: len=%d", len(truncated))
	}
}

func TestSearchGeminiReturnsNon200AsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("Gemini request method = %s, want POST", r.Method)
		}
		http.Error(w, "bad key", http.StatusUnauthorized)
	}))
	defer server.Close()

	oldURL := geminiSearchURL
	geminiSearchURL = func(apiKey string) string {
		if apiKey != "test-key" {
			t.Fatalf("api key = %q, want test-key", apiKey)
		}
		return server.URL
	}
	defer func() { geminiSearchURL = oldURL }()

	cfg := config.Get()
	oldKey := cfg.GeminiAPIKey
	cfg.GeminiAPIKey = "test-key"
	defer func() { cfg.GeminiAPIKey = oldKey }()

	_, err := searchGemini("query", 3)
	if err == nil || !strings.Contains(err.Error(), "gemini search returned 401") {
		t.Fatalf("searchGemini non-200 error = %v", err)
	}
}
