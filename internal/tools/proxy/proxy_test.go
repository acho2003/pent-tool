package proxy

import (
	"strings"
	"testing"
)

func TestParseHeadersRejectsMalformedJSON(t *testing.T) {
	if _, err := parseHeaders(`{"X-Test":"ok"`); err == nil {
		t.Fatal("malformed headers JSON was accepted")
	}
	if _, err := sendRequest(map[string]string{
		"method":  "GET",
		"url":     "https://example.test",
		"headers": `{"X-Test":"ok"`,
	}); err == nil || !strings.Contains(err.Error(), "invalid headers JSON") {
		t.Fatalf("sendRequest malformed headers error = %v", err)
	}
}

func TestParseHeadersAndCountClamp(t *testing.T) {
	headers, err := parseHeaders(`{"X-Test":"ok","Accept":"application/json"}`)
	if err != nil {
		t.Fatalf("parseHeaders: %v", err)
	}
	if headers["X-Test"] != "ok" || headers["Accept"] != "application/json" {
		t.Fatalf("unexpected headers: %#v", headers)
	}

	cases := map[string]int{
		"":    20,
		"abc": 20,
		"0":   1,
		"-5":  1,
		"1":   1,
		"200": 100,
		"100": 100,
		"42":  42,
	}
	for raw, want := range cases {
		if got := clampRequestCount(raw); got != want {
			t.Fatalf("clampRequestCount(%q) = %d, want %d", raw, got, want)
		}
	}
}

func TestSendRequestValidationErrorsBeforeNetwork(t *testing.T) {
	if _, err := sendRequest(map[string]string{"method": "BAD METHOD", "url": "https://example.test"}); err == nil {
		t.Fatal("invalid HTTP method was accepted")
	}
	if _, err := sendRequest(map[string]string{"method": "GET", "url": "://bad"}); err == nil {
		t.Fatal("invalid URL was accepted")
	}
}
