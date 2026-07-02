package oob

import (
	"testing"
	"time"

	ishserver "github.com/projectdiscovery/interactsh/pkg/server"
)

func TestIshToInteractionHTTP(t *testing.T) {
	raw := "GET /cb/path?probe=1 HTTP/1.1\r\nHost: x.oast.pro\r\nUser-Agent: curl/8.4\r\n\r\n"
	i := &ishserver.Interaction{
		Protocol:      "http",
		FullId:        "cabc123",
		RawRequest:    raw,
		RemoteAddress: "203.0.113.5:44321",
		Timestamp:     time.Now(),
	}
	out := ishToInteraction("cabc123", i)
	if out.Protocol != "http" {
		t.Fatalf("protocol = %q", out.Protocol)
	}
	if out.Method != "GET" {
		t.Fatalf("method = %q, want GET", out.Method)
	}
	if out.Path != "/cb/path" {
		t.Fatalf("path = %q, want /cb/path", out.Path)
	}
	if out.Query != "probe=1" {
		t.Fatalf("query = %q, want probe=1", out.Query)
	}
	if out.UserAgent != "curl/8.4" {
		t.Fatalf("ua = %q, want curl/8.4", out.UserAgent)
	}
	if out.RemoteAddr != "203.0.113.5:44321" {
		t.Fatalf("remote = %q", out.RemoteAddr)
	}
}

func TestIshToInteractionDNS(t *testing.T) {
	i := &ishserver.Interaction{
		Protocol:  "dns",
		FullId:    "cdns001",
		QType:     "A",
		Timestamp: time.Time{}, // zero → mapper should backfill
	}
	out := ishToInteraction("cdns001", i)
	if out.Method != "DNS" {
		t.Fatalf("method = %q, want DNS", out.Method)
	}
	if out.Path != "A" {
		t.Fatalf("path = %q, want A (qtype)", out.Path)
	}
	if out.Time.IsZero() {
		t.Fatal("zero timestamp should be backfilled to now")
	}
}

func TestParseRawHTTPInvalid(t *testing.T) {
	if parseRawHTTP("") != nil {
		t.Fatal("empty raw should return nil")
	}
	if parseRawHTTP("this is not http") != nil {
		t.Fatal("garbage raw should return nil")
	}
}

func TestInteractshPollTokenNormalization(t *testing.T) {
	const tok = "ctok999"
	ishMu.Lock()
	ishReg[tok] = true
	ishHits[tok] = []Interaction{{Token: tok, Protocol: "dns", Method: "DNS"}}
	ishMu.Unlock()
	t.Cleanup(func() {
		ishMu.Lock()
		delete(ishReg, tok)
		delete(ishHits, tok)
		ishMu.Unlock()
	})

	for _, in := range []string{tok, "https://" + tok + ".oast.pro", "http://" + tok + ".oast.pro/x", tok + ".oast.pro"} {
		got := interactshPoll(in)
		if len(got) != 1 {
			t.Fatalf("interactshPoll(%q) = %d hits, want 1", in, len(got))
		}
	}
	// Unknown token → no hits.
	if got := interactshPoll("cunknown"); len(got) != 0 {
		t.Fatalf("unknown token returned %d hits", len(got))
	}
}

func TestOnInteractionOnlyRecordsRegistered(t *testing.T) {
	const reg = "creg777"
	ishMu.Lock()
	ishReg[reg] = true
	ishHits[reg] = []Interaction{}
	ishMu.Unlock()
	t.Cleanup(func() {
		ishMu.Lock()
		delete(ishReg, reg)
		delete(ishHits, reg)
		delete(ishHits, "cunreg000")
		ishMu.Unlock()
	})

	// Registered token → recorded.
	onInteraction(&ishserver.Interaction{Protocol: "http", FullId: reg, RawRequest: "GET / HTTP/1.1\r\nHost: h\r\n\r\n", Timestamp: time.Now()})
	if got := interactshPoll(reg); len(got) != 1 {
		t.Fatalf("registered interaction not recorded: %d", len(got))
	}
	// Unregistered token → ignored, no map entry created.
	onInteraction(&ishserver.Interaction{Protocol: "dns", FullId: "cunreg000", Timestamp: time.Now()})
	ishMu.Lock()
	_, exists := ishHits["cunreg000"]
	ishMu.Unlock()
	if exists {
		t.Fatal("unregistered interaction must not create a store entry")
	}
}
