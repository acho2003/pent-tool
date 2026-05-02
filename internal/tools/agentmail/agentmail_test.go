package agentmail

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

func TestExtractVerificationURL(t *testing.T) {
	text := "Confirm your account: https://app.example.test/verify?token=abc123.)"
	if got := extractVerificationURL(text); got != "https://app.example.test/verify?token=abc123" {
		t.Fatalf("verification URL = %q", got)
	}

	fallback := "Use https://app.example.test/path?token=abcdefghijklmnopqrstuvwxyz123456"
	if got := extractVerificationURL(fallback); !strings.Contains(got, "token=abcdefghijklmnopqrstuvwxyz123456") {
		t.Fatalf("fallback URL = %q", got)
	}

	if got := extractVerificationURL("no links here"); got != "" {
		t.Fatalf("unexpected URL = %q", got)
	}
}

func TestRegisterSkipsWhenUnconfigured(t *testing.T) {
	cfg := config.Get()
	oldKey := cfg.AgentMailAPIKey
	cfg.AgentMailAPIKey = ""
	defer func() { cfg.AgentMailAPIKey = oldKey }()

	reg := tools.NewRegistry()
	Register(reg)
	if _, ok := reg.Get("agentmail"); ok {
		t.Fatal("agentmail tool registered without API key")
	}
}
