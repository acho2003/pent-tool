package web

import (
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

func TestNormalizeEngine(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", engineDeterministic},              // default
		{"deterministic", engineDeterministic}, // explicit
		{"autonomous", engineAutonomous},       // explicit
		{"AUTONOMOUS", engineAutonomous},       // case-insensitive
		{"  autonomous  ", engineAutonomous},   // trimmed
		{"Deterministic", engineDeterministic},
		{"ai", engineDeterministic},      // unknown -> safe default
		{"garbage", engineDeterministic}, // unknown -> safe default
	}
	for _, c := range cases {
		if got := normalizeEngine(c.in); got != c.want {
			t.Errorf("normalizeEngine(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestAutonomousProviderConfigured(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.Config
		prof string
		want bool
	}{
		{"nothing set", &config.Config{}, "", false},
		{"api key set", &config.Config{APIKey: "sk-xxx"}, "", true},
		{"custom endpoint (ollama)", &config.Config{APIBase: "http://localhost:11434/v1"}, "", true},
		{"active llm profile", &config.Config{LLMProfile: "openai:default"}, "", true},
		{"per-scan provider profile", &config.Config{}, "openai:default", true},
		{"nil config", nil, "", false},
	}
	for _, c := range cases {
		if got := autonomousProviderConfigured(c.cfg, c.prof); got != c.want {
			t.Errorf("%s: autonomousProviderConfigured = %v, want %v", c.name, got, c.want)
		}
	}
}
