package llm

import (
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// Kimi K2.6 / K3 reject any temperature other than 1 ("only 1 is allowed for
// this model"). Regression for issue #237.
func TestModelRequiresFixedTemperature(t *testing.T) {
	cases := map[string]bool{
		"kimi-k2.6":        true,
		"kimi-k3":          true,
		"kimi-k3.0":        true,
		"kimi-k3-max":      true,
		"openai/kimi-k2.6": true,
		"moonshot/kimi-k3": true,

		"kimi-k2.5":       false,
		"kimi-k2":         false,
		"gpt-4o":          false,
		"gpt-5.4":         false,
		"deepseek-v4-pro": false,
		"claude-sonnet-4": false,
	}
	for model, want := range cases {
		if got := modelRequiresFixedTemperature(model); got != want {
			t.Errorf("modelRequiresFixedTemperature(%q) = %v, want %v", model, got, want)
		}
	}
}

// For a fixed-temperature model, effectiveTemperature must always return 1 —
// even after the agent's per-role SetTemperature override (e.g. validator 0.0)
// and regardless of the configured XALGORIX_TEMPERATURE.
func TestEffectiveTemperature_FixedModelIgnoresOverrideAndConfig(t *testing.T) {
	half := 0.5
	c := NewClient(&config.Config{LLM: "openai/kimi-k2.6", APIKey: "k", Temperature: &half})

	if got := c.effectiveTemperature(); got == nil || *got != 1.0 {
		t.Fatalf("kimi effectiveTemperature (config 0.5) = %v, want 1.0", got)
	}

	zero := 0.0
	c.SetTemperature(&zero) // agent validator override
	if got := c.effectiveTemperature(); got == nil || *got != 1.0 {
		t.Fatalf("kimi effectiveTemperature after SetTemperature(0.0) = %v, want 1.0", got)
	}
}

// Non-fixed models keep the existing behavior: per-call override wins, else
// the config default.
func TestEffectiveTemperature_NormalModelHonorsOverride(t *testing.T) {
	def := 0.2
	c := NewClient(&config.Config{LLM: "openai/gpt-4o", APIKey: "k", Temperature: &def})

	if got := c.effectiveTemperature(); got == nil || *got != 0.2 {
		t.Fatalf("gpt-4o default temperature = %v, want 0.2", got)
	}
	override := 0.7
	c.SetTemperature(&override)
	if got := c.effectiveTemperature(); got == nil || *got != 0.7 {
		t.Fatalf("gpt-4o overridden temperature = %v, want 0.7", got)
	}
}
