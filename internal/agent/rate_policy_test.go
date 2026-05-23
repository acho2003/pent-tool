package agent

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

func TestEffectiveRequestRatePolicy_CustomInstructionOverridesConfig(t *testing.T) {
	policy := EffectiveRequestRatePolicy(
		&config.Config{RateLimitRPS: 10},
		"Run carefully, max 3 requests/sec, and avoid noisy scans.",
	)
	if !policy.Enabled() {
		t.Fatal("expected rate policy")
	}
	if policy.MaxRPS != 3 {
		t.Fatalf("MaxRPS = %v, want 3", policy.MaxRPS)
	}
	if policy.Source != "custom instructions" {
		t.Fatalf("Source = %q, want custom instructions", policy.Source)
	}
}

func TestEffectiveRequestRatePolicy_UsesMostRestrictiveConfig(t *testing.T) {
	policy := EffectiveRequestRatePolicy(
		&config.Config{RateLimitRPS: 2},
		"limit to 5 requests per second",
	)
	if policy.MaxRPS != 2 {
		t.Fatalf("MaxRPS = %v, want 2", policy.MaxRPS)
	}
	if policy.Source != "XALGORIX_RATE_RPS" {
		t.Fatalf("Source = %q, want XALGORIX_RATE_RPS", policy.Source)
	}
}

func TestEffectiveRequestRatePolicy_NormalizesSubOneRPS(t *testing.T) {
	policy := EffectiveRequestRatePolicy(
		&config.Config{RateLimitRPS: 10},
		"max 0.5 requests/sec",
	)
	if policy.MaxRPS != 1 {
		t.Fatalf("MaxRPS = %v, want minimum supported 1", policy.MaxRPS)
	}
	if !strings.Contains(policy.Source, "minimum supported 1 rps") {
		t.Fatalf("Source = %q, want minimum note", policy.Source)
	}
}

func TestRateLimitedChecklistRemovesFastExamples(t *testing.T) {
	policy := EffectiveRequestRatePolicy(
		&config.Config{RateLimitRPS: 10},
		"max 3 requests/sec",
	)
	got := rateLimitedChecklist(defaultChecklist, policy)
	for _, bad := range []string{"-T4", "-rl 50", "-threads 50", "-t 50"} {
		if strings.Contains(got, bad) {
			t.Fatalf("checklist still contains fast flag %q", bad)
		}
	}
	for _, want := range []string{"-rl 3", "--max-rate 3", "--scan-delay 334ms", "-rate 3"} {
		if !strings.Contains(got, want) {
			t.Fatalf("checklist missing %q", want)
		}
	}
}
