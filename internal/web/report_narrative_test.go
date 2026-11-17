package web

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

func TestReportRiskNarrativeNeverClaimsStrongPostureAndFlagsIncompleteScanners(t *testing.T) {
	clean := reportRiskNarrative("https://app.test", 2, 0, 0, 0, 1, 1, "LOW", 1.5, 0)
	if strings.Contains(strings.ToLower(clean), "strong security posture") {
		t.Fatalf("narrative claims a strong posture: %q", clean)
	}
	if !strings.Contains(clean, "not evidence that none exist") {
		t.Fatalf("low-only narrative lacks the automated-scan caveat: %q", clean)
	}
	if strings.Contains(clean, "did not complete") {
		t.Fatalf("complete run mentions incomplete scanners: %q", clean)
	}

	partial := reportRiskNarrative("https://app.test", 0, 0, 0, 0, 0, 0, "INFO", 0, 2)
	if !strings.Contains(partial, "2 scanner runs did not complete") {
		t.Fatalf("incomplete scanners not reported in the summary: %q", partial)
	}
	high := reportRiskNarrative("https://app.test", 1, 0, 1, 0, 0, 0, "HIGH", 7.5, 1)
	if !strings.Contains(high, "1 scanner run did not complete") || !strings.Contains(high, "Immediate remediation") {
		t.Fatalf("high narrative lost severity or incompleteness: %q", high)
	}
}

func TestIncompleteScannerRunsIgnoresSkippedAndNotApplicable(t *testing.T) {
	runs := []scanner.Run{{Status: "completed"}, {Status: "skipped"}, {Status: "not_applicable"}, {Status: "failed"}, {Status: "timeout"}, {Status: "partial"}, {Status: "cancelled"}}
	if got := incompleteScannerRuns(runs); got != 4 {
		t.Fatalf("incompleteScannerRuns=%d want 4", got)
	}
}
