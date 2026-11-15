package web

import (
	"context"

	"github.com/xalgord/xalgorix/v4/internal/credentials"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

// PrepareHeadlessAuth runs the assessment authentication-preparation flow for a
// one-shot headless run (for example a CLI shared-token scan) against the given
// transient vault, without constructing a full dashboard server or touching the
// on-disk credential store.
//
// It returns the per-target authenticated header lines to assign to
// pipeline.Config.AssessmentAuthHeaders, exactly as the web scan path does. The
// plan's capability evidence and per-job execution modes are updated in place,
// so the caller's plan reflects per-service verified/available/failed state.
func PrepareHeadlessAuth(ctx context.Context, vault *credentials.Vault, plan *scanner.AssessmentPlan) (map[string][]string, error) {
	s := &Server{vaultOverride: vault}
	return s.prepareAssessmentAuthentication(ctx, plan)
}
