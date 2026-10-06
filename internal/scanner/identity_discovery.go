package scanner

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

// The primary crawl retains its existing semantics. Additional identities use
// independent browser profiles and verifiers, never another identity's session.
func discoverAdditionalIdentities(ctx context.Context, targetID string, req Request, cfg Config, surface *AttackSurface) []Run {
	var runs []Run
	for _, auth := range cfg.AssessmentAuthContexts {
		if auth.TargetID != targetID || auth.Primary {
			continue
		}
		request := req
		request.AuthContextID = auth.ID
		request.Scope = req.Scope + ":identity:" + auth.ID
		request.ScanDir = filepath.Join(req.ScanDir, "identities", stableJobPath(auth.ID))
		request.TargetAuth = strings.Join(auth.Headers, "\n")
		request.AuthRefresh, request.BrowserStorage = auth.Refresh, auth.BrowserStorage
		run := Run{Scanner: "browser", Target: req.Target, Scope: request.Scope, Stage: StageCrawl, Status: "skipped", AuthContextID: auth.ID, AuthIdentity: auth.Identity, AuthRole: auth.Role, AuthState: auth.State, StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		if auth.State != assessment.StateVerified || auth.Refresh == nil || len(auth.Headers) == 0 || !validAuthenticationContextID(auth.ID) {
			run.Reason, run.GapKind = "identity browser discovery requires its own verified target-bound credential", GapAuthFailed
		} else {
			run = DiscoverBrowser(ctx, request, cfg)
			run.Stage, run.AuthIdentity, run.AuthRole = StageCrawl, auth.Identity, auth.Role
			if parsed, err := ParseKatanaAttackSurfaceScoped(run.ArtifactPath, surface.Scope, surface.Target, run.Authenticated, req.AppScope); err == nil {
				byID := map[string]int{}
				for i := range surface.Endpoints {
					byID[surface.Endpoints[i].ID] = i
				}
				for _, endpoint := range parsed.Endpoints {
					endpoint.Provenance = append(endpoint.Provenance, EndpointProvenance{Tool: "browser", Artifact: run.ArtifactPath, Authenticated: run.Authenticated})
					mergeSurfaceEndpoint(surface, byID, endpoint)
				}
				surface.RawCount += parsed.RawCount
			} else {
				surface.DiscoveryGaps = append(surface.DiscoveryGaps, fmt.Sprintf("identity %s browser produced no usable inventory", auth.Identity))
			}
		}
		if run.Status != "completed" || run.Completeness == "partial" {
			surface.DiscoveryGaps = append(surface.DiscoveryGaps, "identity "+auth.Identity+": "+run.Reason)
		}
		runs = append(runs, finalizeRun(run))
	}
	return runs
}
