package scanner

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func runSupplementalZAPDiscovery(ctx context.Context, targetID string, req Request, cfg Config, surface *AttackSurface, existing []Run, emit EmitFunc, control func(string, context.CancelFunc) func()) []Run {
	contexts := []AuthContext{{TargetID: targetID, Primary: true, Headers: strings.Split(req.TargetAuth, "\n"), Refresh: req.AuthRefresh}}
	for _, auth := range cfg.AssessmentAuthContexts {
		if auth.TargetID == targetID && !auth.Primary {
			contexts = append(contexts, auth)
		}
	}
	var runs []Run
	for _, auth := range contexts {
		request := req
		request.ZAPDiscoveryOnly, request.StructuredDispatch = true, true
		request.Variant = "zap-discovery"
		request.ScanDir = filepath.Join(req.ScanDir, "zap-supplemental")
		request.Scope = "discovery:" + targetID + ":zap"
		if !auth.Primary {
			if auth.State != assessment.StateVerified {
				continue
			}
			applyIdentityRequest(&request, auth)
			request.ScanDir = filepath.Join(request.ScanDir, stableJobPath(auth.ID))
			request.Scope += ":identity:" + auth.ID
		}
		var run Run
		for _, old := range existing {
			if old.Scope == request.Scope && old.Variant == request.Variant && old.PlanFingerprint == req.PlanFingerprint && old.Status == "completed" && old.Completeness != "partial" && VerifyChecksum(old) == nil {
				run = old
				break
			}
		}
		if run.Scanner == "" {
			attempt, err := newAssessmentAttemptID()
			if err != nil {
				surface.DiscoveryGaps = append(surface.DiscoveryGaps, "supplemental ZAP attempt unavailable")
				continue
			}
			request.AttemptID = attempt
			request.ScanDir = filepath.Join(request.ScanDir, attempt)
			for _, endpoint := range surface.Endpoints {
				if endpoint.Method != "GET" || endpoint.State != EndpointStateInScope || endpoint.Kind == "static" {
					continue
				}
				if request.AuthContextID != "" && endpoint.AuthContextID != request.AuthContextID {
					continue
				}
				if request.AuthContextID == "" && endpoint.AuthContextID != "" && endpoint.AuthContextID != inventoryID(surface.Scope, "target-bound") {
					continue
				}
				if allowed, _ := request.AppScope.Allows(endpoint.URL); !allowed {
					continue
				}
				if excluded, _ := request.AppScope.Excluded("GET", endpoint.URL); excluded {
					continue
				}
				request.InputRequests = append(request.InputRequests, ScannerRequestInput{EndpointID: endpoint.ID, URL: endpoint.URL, Method: "GET", AuthContextID: endpoint.AuthContextID, InventoryScope: surface.Scope, Selected: true, Reason: "bounded supplemental discovery seed"})
				request.EndpointTargets = append(request.EndpointTargets, endpoint.URL)
			}
			manifest, err := SaveScannerInputs(request, "zap")
			if err != nil {
				surface.DiscoveryGaps = append(surface.DiscoveryGaps, "supplemental ZAP input manifest unavailable")
				continue
			}
			runCtx, cancel := context.WithCancel(ctx)
			unregister := func() {}
			if control != nil {
				unregister = control(attempt, cancel)
			}
			discoveryCfg := cfg
			if discoveryCfg.ZAPTimeout <= 0 || discoveryCfg.ZAPTimeout > 5*time.Minute {
				discoveryCfg.ZAPTimeout = 5 * time.Minute
			}
			taggedEmit := func(event Event) {
				if emit == nil {
					return
				}
				if event.Type == "scanner_completed" || event.Type == "scanner_failed" {
					return
				}
				if event.Run.Scanner != "" {
					event.Run.Scope, event.Run.AttemptID, event.Run.PlanFingerprint, event.Run.Variant = request.Scope, attempt, req.PlanFingerprint, request.Variant
					event.Run.Stage = StageCrawl
					event.Run.AuthContextID, event.Run.AuthIdentity, event.Run.AuthRole = request.AuthContextID, request.AuthIdentity, request.AuthRole
				}
				emit(event)
			}
			run = runAttempt(runCtx, zapRunner{}, request, discoveryCfg, taggedEmit)
			if runCtx.Err() == context.Canceled {
				run.Status, run.ExecutionOutcome, run.Outcome, run.Completeness = "cancelled", "CANCELLED", "PARTIAL", "partial"
			}
			cancel()
			unregister()
			run.InputManifestPath, run.AttemptID, run.PlanFingerprint, run.Variant = manifest, attempt, req.PlanFingerprint, request.Variant
			run.Scope, run.AuthContextID, run.AuthIdentity, run.AuthRole = request.Scope, request.AuthContextID, request.AuthIdentity, request.AuthRole
			run.Authenticated = request.TargetAuth != "" && run.AuthState == assessment.StateVerified
		}
		run.Stage, run.WorkflowVersion = StageCrawl, req.WorkflowVersion
		run = finalizeRun(run)
		if parsed, err := ParseKatanaAttackSurfaceScoped(run.ArtifactPath, surface.Scope, surface.Target, run.Authenticated, req.AppScope); err == nil {
			byID := map[string]int{}
			for i := range surface.Endpoints {
				byID[surface.Endpoints[i].ID] = i
			}
			for _, endpoint := range parsed.Endpoints {
				endpoint.Provenance = append(endpoint.Provenance, EndpointProvenance{Tool: "zap", Source: "supplemental-discovery", Artifact: run.ArtifactPath, Authenticated: endpoint.ObservedWithAuth})
				mergeSurfaceEndpoint(surface, byID, endpoint)
			}
			surface.RawCount += parsed.RawCount
		} else {
			surface.DiscoveryGaps = append(surface.DiscoveryGaps, "supplemental ZAP produced no usable discovery artifact")
		}
		if run.Status != "completed" || run.Completeness == "partial" {
			surface.DiscoveryGaps = append(surface.DiscoveryGaps, "supplemental ZAP: "+run.Reason)
		}
		if emit != nil {
			kind := "scanner_completed"
			if run.Status != "completed" {
				kind = "scanner_failed"
			}
			emit(Event{Type: kind, Scanner: "zap", Run: run})
		}
		runs = append(runs, run)
	}
	return runs
}
