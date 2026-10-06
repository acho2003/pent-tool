package scanner

import (
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"testing"
)

func TestAdditionalIdentityDiscoveryNeverFallsBackToPrimaryCredentials(t *testing.T) {
	cfg := Config{AssessmentAuthContexts: []AuthContext{
		{ID: AuthenticationContextID("app", "primary"), Identity: "primary", TargetID: "app", Primary: true, State: assessment.StateVerified, Headers: []string{"Authorization: Bearer primary-secret"}},
		{ID: AuthenticationContextID("app", "failed"), Identity: "failed", TargetID: "app", State: assessment.StateFailed},
		{ID: AuthenticationContextID("other", "other"), Identity: "other", TargetID: "other", State: assessment.StateVerified, Headers: []string{"Authorization: Bearer other-secret"}},
	}}
	req := Request{Target: "https://app.test/", Scope: "discovery:app", TargetAuth: "Authorization: Bearer primary-secret", ScanDir: t.TempDir()}
	surface := NewSeedAttackSurface("app:app", req.Target)
	runs := discoverAdditionalIdentities(t.Context(), "app", req, cfg, surface)
	if len(runs) != 1 || runs[0].AuthIdentity != "failed" || runs[0].Status != "skipped" || runs[0].ArtifactPath != "" || len(surface.DiscoveryGaps) != 1 {
		t.Fatalf("failed identity gained another session: %+v gaps=%v", runs, surface.DiscoveryGaps)
	}
}

func TestIdentityDiscoveryProofCountsOnlyItsOwnArtifact(t *testing.T) {
	contextID := AuthenticationContextID("app", "reader")
	endpoint, _ := requestVariantEndpoint("app:app", "https://app.test/api/read", "GET", "", "", true, contextID)
	endpoint.ObservationKind = "observed"
	endpoint.Provenance = []EndpointProvenance{{Tool: "browser", Artifact: "attempt-one/browser.jsonl", Authenticated: true}}
	surface := AttackSurface{Scope: "app:app", Endpoints: []AttackSurfaceEndpoint{endpoint}}
	runs := []Run{{Scanner: "browser", AuthIdentity: "reader", AuthContextID: contextID, ArtifactPath: "attempt-one/browser.jsonl", AttemptID: "one"}, {Scanner: "browser", AuthIdentity: "reader", AuthContextID: contextID, ArtifactPath: "attempt-two/browser.jsonl", AttemptID: "two"}}
	proof := BuildCoverageProof([]AttackSurface{surface}, runs)
	if len(proof.IdentityDiscovery) != 2 || proof.IdentityDiscovery[0].ObservedRequests != 1 || proof.IdentityDiscovery[1].ObservedRequests != 0 {
		t.Fatalf("another attempt credited observations: %+v", proof.IdentityDiscovery)
	}
}
