package scanner

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func identityRoutedScanner(name string) bool {
	switch name {
	case "auth", "nuclei", "zap", "wapiti", "dalfox":
		return true
	}
	return false
}

// Role jobs are part of the preview fingerprint, not invented during execution.
// The first identity retains legacy/default request identity for compatibility.
func expandIdentityJobs(cfg assessment.AssessmentConfig, jobs []PlanJob) []PlanJob {
	if cfg.WorkflowVersion != "unified-v1" {
		return jobs
	}
	identities := map[string]map[string]string{}
	for _, binding := range cfg.Access {
		switch binding.Kind {
		case assessment.AccessApplicationHeaders, assessment.AccessApplicationCookies, assessment.AccessBearerToken, assessment.AccessAPIKey, assessment.AccessFormLogin:
		default:
			continue
		}
		for _, target := range binding.TargetIDs {
			if identities[target] == nil {
				identities[target] = map[string]string{}
			}
			identities[target][binding.Identity] = binding.Role
		}
	}
	original := slices.Clone(jobs)
	for target, roles := range identities {
		names := make([]string, 0, len(roles))
		for name := range roles {
			names = append(names, name)
		}
		slices.Sort(names)
		if len(names) < 2 {
			continue
		}
		for _, identity := range names[1:] {
			id := AuthenticationContextID(target, identity)
			for _, job := range original {
				if job.TargetID != target || !identityRoutedScanner(job.Scanner) {
					continue
				}
				job.ID += ":identity:" + id
				job.Variant += ":identity:" + id
				job.AuthContextID, job.AuthIdentity, job.AuthRole = id, identity, roles[identity]
				jobs = append(jobs, job)
			}
		}
	}
	return jobs
}

func (p *Pipeline) refreshIdentity(ctx context.Context, targetID, contextID string) (AuthContext, error) {
	for i := range p.Config.AssessmentAuthContexts {
		auth := &p.Config.AssessmentAuthContexts[i]
		if auth.TargetID != targetID || auth.ID != contextID {
			continue
		}
		if auth.State != assessment.StateVerified || auth.Refresh == nil || len(auth.Headers) == 0 {
			return *auth, fmt.Errorf("named identity is not verified")
		}
		headers, err := auth.Refresh(ctx, slices.Clone(auth.Headers))
		if err != nil || len(headers) == 0 {
			auth.State = assessment.StateExpired
			return *auth, fmt.Errorf("named identity verification expired")
		}
		auth.Headers = slices.Clone(headers)
		return *auth, nil
	}
	return AuthContext{}, fmt.Errorf("named identity has no target-bound credential")
}

func applyIdentityRequest(req *Request, auth AuthContext) {
	req.AuthContextID, req.AuthIdentity, req.AuthRole = auth.ID, auth.Identity, auth.Role
	req.TargetAuth = strings.Join(auth.Headers, "\n")
	req.AuthRefresh, req.BrowserStorage = auth.Refresh, auth.BrowserStorage
	req.AuthKind = "HTTP headers"
}

func refreshRunIdentity(ctx context.Context, p *Pipeline, job PlanJob) error {
	if job.AuthContextID != "" {
		_, err := p.refreshIdentity(ctx, job.TargetID, job.AuthContextID)
		return err
	}
	return p.refreshAssessmentWebAuth(ctx, job.TargetID)
}

// Resolved read operations are explicit schema seeds for each configured role.
// They remain seeds until native traffic is observed; they are never live-host
// or authentication evidence, and external schema servers remain candidates.
func addIdentitySchemaSeeds(surface *AttackSurface, targetID string, contexts []AuthContext) {
	if surface == nil {
		return
	}
	seeds := slices.Clone(surface.Endpoints)
	indexes := map[string]int{}
	for i := range surface.Endpoints {
		indexes[surface.Endpoints[i].ID] = i
	}
	bound, err := assessment.ParseApprovedOrigin("", surface.Target)
	if err != nil {
		return
	}
	for _, auth := range contexts {
		if auth.TargetID != targetID || auth.Primary || auth.State != assessment.StateVerified || !validAuthenticationContextID(auth.ID) {
			continue
		}
		for _, seed := range seeds {
			if seed.ObservationKind != "schema" || seed.State != EndpointStateInScope || seed.AuthContextID != "" || (seed.Method != "GET" && seed.Method != "HEAD") {
				continue
			}
			origin, err := assessment.ParseApprovedOrigin("", seed.URL)
			if err != nil || origin.Origin() != bound.Origin() {
				continue
			}
			endpoint, ok := requestVariantEndpoint(surface.Scope, seed.URL, seed.Method, "", "", true, auth.ID)
			if !ok {
				continue
			}
			endpoint.Kind, endpoint.ObservationKind = seed.Kind, "schema"
			endpoint.ObservedWithAuth, endpoint.RequiresAuth = false, nil
			endpoint.Sources = slices.Clone(seed.Sources)
			endpoint.Provenance = slices.Clone(seed.Provenance)
			endpoint.Parameters = slices.Clone(seed.Parameters)
			endpoint.HasParameters, endpoint.HasForm = seed.HasParameters, seed.HasForm
			endpoint.State, endpoint.StateReason = EndpointStateInScope, "resolved schema seed for separately configured identity"
			if _, exists := indexes[endpoint.ID]; !exists {
				mergeSurfaceEndpoint(surface, indexes, endpoint)
			}
		}
	}
}
