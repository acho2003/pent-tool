package web

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

// Verify every named identity independently. The existing single-context
// adapters receive the primary context only; credentials are never concatenated
// across roles. Comparisons consume the separately verified runtime contexts.
func (s *Server) prepareAssessmentAuthentication(ctx context.Context, plan *scanner.AssessmentPlan) (map[string][]string, error) {
	if plan == nil || len(plan.Config.Access) == 0 {
		return map[string][]string{}, nil
	}
	groups := map[string][]assessment.AccessBinding{}
	for _, binding := range plan.Config.Access {
		if webAuthenticationKind(binding.Kind) {
			groups[binding.Identity] = append(groups[binding.Identity], binding)
		}
	}
	if len(groups) <= 1 {
		plan.AuthContexts = nil
		return s.prepareSingleContextAuthentication(ctx, plan)
	}
	identities := make([]string, 0, len(groups))
	for identity := range groups {
		identities = append(identities, identity)
	}
	slices.Sort(identities)
	primaryHeaders := map[string][]string{}
	chosen := map[string]bool{}
	plan.AuthContexts = nil
	for _, identity := range identities {
		isolated := *plan
		isolated.AuthContexts = nil
		isolated.Config = plan.Config
		isolated.Config.Access = groups[identity]
		isolated.Jobs = slices.Clone(plan.Jobs)
		isolated.Decisions = slices.Clone(plan.Decisions)
		isolated.Capabilities = assessment.DeriveCapabilities(isolated.Config)
		headers, err := s.prepareSingleContextAuthentication(ctx, &isolated)
		if err != nil {
			return nil, err
		}
		refreshers, err := s.assessmentAuthRefreshers(&isolated, headers)
		if err != nil {
			return nil, err
		}
		storage := s.assessmentBrowserStorage(&isolated)
		targets := map[string]string{}
		for _, binding := range groups[identity] {
			for _, targetID := range binding.TargetIDs {
				if role, ok := targets[targetID]; ok && role != binding.Role {
					return nil, fmt.Errorf("one authentication identity cannot declare conflicting roles on the same target")
				}
				targets[targetID] = binding.Role
			}
		}
		targetIDs := make([]string, 0, len(targets))
		for targetID := range targets {
			targetIDs = append(targetIDs, targetID)
		}
		slices.Sort(targetIDs)
		for _, targetID := range targetIDs {
			state := assessment.StateFailed
			for _, capability := range isolated.Capabilities {
				if capability.Capability == assessment.CapAuthWeb && capability.TargetID == targetID && blockingAuthState(capability.State) {
					state = capability.State
					break
				}
			}
			reason := blockingAuthReason(isolated.Capabilities, targetID)
			if len(headers[targetID]) > 0 {
				state, reason = assessment.StateVerified, "identity passed its target-bound verification and anonymous negative control"
			}
			auth := scanner.AuthContext{ID: scanner.AuthenticationContextID(targetID, identity), TargetID: targetID, Identity: identity, Role: targets[targetID], Primary: !chosen[targetID], State: state, Reason: reason, Headers: slices.Clone(headers[targetID]), Refresh: refreshers[targetID], BrowserStorage: storage[targetID]}
			plan.AuthContexts = append(plan.AuthContexts, auth)
			if auth.Primary {
				chosen[targetID] = true
				primaryHeaders[targetID] = slices.Clone(headers[targetID])
				for i := range plan.Jobs {
					if plan.Jobs[i].TargetID == targetID && plan.Jobs[i].AuthContextID == "" {
						plan.Jobs[i] = isolated.Jobs[i]
					}
				}
				for i := range plan.Decisions {
					if plan.Decisions[i].TargetID == targetID {
						plan.Decisions[i] = isolated.Decisions[i]
					}
				}
			}
			for i := range plan.Jobs {
				if plan.Jobs[i].TargetID == targetID && plan.Jobs[i].AuthContextID == auth.ID {
					plan.Jobs[i] = isolated.Jobs[i]
				}
			}
			for i := range plan.Capabilities {
				capability := &plan.Capabilities[i]
				if capability.Capability != assessment.CapAuthWeb || capability.TargetID != targetID {
					continue
				}
				for _, binding := range groups[identity] {
					if capability.ReferenceID == binding.CredentialID && slices.Contains(binding.TargetIDs, targetID) {
						capability.State, capability.Reason = state, strings.TrimSpace(reason)
						if state == assessment.StateVerified || state == assessment.StateFailed {
							capability.Provenance = authVerificationProvenance
						}
					}
				}
			}
		}
	}
	return primaryHeaders, nil
}
