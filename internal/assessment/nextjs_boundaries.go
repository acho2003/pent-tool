package assessment

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// NextjsBoundaryApproval opts into one controlled cache, redirect or fetch test.
// A callback destination is authorized only by the existing approved scope.
type NextjsBoundaryApproval struct {
	ID            string `json:"id"`
	TargetID      string `json:"target_id"`
	Kind          string `json:"kind"`
	FixtureRef    string `json:"fixture_ref"`
	OwnerIdentity string `json:"owner_identity,omitempty"`
	Identity      string `json:"identity"`
}

func normalizeNextjsBoundaryApprovals(values []NextjsBoundaryApproval) []NextjsBoundaryApproval {
	result := slices.Clone(values)
	for i := range result {
		a := &result[i]
		a.ID = strings.TrimSpace(a.ID)
		a.TargetID = strings.TrimSpace(a.TargetID)
		a.Kind = strings.ToLower(strings.TrimSpace(a.Kind))
		a.FixtureRef = strings.ToLower(strings.TrimSpace(a.FixtureRef))
		a.OwnerIdentity = strings.TrimSpace(a.OwnerIdentity)
		a.Identity = strings.TrimSpace(a.Identity)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].TargetID+"\x00"+result[i].ID < result[j].TargetID+"\x00"+result[j].ID
	})
	return result
}

// ValidateNextjsBoundaryApprovals is also enforced by direct native callers.
func ValidateNextjsBoundaryApprovals(cfg AssessmentConfig) []Problem {
	if len(cfg.NextjsBoundaryApprovals) == 0 {
		return nil
	}
	var problems []Problem
	add := func(message string) { problems = append(problems, blocking("nextjs_boundary.approval", message)) }
	if !cfg.TestEnvironment || (cfg.Mode != ModeGrayBox && cfg.Mode != ModeWhiteBox) || cfg.WorkflowVersion != "unified-v1" {
		add("Controlled boundary probes require a declared test environment, Gray/White Box mode, and the expanded workflow")
	}
	if !slices.Contains(cfg.Types, TypeWebApplication) && !slices.Contains(cfg.Types, TypeAPI) {
		add("Boundary probes require a web/API assessment")
	}
	if len(cfg.NextjsBoundaryApprovals) > 20 {
		add("At most 20 controlled boundary probes may be approved")
	}
	seen := map[string]bool{}
	for _, a := range cfg.NextjsBoundaryApprovals {
		key := a.TargetID + "\x00" + a.ID
		if !nextjsApprovalID.MatchString(a.ID) || !validFixtureRef(a.FixtureRef) || seen[key] {
			add("Boundary probes require a unique bounded ID and manifest fixture reference")
		}
		seen[key] = true
		if !slices.ContainsFunc(cfg.Targets, func(t Target) bool { return t.ID == a.TargetID && t.Kind == KindURL }) {
			add("Boundary probes require an explicitly supplied URL target")
		}
		bound := func(identity string) bool {
			return slices.ContainsFunc(cfg.Access, func(b AccessBinding) bool {
				if b.Identity != identity || !slices.Contains(b.TargetIDs, a.TargetID) || b.CredentialID == "" {
					return false
				}
				switch b.Kind {
				case AccessApplicationHeaders, AccessApplicationCookies, AccessBearerToken, AccessAPIKey, AccessFormLogin:
					return true
				}
				return false
			})
		}
		if a.Identity != "anonymous" && !bound(a.Identity) {
			add(fmt.Sprintf("Boundary identity %q is not bound to its target", a.Identity))
		}
		switch a.Kind {
		case "cache":
			if a.OwnerIdentity == "" || a.OwnerIdentity == "anonymous" || a.OwnerIdentity == a.Identity || !bound(a.OwnerIdentity) {
				add("Cache probes require an allowed owner and a different denied identity")
			}
		case "redirect", "proxy":
			if a.OwnerIdentity != "" {
				add("URL probes do not use an owner identity")
			}
		default:
			add("Boundary kind must be cache, redirect, or proxy")
		}
	}
	return problems
}
