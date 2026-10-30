package assessment

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// NextjsActionApproval authorizes only the enumerated one-shot action cases.
// Its manifest and request/cleanup bodies live in the content-addressed store.
type NextjsActionApproval struct {
	ID            string             `json:"id"`
	TargetID      string             `json:"target_id"`
	FixtureRef    string             `json:"fixture_ref"`
	OwnerIdentity string             `json:"owner_identity"`
	Cases         []NextjsActionCase `json:"cases"`
}

type NextjsActionCase struct {
	ID          string `json:"id"`
	Identity    string `json:"identity"`
	Expect      string `json:"expect"`
	CrossOrigin bool   `json:"cross_origin,omitempty"`
}

var nextjsApprovalID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func normalizeNextjsActionApprovals(values []NextjsActionApproval) []NextjsActionApproval {
	result := slices.Clone(values)
	for i := range result {
		a := &result[i]
		a.ID, a.TargetID, a.OwnerIdentity = strings.TrimSpace(a.ID), strings.TrimSpace(a.TargetID), strings.TrimSpace(a.OwnerIdentity)
		a.FixtureRef = strings.ToLower(strings.TrimSpace(a.FixtureRef))
		a.Cases = slices.Clone(a.Cases)
		for j := range a.Cases {
			c := &a.Cases[j]
			c.ID, c.Identity, c.Expect = strings.TrimSpace(c.ID), strings.TrimSpace(c.Identity), strings.ToLower(strings.TrimSpace(c.Expect))
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].TargetID+"\x00"+result[i].ID < result[j].TargetID+"\x00"+result[j].ID
	})
	return result
}

// ValidateNextjsActionApprovals also protects direct native runner callers.
func ValidateNextjsActionApprovals(cfg AssessmentConfig) []Problem {
	if len(cfg.NextjsActionApprovals) == 0 {
		return nil
	}
	var problems []Problem
	add := func(code, message string) { problems = append(problems, blocking("nextjs_action."+code, message)) }
	if !cfg.TestEnvironment || (cfg.Mode != ModeGrayBox && cfg.Mode != ModeWhiteBox) {
		add("environment", "Server Action campaigns require a declared test environment and Gray Box or White Box mode")
	}
	if cfg.WorkflowVersion != "unified-v1" {
		add("workflow", "Server Action campaigns require the expanded unified-v1 workflow")
	}
	if !slices.Contains(cfg.Types, TypeWebApplication) && !slices.Contains(cfg.Types, TypeAPI) {
		add("type", "Server Action campaigns require a web application or API assessment")
	}
	if len(cfg.NextjsActionApprovals) > 20 {
		add("limit", "At most 20 Server Action campaigns may be approved")
	}
	seen := map[string]bool{}
	for _, a := range cfg.NextjsActionApprovals {
		key := a.TargetID + "\x00" + a.ID
		if !nextjsApprovalID.MatchString(a.ID) || seen[key] || !validFixtureRef(a.FixtureRef) {
			add("approval", "Server Action campaigns require a unique bounded ID and valid manifest fixture reference")
		}
		seen[key] = true
		target := slices.IndexFunc(cfg.Targets, func(t Target) bool { return t.ID == a.TargetID && t.Kind == KindURL })
		if target < 0 {
			add("target", "Server Action campaigns require an explicitly supplied URL target")
		}
		bound := func(name string) bool {
			return slices.ContainsFunc(cfg.Access, func(b AccessBinding) bool {
				if b.Identity != name || !slices.Contains(b.TargetIDs, a.TargetID) || b.CredentialID == "" {
					return false
				}
				switch b.Kind {
				case AccessApplicationHeaders, AccessApplicationCookies, AccessBearerToken, AccessAPIKey, AccessFormLogin:
					return true
				}
				return false
			})
		}
		if a.OwnerIdentity == "" || a.OwnerIdentity == "anonymous" || !bound(a.OwnerIdentity) {
			add("owner", "The campaign owner must be a named web identity bound to its exact target")
		}
		if len(a.Cases) < 2 || len(a.Cases) > 8 {
			add("cases", "A Server Action campaign must enumerate between two and eight one-shot cases")
			continue
		}
		first := a.Cases[0]
		if first.Identity != a.OwnerIdentity || first.Expect != "allow" || first.CrossOrigin {
			add("baseline", "The first case must allow the owner from the same origin")
		}
		ids := map[string]bool{}
		variants := map[string]bool{}
		for i, c := range a.Cases {
			if !nextjsApprovalID.MatchString(c.ID) || ids[c.ID] {
				add("case_id", "Action case IDs must be unique and bounded within the campaign")
			}
			ids[c.ID] = true
			variant := fmt.Sprintf("%s\x00%t", c.Identity, c.CrossOrigin)
			if variants[variant] {
				add("case_duplicate", "Each action identity/origin variant may be approved only once in a campaign")
			}
			variants[variant] = true
			if c.CrossOrigin && c.Identity != a.OwnerIdentity {
				add("origin_identity", "Origin cases must use the owner identity so origin and authorization failures are not conflated")
			}
			if c.Identity != "anonymous" && !bound(c.Identity) {
				add("identity", fmt.Sprintf("Action case identity %q is not bound to the campaign target", c.Identity))
			}
			if i > 0 && (c.Expect != "deny" || (c.Identity == a.OwnerIdentity && !c.CrossOrigin)) {
				add("expectation", "Cases after the baseline must deny a different identity or a cross-origin request")
			}
		}
	}
	return problems
}
