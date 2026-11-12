package web

import (
	"slices"
	"sort"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

// otherTargetsService groups findings and runs that belong to no declared
// service (ungrouped targets, or scopes that cannot be attributed).
const otherTargetsService = "Other targets"

// reportService is one microservice row of the services overview: its
// targets, active finding counts by severity, authentication state and run
// outcomes, all derived from the saved plan, runs and findings.
type reportService struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Targets   []string       `json:"targets"`
	Counts    map[string]int `json:"counts"`
	Findings  int            `json:"findings"`
	Auth      string         `json:"auth"`
	Completed int            `json:"completed"`
	Failed    int            `json:"failed"`
	Skipped   int            `json:"skipped"`
}

// scopeTargetID maps a run or finding scope ("app:<id>", "host:<id>",
// "assessment:<id>", "discovery:<id>") to a target ID of the config.
func scopeTargetID(scope string, cfg assessment.AssessmentConfig) string {
	_, rest, ok := strings.Cut(scope, ":")
	if !ok {
		return ""
	}
	// "app:<id>", "host:<id>", or a stage scope with a suffix such as
	// "discovery:<id>:zap". Target IDs may themselves contain ":", so the
	// longest matching prefix of rest wins.
	best := ""
	for _, target := range cfg.Targets {
		if (rest == target.ID || strings.HasPrefix(rest, target.ID+":")) && len(target.ID) > len(best) {
			best = target.ID
		}
	}
	return best
}

// serviceIndex maps target IDs to the position of their service.
func serviceIndex(cfg assessment.AssessmentConfig) map[string]int {
	index := map[string]int{}
	for i, service := range cfg.Services {
		for _, id := range service.TargetIDs {
			index[id] = i
		}
	}
	return index
}

// buildReportServices returns the services overview, or nil when the
// assessment declares no services (legacy and single-application scans).
func buildReportServices(plan *scanner.AssessmentPlan, runs []scanner.Run, vulns []VulnSummary) []reportService {
	if plan == nil || len(plan.Config.Services) == 0 {
		return nil
	}
	cfg := plan.Config
	index := serviceIndex(cfg)
	targetValues := map[string]string{}
	for _, target := range cfg.Targets {
		targetValues[target.ID] = target.Value
	}
	out := make([]reportService, 0, len(cfg.Services)+1)
	for _, service := range cfg.Services {
		row := reportService{ID: service.ID, Name: service.Name, Counts: map[string]int{}}
		for _, id := range service.TargetIDs {
			row.Targets = append(row.Targets, targetValues[id])
		}
		out = append(out, row)
	}
	other := reportService{ID: "", Name: otherTargetsService, Counts: map[string]int{}}
	for _, target := range cfg.Targets {
		if _, grouped := index[target.ID]; !grouped {
			other.Targets = append(other.Targets, target.Value)
		}
	}
	rowFor := func(scope string) *reportService {
		if i, ok := index[scopeTargetID(scope, cfg)]; ok {
			return &out[i]
		}
		return &other
	}
	for _, v := range vulns {
		row := rowFor(v.Scope)
		row.Findings++
		row.Counts[normalizeServiceSeverity(v.Severity)]++
	}
	for _, run := range runs {
		scope := scanner.FindingScope(run)
		if strings.HasPrefix(scope, "recon:") || run.Scanner == "auth" {
			continue
		}
		row := rowFor(scope)
		switch run.Status {
		case "completed":
			row.Completed++
		case "failed", "cancelled":
			row.Failed++
		default:
			row.Skipped++
		}
	}
	for i := range out {
		out[i].Auth = serviceAuthState(plan, cfg.Services[i])
	}
	if len(other.Targets) > 0 || other.Findings > 0 || other.Completed+other.Failed+other.Skipped > 0 {
		other.Auth = "n/a"
		out = append(out, other)
	}
	return out
}

func normalizeServiceSeverity(severity string) string {
	switch s := strings.ToLower(strings.TrimSpace(severity)); s {
	case "critical", "high", "medium", "low":
		return s
	default:
		return "info"
	}
}

// serviceAuthState summarizes web authentication across a service's URL
// targets from the recorded capability states. It never upgrades a state:
// an applied but unverified token stays "token applied, not verified".
func serviceAuthState(plan *scanner.AssessmentPlan, service assessment.Service) string {
	states := []string{}
	for _, capability := range plan.Capabilities {
		if capability.Capability != assessment.CapAuthWeb || !slices.Contains(service.TargetIDs, capability.TargetID) {
			continue
		}
		label := ""
		switch capability.State {
		case assessment.StateVerified:
			label = "verified"
		case assessment.StateAvailable, assessment.StateDeclared:
			label = "token applied, not verified"
			if capability.AccessKind != assessment.AccessTokenLogin {
				label = "not verified"
			}
		case assessment.StateFailed:
			label = "failed"
		case assessment.StateExpired:
			label = "expired"
		case assessment.StateUnavailable:
			label = "unavailable"
		}
		if label != "" && !slices.Contains(states, label) {
			states = append(states, label)
		}
	}
	if len(states) == 0 {
		return "not configured"
	}
	sort.Strings(states)
	return strings.Join(states, ", ")
}

// orderScopesByService stably reorders report scopes so each service's
// scopes are adjacent, in declared service order; ungrouped scopes follow.
// It also labels each scope with its service name.
func orderScopesByService(scopes []reportScope, plan *scanner.AssessmentPlan) {
	if plan == nil || len(plan.Config.Services) == 0 {
		return
	}
	cfg := plan.Config
	index := serviceIndex(cfg)
	position := func(scope reportScope) int {
		if i, ok := index[scopeTargetID(scope.ID, cfg)]; ok {
			return i
		}
		return len(cfg.Services)
	}
	for i := range scopes {
		if p := position(scopes[i]); p < len(cfg.Services) {
			scopes[i].Service = cfg.Services[p].Name
		}
	}
	sort.SliceStable(scopes, func(a, b int) bool { return position(scopes[a]) < position(scopes[b]) })
}
