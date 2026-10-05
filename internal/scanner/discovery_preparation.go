package scanner

import (
	"slices"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

type DiscoveryAction struct {
	Scanner     string `json:"scanner"`
	Description string `json:"description"`
}

func proposedDiscoveryActions(cfg assessment.AssessmentConfig, kind string) []DiscoveryAction {
	actions := []DiscoveryAction{}
	if kind == "host" {
		actions = append(actions, DiscoveryAction{"dnsx", "Resolve this hostname and record DNS/wildcard evidence"})
	}
	if slices.Contains(cfg.Types, assessment.TypeWebApplication) || slices.Contains(cfg.Types, assessment.TypeAPI) {
		description := "Probe this exact HTTP(S) origin and path without following redirects"
		if kind == "host" {
			description = "Probe this hostname on HTTP port 80 and HTTPS port 443 without following redirects"
		}
		actions = append(actions, DiscoveryAction{"httpx", description})
	}
	if kind == "host" && (cfg.ScannerSelection.Mode != "custom" || slices.Contains(cfg.ScannerSelection.Variants, "nmap")) {
		actions = append(actions, DiscoveryAction{"nmap", "TCP connect and service discovery using the configured Nmap default port policy"})
	}
	return actions
}

// These jobs are part of the explicitly approved destination preparation,
// rather than vulnerability scanner choices. Do not upgrade original targets
// or legacy plans when an operator turns the feature flag on.
func ensureApprovedDiscoveryPreparation(plan *AssessmentPlan, input PlanInput) {
	cfg := plan.Config
	if cfg.WorkflowVersion != "unified-v1" || cfg.ParentPlanFingerprint == "" {
		return
	}
	for _, target := range cfg.Targets {
		if !strings.HasPrefix(target.ID, "discovered-") {
			continue
		}
		kind := "origin"
		if target.Kind == assessment.KindHost {
			kind = "host"
		} else if target.Kind != assessment.KindURL {
			continue
		}
		for _, action := range proposedDiscoveryActions(cfg, kind) {
			if action.Scanner == "nmap" {
				continue
			} // Existing configured network jobs retain their policy.
			available := action.Scanner == "httpx"
			if value, known := input.Availability[action.Scanner]; known {
				available = value
			}
			state := PlanSelected
			reason := action.Description
			if !available {
				state = PlanUnavailable
				reason = "approved discovery prerequisite executable is unavailable"
			}
			typ := assessment.TypeNetwork
			if slices.Contains(cfg.Types, assessment.TypeWebApplication) {
				typ = assessment.TypeWebApplication
			} else if slices.Contains(cfg.Types, assessment.TypeAPI) {
				typ = assessment.TypeAPI
			}
			replaced := false
			for i := range plan.Decisions {
				decision := &plan.Decisions[i]
				if decision.Scanner == action.Scanner && decision.TargetID == target.ID {
					decision.State, decision.ReasonCode, decision.Reason = state, "discovery.approved_preparation", reason
					replaced = true
				}
			}
			if !replaced {
				plan.Decisions = append(plan.Decisions, PlanDecision{Scanner: action.Scanner, TargetID: target.ID, Types: []assessment.Type{typ}, State: state, ReasonCode: "discovery.approved_preparation", Reason: reason})
			}
			if !slices.ContainsFunc(plan.Jobs, func(job PlanJob) bool { return job.Scanner == action.Scanner && job.TargetID == target.ID }) {
				plan.Jobs = append(plan.Jobs, PlanJob{ID: action.Scanner + ":" + target.ID + ":" + action.Scanner, Scanner: action.Scanner, Variant: action.Scanner, TargetID: target.ID, Target: target.Value, State: state, Reason: reason, AssessmentType: typ, AssessmentTypes: []assessment.Type{typ}})
			}
		}
	}
}
