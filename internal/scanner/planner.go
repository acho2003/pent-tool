package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

type PlanState string

const (
	PlanSelected      PlanState = "selected"
	PlanOptional      PlanState = "optional"
	PlanConditional   PlanState = "conditional"
	PlanUnavailable   PlanState = "unavailable"
	PlanNotApplicable PlanState = "not_applicable"
	PlanSkipped       PlanState = "skipped"
)

type PlanDecision struct {
	Scanner       string            `json:"scanner"`
	TargetID      string            `json:"target_id,omitempty"`
	Types         []assessment.Type `json:"assessment_types,omitempty"`
	State         PlanState         `json:"state"`
	ReasonCode    string            `json:"reason_code"`
	Reason        string            `json:"reason"`
	ExecutionMode string            `json:"execution_mode,omitempty"`
}

type PlanJob struct {
	ID             string          `json:"id"`
	Scanner        string          `json:"scanner"`
	TargetID       string          `json:"target_id"`
	Target         string          `json:"target"`
	AssessmentType assessment.Type `json:"assessment_type"`
	Variant        string          `json:"variant"`
	Dependencies   []string        `json:"dependencies,omitempty"`
	ExecutionMode  string          `json:"execution_mode,omitempty"`
}

type TypeCoverage struct {
	Type   assessment.Type `json:"type"`
	State  string          `json:"state"`
	Reason string          `json:"reason"`
}

type PlanInput struct {
	Config assessment.AssessmentConfig `json:"config"`
	// Availability is an execution capability snapshot, keyed by registry ID.
	// Missing entries use the build's registry default.
	Availability map[string]bool `json:"-"`
}

type AssessmentPlan struct {
	Config          assessment.AssessmentConfig     `json:"config"`
	Capabilities    []assessment.CapabilityEvidence `json:"capabilities"`
	Decisions       []PlanDecision                  `json:"decisions"`
	Jobs            []PlanJob                       `json:"jobs"`
	Coverage        []TypeCoverage                  `json:"coverage"`
	Warnings        []assessment.Problem            `json:"warnings,omitempty"`
	Errors          []assessment.Problem            `json:"errors,omitempty"`
	Fingerprint     string                          `json:"fingerprint"`
	RegistryVersion string                          `json:"registry_version"`
}

// PlanAssessment is a deterministic, side-effect-free plan builder. It never
// probes targets, pulls images, clones repositories, or resolves credentials.
func PlanAssessment(input PlanInput) AssessmentPlan {
	cfg := assessment.Normalize(input.Config)
	plan := AssessmentPlan{Config: cfg, Capabilities: assessment.DeriveCapabilities(cfg), RegistryVersion: "1"}
	problems := assessment.Validate(cfg)
	for _, p := range problems {
		if p.Blocking {
			plan.Errors = append(plan.Errors, p)
		} else {
			plan.Warnings = append(plan.Warnings, p)
		}
	}
	if len(plan.Errors) > 0 {
		plan.Fingerprint = planFingerprint(cfg, plan.Jobs)
		return plan
	}
	defs := ScannerRegistry()
	requestedCustom := cfg.ScannerSelection.Mode == "custom"
	custom := map[string]bool{}
	for _, v := range cfg.ScannerSelection.Variants {
		custom[v] = true
	}
	if requestedCustom && len(custom) == 0 {
		plan.Errors = append(plan.Errors, assessment.Problem{Code: "selection.empty", Message: "custom scanner selection must include at least one registry ID", Blocking: true})
	}
	for _, id := range cfg.ScannerSelection.Variants {
		if _, ok := RegistryEntry(id); !ok {
			plan.Errors = append(plan.Errors, assessment.Problem{Code: "selection.unknown", Message: fmt.Sprintf("unknown scanner variant %q", id), Blocking: true})
		}
	}
	if len(plan.Errors) > 0 {
		plan.Fingerprint = planFingerprint(cfg, plan.Jobs)
		return plan
	}

	for _, def := range defs {
		matchedTargets := make([]assessment.Target, 0)
		for _, target := range cfg.Targets {
			if slices.Contains(def.TargetKinds, target.Kind) {
				matchedTargets = append(matchedTargets, target)
			}
		}
		if len(matchedTargets) == 0 {
			plan.Decisions = append(plan.Decisions, PlanDecision{Scanner: def.ID, State: PlanNotApplicable, ReasonCode: "target_or_type_missing", Reason: "No supplied target and requested assessment type match this scanner."})
			continue
		}
		selected := def.DefaultSelection == "automatic" || def.DefaultSelection == "conditional"
		if requestedCustom {
			selected = custom[def.ID]
		}
		for _, target := range matchedTargets {
			for _, typ := range cfg.Types {
				if !slices.Contains(def.AssessmentTypes, typ) {
					continue
				}
				if !targetSupportsType(target, typ) {
					continue
				}
				state, code, reason := eligibility(def, target, plan.Capabilities, input.Availability)
				if def.ID == "subfinder" && target.Kind == assessment.KindDomain {
					if cfg.SubdomainDiscovery {
						state, code, reason = PlanConditional, "discovery.subdomain_opt_in", "Subdomain discovery was explicitly authorized and will be attempted during preparation."
					} else {
						state, code, reason = PlanOptional, "discovery.subdomain_opt_in_required", "Subdomain discovery is off by default; enable it to authorize enumeration under this domain."
					}
				}
				if requestedCustom && custom[def.ID] && state == PlanOptional && !(def.ID == "subfinder" && !cfg.SubdomainDiscovery) {
					state, code, reason = PlanSelected, "scanner.explicitly_selected", "This optional scanner was explicitly selected by the operator."
				}
				if state == PlanSelected || state == PlanConditional {
					if !selected {
						state, code, reason = PlanSkipped, "selection.customized", "This scanner is applicable but omitted from the custom scanner selection."
					}
				}
				execMode := ""
				if def.SupportsAuthentication && hasCapability(plan.Capabilities, assessment.CapAuthWeb, target.ID, assessment.StateVerified) {
					execMode = "authenticated"
				} else if def.SupportsAuthentication {
					execMode = "unauthenticated"
				}
				plan.Decisions = append(plan.Decisions, PlanDecision{Scanner: def.ID, TargetID: target.ID, Types: []assessment.Type{typ}, State: state, ReasonCode: code, Reason: reason, ExecutionMode: execMode})
				if state == PlanSelected || state == PlanConditional {
					plan.Jobs = append(plan.Jobs, PlanJob{ID: fmt.Sprintf("%s:%s:%s", def.ID, target.ID, typ), Scanner: def.ID, TargetID: target.ID, Target: target.Value, AssessmentType: typ, Variant: def.ID, ExecutionMode: execMode})
				}
			}
		}
		if len(plan.Decisions) == 0 || !slices.ContainsFunc(plan.Decisions, func(d PlanDecision) bool { return d.Scanner == def.ID }) {
			plan.Decisions = append(plan.Decisions, PlanDecision{Scanner: def.ID, State: PlanNotApplicable, ReasonCode: "target_or_type_missing", Reason: "No supplied target and requested assessment type match this scanner."})
		}
	}
	for _, typ := range cfg.Types {
		coverage := TypeCoverage{Type: typ, State: "not_applicable", Reason: "No scanner in this build supports the requested type and supplied resources."}
		for _, d := range plan.Decisions {
			if slices.Contains(d.Types, typ) {
				switch d.State {
				case PlanSelected:
					coverage.State = "planned"
					coverage.Reason = "At least one scanner job is planned."
				case PlanConditional:
					if coverage.State != "planned" {
						coverage.State = "conditional"
						coverage.Reason = "Coverage depends on a preparation step or resource check."
					}
				case PlanUnavailable:
					if coverage.State == "not_applicable" {
						coverage.State = "unavailable"
						coverage.Reason = d.Reason
					}
				}
			}
		}
		plan.Coverage = append(plan.Coverage, coverage)
	}
	sort.SliceStable(plan.Jobs, func(i, j int) bool { return plan.Jobs[i].ID < plan.Jobs[j].ID })
	plan.Fingerprint = planFingerprint(cfg, plan.Jobs)
	return plan
}

func eligibility(def ScannerDefinition, target assessment.Target, evidence []assessment.CapabilityEvidence, availability map[string]bool) (PlanState, string, string) {
	available := def.Available
	if v, ok := availability[def.ID]; ok {
		available = v
	}
	if !available {
		return PlanUnavailable, "scanner.unavailable", fmt.Sprintf("%s is relevant but its scanner or service is unavailable.", def.Name)
	}
	conditional := false
	for _, required := range def.RequiredCapabilities {
		found := false
		for _, e := range evidence {
			if e.TargetID == target.ID && e.Capability == required && e.State != assessment.StateUnavailable {
				found = true
				if e.State == assessment.StateDeclared && (required == assessment.CapWeb || required == assessment.CapSource || required == assessment.CapImage || required == assessment.CapDependency || required == assessment.CapIaC) {
					conditional = true
				}
			}
		}
		// These capabilities are established by bounded preparation of source.
		if (required == assessment.CapDependency || required == assessment.CapIaC) && (target.Kind == assessment.KindRepository || target.Kind == assessment.KindLocalSourcePath) {
			found, conditional = true, true
		}
		if required == assessment.CapNetwork && target.Kind == assessment.KindURL && def.ID == "testssl" {
			found = true
		}
		if !found {
			return PlanNotApplicable, "capability.missing", fmt.Sprintf("Required capability %s is unavailable for target %s.", required, target.ID)
		}
	}
	if def.DefaultSelection == "optional" || def.DefaultSelection == "explicit_opt_in" {
		return PlanOptional, "scanner.explicit_opt_in", "This scanner is optional and requires explicit operator selection."
	}
	if conditional {
		return PlanConditional, "resource.preparation_required", "The scanner is relevant; target reachability or resource preparation must succeed before it runs."
	}
	return PlanSelected, "scanner.applicable", "Target, assessment type, and required capabilities match."
}

func targetSupportsType(target assessment.Target, typ assessment.Type) bool {
	switch target.Kind {
	case assessment.KindDomain:
		return typ == assessment.TypeNetwork || typ == assessment.TypeWebApplication || typ == assessment.TypeAPI || typ == assessment.TypeHost
	case assessment.KindURL:
		return typ == assessment.TypeWebApplication || typ == assessment.TypeAPI || typ == assessment.TypeNetwork
	case assessment.KindIP, assessment.KindCIDR:
		return typ == assessment.TypeNetwork || typ == assessment.TypeHost
	case assessment.KindHost:
		return typ == assessment.TypeNetwork || typ == assessment.TypeHost || typ == assessment.TypeWebApplication || typ == assessment.TypeAPI
	case assessment.KindRepository, assessment.KindLocalSourcePath:
		return typ == assessment.TypeSourceCode || typ == assessment.TypeDependencies || typ == assessment.TypeIaC
	case assessment.KindDockerImage:
		return typ == assessment.TypeContainer || typ == assessment.TypeDependencies
	case assessment.KindSBOM:
		return typ == assessment.TypeDependencies
	default:
		return false
	}
}

func hasCapability(all []assessment.CapabilityEvidence, c assessment.Capability, target string, state assessment.EvidenceState) bool {
	for _, e := range all {
		if e.Capability == c && e.TargetID == target && e.State == state {
			return true
		}
	}
	return false
}
func planFingerprint(cfg assessment.AssessmentConfig, jobs []PlanJob) string {
	data, _ := json.Marshal(struct {
		Config assessment.AssessmentConfig `json:"config"`
		Jobs   []PlanJob                   `json:"jobs"`
	}{cfg, jobs})
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
