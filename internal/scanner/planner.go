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
	ID              string            `json:"id"`
	State           PlanState         `json:"state"`
	Scanner         string            `json:"scanner"`
	TargetID        string            `json:"target_id"`
	Target          string            `json:"target"`
	AssessmentType  assessment.Type   `json:"assessment_type"`
	AssessmentTypes []assessment.Type `json:"assessment_types,omitempty"`
	Variant         string            `json:"variant"`
	Dependencies    []string          `json:"dependencies,omitempty"`
	ExecutionMode   string            `json:"execution_mode,omitempty"`
	Reason          string            `json:"reason,omitempty"`
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
	// CredentialAvailability is keyed by targetID + NUL + accessKind + NUL + credentialID. A
	// declared ID alone is not evidence that a secret exists or is target-bound.
	CredentialAvailability map[string]bool `json:"-"`
}

type AssessmentPlan struct {
	Config          assessment.AssessmentConfig     `json:"config"`
	Capabilities    []assessment.CapabilityEvidence `json:"capabilities"`
	Decisions       []PlanDecision                  `json:"decisions"`
	Jobs            []PlanJob                       `json:"jobs"`
	Coverage        []TypeCoverage                  `json:"coverage"`
	APIEndpoints    []APIEndpoint                   `json:"api_endpoints,omitempty"`
	Warnings        []assessment.Problem            `json:"warnings,omitempty"`
	Errors          []assessment.Problem            `json:"errors,omitempty"`
	Fingerprint     string                          `json:"fingerprint"`
	RegistryVersion string                          `json:"registry_version"`
}

// PlanAssessment is a deterministic, side-effect-free plan builder. It never
// probes targets, pulls images, clones repositories, or resolves credentials.
func PlanAssessment(input PlanInput) AssessmentPlan {
	cfg := assessment.Normalize(input.Config)
	// RegistryVersion also pins scanner and preparation semantics which affect
	// execution identity (including which imported API operations are seeded).
	plan := AssessmentPlan{Config: cfg, Capabilities: assessment.DeriveCapabilities(cfg), RegistryVersion: "3"}
	for i := range plan.Capabilities {
		evidence := &plan.Capabilities[i]
		if evidence.Capability != assessment.CapAuthWeb && evidence.Capability != assessment.CapSSH {
			continue
		}
		credentialID := evidence.ReferenceID
		if credentialID == "" {
			evidence.State = assessment.StateUnavailable
			evidence.Reason = "authenticated access is not backed by a credential reference"
			continue
		}
		if input.CredentialAvailability[credentialAvailabilityKey(evidence.TargetID, evidence.AccessKind, credentialID)] {
			evidence.State = assessment.StateAvailable
			evidence.Reason = "target-bound credential exists; access verification is still pending"
		} else {
			evidence.State = assessment.StateUnavailable
			evidence.Reason = "credential is missing, unreadable, or not bound to this target"
		}
	}
	problems := assessment.Validate(cfg)
	for _, p := range problems {
		if p.Blocking {
			plan.Errors = append(plan.Errors, p)
		} else {
			plan.Warnings = append(plan.Warnings, p)
		}
	}
	if len(plan.Errors) > 0 {
		plan.Fingerprint = planFingerprint(cfg, plan.Capabilities, plan.Decisions, plan.Jobs, plan.RegistryVersion)
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
		plan.Fingerprint = planFingerprint(cfg, plan.Capabilities, plan.Decisions, plan.Jobs, plan.RegistryVersion)
		return plan
	}

	// httpx (reachability probe) and katana (the web-crawl stage that feeds the
	// scanners) run implicitly, not as selectable per-target coverage jobs, so
	// they never surface as coverage gaps. subfinder stays planner-managed: it is
	// a real conditional job (opt-in subdomain discovery).
	discoveryTools := map[string]bool{"httpx": true, "katana": true}
	for _, def := range defs {
		if discoveryTools[def.ID] {
			continue
		}
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
				if def.ID == "subfinder" && target.Kind == assessment.KindDomain && state != PlanUnavailable {
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
					appendPlanJob(&plan.Jobs, PlanJob{ID: fmt.Sprintf("%s:%s:%s", def.ID, target.ID, def.ID), State: state, Scanner: def.ID, TargetID: target.ID, Target: target.Value, AssessmentType: typ, AssessmentTypes: []assessment.Type{typ}, Variant: def.ID, ExecutionMode: execMode})
				}
			}
		}
		if len(plan.Decisions) == 0 || !slices.ContainsFunc(plan.Decisions, func(d PlanDecision) bool { return d.Scanner == def.ID }) {
			plan.Decisions = append(plan.Decisions, PlanDecision{Scanner: def.ID, State: PlanNotApplicable, ReasonCode: "target_or_type_missing", Reason: "No supplied target and requested assessment type match this scanner."})
		}
	}
	for _, target := range cfg.Targets {
		for _, typ := range cfg.Types {
			if !targetSupportsType(target, typ) {
				continue
			}
			matched := slices.ContainsFunc(plan.Decisions, func(d PlanDecision) bool {
				return d.TargetID == target.ID && slices.Contains(d.Types, typ)
			})
			if !matched {
				plan.Decisions = append(plan.Decisions, PlanDecision{
					Scanner: "adapter", TargetID: target.ID, Types: []assessment.Type{typ},
					State: PlanUnavailable, ReasonCode: "adapter.unavailable",
					Reason: unsupportedTypeReason(typ),
				})
			}
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
	plan.Fingerprint = planFingerprint(cfg, plan.Capabilities, plan.Decisions, plan.Jobs, plan.RegistryVersion)
	return plan
}

func appendPlanJob(jobs *[]PlanJob, job PlanJob) {
	for i := range *jobs {
		existing := &(*jobs)[i]
		if existing.Scanner != job.Scanner || existing.TargetID != job.TargetID || existing.Variant != job.Variant {
			continue
		}
		if !slices.Contains(existing.AssessmentTypes, job.AssessmentType) {
			existing.AssessmentTypes = append(existing.AssessmentTypes, job.AssessmentType)
		}
		if existing.State == PlanConditional && job.State == PlanSelected {
			existing.State = PlanSelected
		}
		return
	}
	*jobs = append(*jobs, job)
}

func credentialAvailabilityKey(targetID string, accessKind assessment.AccessKind, credentialID string) string {
	return targetID + "\x00" + string(accessKind) + "\x00" + credentialID
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
		if def.ID == "trivy" && required == assessment.CapSource {
			switch target.Kind {
			case assessment.KindDockerImage:
				required = assessment.CapImage
			case assessment.KindSBOM:
				required = assessment.CapSBOM
			}
		}
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
		// Nikto needs only reachability to the host's web port, so a network
		// target (IP, host, or domain) satisfies its web-capability requirement
		// without granting CapWeb broadly to other web scanners.
		if required == assessment.CapWeb && def.ID == "nikto" && (target.Kind == assessment.KindIP || target.Kind == assessment.KindHost || target.Kind == assessment.KindDomain) {
			found = true
		}
		if target.Kind == assessment.KindSBOM && def.ID == "trivy" {
			conditional = true // local file readability is checked at execution
		}
		if required == assessment.CapSSH && (def.ID == "vuls" || def.ID == "lynis") {
			conditional = true // the alias and remote tool are checked at execution
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
		return typ == assessment.TypeNetwork || typ == assessment.TypeHost || typ == assessment.TypeWebApplication || typ == assessment.TypeAPI || typ == assessment.TypeCompliance
	case assessment.KindRepository, assessment.KindLocalSourcePath:
		return typ == assessment.TypeSourceCode || typ == assessment.TypeDependencies || typ == assessment.TypeIaC
	case assessment.KindDockerImage:
		return typ == assessment.TypeContainer || typ == assessment.TypeDependencies
	case assessment.KindSBOM:
		return typ == assessment.TypeDependencies
	case assessment.KindCloudAccount:
		return typ == assessment.TypeCloud
	case assessment.KindKubernetesCluster:
		return typ == assessment.TypeKubernetes
	default:
		return false
	}
}

func unsupportedTypeReason(typ assessment.Type) string {
	switch typ {
	case assessment.TypeCloud:
		return "Cloud assessment is represented in the plan, but this build has no cloud scanner adapter."
	case assessment.TypeKubernetes:
		return "Kubernetes assessment is represented in the plan, but this build has no Kubernetes scanner adapter."
	default:
		return fmt.Sprintf("No scanner adapter in this build supports assessment type %s for the supplied resource.", typ)
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
func planFingerprint(cfg assessment.AssessmentConfig, capabilities []assessment.CapabilityEvidence, decisions []PlanDecision, jobs []PlanJob, registryVersion string) string {
	data, _ := json.Marshal(struct {
		Config          assessment.AssessmentConfig     `json:"config"`
		Capabilities    []assessment.CapabilityEvidence `json:"capabilities"`
		Decisions       []PlanDecision                  `json:"decisions"`
		Jobs            []PlanJob                       `json:"jobs"`
		RegistryVersion string                          `json:"registry_version"`
	}{cfg, capabilities, decisions, jobs, registryVersion})
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
