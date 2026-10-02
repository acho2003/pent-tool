package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

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
	Stage           string            `json:"stage,omitempty"`
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
	// UnavailabilityReasons explains runtime capability failures separately
	// from an absent scanner binary.
	UnavailabilityReasons map[string]string `json:"-"`
	// CredentialAvailability is keyed by targetID + NUL + accessKind + NUL + credentialID. A
	// declared ID alone is not evidence that a secret exists or is target-bound.
	CredentialAvailability map[string]bool `json:"-"`
	// ToolVersions is keyed by registry ID (or a tool artifact such as a
	// template set) and is hashed verbatim into the fingerprint, so a tool
	// upgrade between preview and start makes the accepted plan stale.
	ToolVersions map[string]string `json:"-"`
	// CredentialRevisions is keyed by credential ID with a non-secret revision
	// value; rotating a bound credential makes the accepted plan stale.
	CredentialRevisions map[string]string `json:"-"`
}

// PlanRegistryVersion pins scanner, stage and preparation semantics that affect
// execution identity. Bumping it deliberately invalidates stored plans and
// schedules (version 4: stage ladder, dependencies, provider selection).
const PlanRegistryVersion = "4"

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
	ToolVersions    map[string]string               `json:"-"`
}

// PlanAssessment is a deterministic, side-effect-free plan builder. It never
// probes targets, pulls images, clones repositories, or resolves credentials.
func PlanAssessment(input PlanInput) AssessmentPlan {
	cfg := assessment.Normalize(input.Config)
	// RegistryVersion also pins scanner and preparation semantics which affect
	// execution identity (including which imported API operations are seeded).
	plan := AssessmentPlan{Config: cfg, Capabilities: assessment.DeriveCapabilities(cfg), RegistryVersion: PlanRegistryVersion, ToolVersions: input.ToolVersions}
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
		plan.Fingerprint = planFingerprint(plan, input.ToolVersions, input.CredentialRevisions)
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
		plan.Fingerprint = planFingerprint(plan, input.ToolVersions, input.CredentialRevisions)
		return plan
	}

	// Katana is promoted separately below as the crawl stage. HTTPX and
	// Subfinder are ordinary evidence jobs so failures are visible in coverage.
	discoveryTools := map[string]bool{"katana": true}
	// Discovery provider choices select a registry ID directly (in auto mode
	// too, so custom-mode demotion never applies) and skip its alternative.
	providerChosen, providerReplaced := providerSelections(cfg.DiscoveryProviders)
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
		if providerChosen[def.ID] {
			selected = true
		}
		for _, target := range matchedTargets {
			for _, typ := range cfg.Types {
				if !slices.Contains(def.AssessmentTypes, typ) {
					continue
				}
				if !targetSupportsType(target, typ) {
					continue
				}
				state, code, reason := eligibility(def, target, plan.Capabilities, input.Availability, input.UnavailabilityReasons)
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
				if providerChosen[def.ID] && state == PlanOptional {
					state, code, reason = PlanSelected, "discovery.provider_selected", "This scanner was chosen as a discovery provider."
				}
				if chosen := providerReplaced[def.ID]; chosen != "" && (state == PlanSelected || state == PlanConditional || state == PlanOptional) {
					state, code, reason = PlanSkipped, "selection.provider_alternative", fmt.Sprintf("Skipped because %s was chosen as the alternative provider.", chosen)
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
	// Authentication and crawling are accepted workflow jobs. They are not
	// selectable vulnerability scanners: they prepare evidence for later stages
	// and carry their own completion or gap status.
	if slices.Contains(cfg.Types, assessment.TypeWebApplication) || slices.Contains(cfg.Types, assessment.TypeAPI) {
		for _, target := range cfg.Targets {
			if target.Kind != assessment.KindURL && target.Kind != assessment.KindDomain && target.Kind != assessment.KindHost {
				continue
			}
			if assessmentWebAuthBound(cfg.Access, target.ID) {
				plan.Jobs = append(plan.Jobs, PlanJob{ID: "auth:" + target.ID + ":auth", State: PlanSelected, Scanner: "auth", TargetID: target.ID, Target: target.Value, Variant: "auth", Stage: StageAuth})
			}
			state := PlanSelected
			if available, known := input.Availability["katana"]; known && !available {
				state = PlanUnavailable
			}
			plan.Decisions = append(plan.Decisions, PlanDecision{Scanner: "katana", TargetID: target.ID, State: state, ReasonCode: "workflow.crawl", Reason: "Endpoint discovery stage; authentication is verified before crawling when configured."})
			plan.Jobs = append(plan.Jobs, PlanJob{ID: "katana:" + target.ID + ":katana", State: state, Scanner: "katana", TargetID: target.ID, Target: target.Value, Variant: "katana", Stage: StageCrawl})
		}
	}
	plan.Decisions = append(plan.Decisions, unregisteredProviderDecisions(cfg)...)
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
	assignStages(plan.Jobs)
	// Every dependency points at a strictly earlier stage, so ordering by stage
	// rank (ties by job ID) is a deterministic topological order.
	sort.SliceStable(plan.Jobs, func(i, j int) bool {
		ri, rj := stageRank(plan.Jobs[i].Stage), stageRank(plan.Jobs[j].Stage)
		if ri != rj {
			return ri < rj
		}
		return plan.Jobs[i].ID < plan.Jobs[j].ID
	})
	plan.Fingerprint = planFingerprint(plan, input.ToolVersions, input.CredentialRevisions)
	return plan
}

// assignStages sets each job's Stage from the ladder and, for web/API workflow
// jobs, its Dependencies: the same-target workflow jobs in each prerequisite
// stage, looking through prerequisite stages that have no job for the target.
// Scanners outside the web workflow are ordered by stage but get no
// prerequisites, because their adapters do not consume workflow outputs.
func assignStages(jobs []PlanJob) {
	byStage := map[string]map[string][]string{} // targetID -> stage -> job IDs
	for i := range jobs {
		jobs[i].Stage = stageForScanner(jobs[i].Scanner)
		if !webWorkflowScanner(jobs[i].Scanner) {
			continue
		}
		if byStage[jobs[i].TargetID] == nil {
			byStage[jobs[i].TargetID] = map[string][]string{}
		}
		byStage[jobs[i].TargetID][jobs[i].Stage] = append(byStage[jobs[i].TargetID][jobs[i].Stage], jobs[i].ID)
	}
	for i := range jobs {
		jobs[i].Dependencies = nil
		if !webWorkflowScanner(jobs[i].Scanner) {
			continue
		}
		stages := byStage[jobs[i].TargetID]
		visited := map[string]bool{}
		var deps []string
		var visit func(stage string)
		visit = func(stage string) {
			for _, prereq := range stagePrerequisites[stage] {
				if visited[prereq] {
					continue
				}
				visited[prereq] = true
				if ids := stages[prereq]; len(ids) > 0 {
					deps = append(deps, ids...)
				} else {
					visit(prereq)
				}
			}
		}
		visit(jobs[i].Stage)
		sort.Strings(deps)
		jobs[i].Dependencies = slices.Compact(deps)
	}
}

func webWorkflowScanner(id string) bool {
	return scannerGroups[id] == GroupWebAPI
}

// providerSelections returns the registry IDs chosen through discovery
// providers and, for each unchosen alternative, the provider that replaced it.
func providerSelections(dp *assessment.DiscoveryProviders) (map[string]bool, map[string]string) {
	chosen, replaced := map[string]bool{}, map[string]string{}
	if dp == nil {
		return chosen, replaced
	}
	if len(dp.Subdomain) > 0 {
		for _, p := range dp.Subdomain {
			chosen[p] = true
		}
		for _, alt := range []string{assessment.ProviderSubfinder, assessment.ProviderAmass} {
			if !chosen[alt] {
				replaced[alt] = strings.Join(dp.Subdomain, ", ")
			}
		}
	}
	for _, pair := range []struct{ choice, a, b string }{
		{dp.Historical, assessment.ProviderGau, assessment.ProviderWaybackurls},
		{dp.TLS, assessment.ProviderTestssl, assessment.ProviderSSLyze},
	} {
		switch pair.choice {
		case pair.a:
			chosen[pair.a], replaced[pair.b] = true, pair.a
		case pair.b:
			chosen[pair.b], replaced[pair.a] = true, pair.b
		}
	}
	return chosen, replaced
}

// providerTemplates maps provider IDs without a registry entry yet to the
// registered scanner whose target kinds and assessment types they share.
var providerTemplates = map[string]string{
	assessment.ProviderAmass:       "subfinder",
	assessment.ProviderGau:         "katana",
	assessment.ProviderWaybackurls: "katana",
	assessment.ProviderSSLyze:      "testssl",
}

// unregisteredProviderDecisions makes a chosen provider that has no adapter in
// this build visible as unavailable instead of silently dropping it.
func unregisteredProviderDecisions(cfg assessment.AssessmentConfig) []PlanDecision {
	dp := cfg.DiscoveryProviders
	if dp == nil {
		return nil
	}
	ids := append(append([]string{}, dp.Subdomain...), dp.Historical, dp.TLS)
	var out []PlanDecision
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, registered := RegistryEntry(id); registered {
			continue
		}
		tmpl, ok := RegistryEntry(providerTemplates[id])
		if !ok {
			continue
		}
		for _, target := range cfg.Targets {
			if !slices.Contains(tmpl.TargetKinds, target.Kind) {
				continue
			}
			for _, typ := range cfg.Types {
				if !slices.Contains(tmpl.AssessmentTypes, typ) || !targetSupportsType(target, typ) {
					continue
				}
				out = append(out, PlanDecision{Scanner: id, TargetID: target.ID, Types: []assessment.Type{typ}, State: PlanUnavailable, ReasonCode: "scanner.unavailable", Reason: fmt.Sprintf("%s was chosen as a discovery provider, but this build has no %s adapter yet.", id, id)})
			}
		}
	}
	return out
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

func eligibility(def ScannerDefinition, target assessment.Target, evidence []assessment.CapabilityEvidence, availability map[string]bool, unavailableReasons map[string]string) (PlanState, string, string) {
	available := def.Available
	if v, ok := availability[def.ID]; ok {
		available = v
	}
	if !available {
		if reason := unavailableReasons[def.ID]; reason != "" {
			return PlanUnavailable, "scanner.capability_unavailable", reason
		}
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

// planFingerprint binds the plan's decisions plus the tool versions and
// credential revisions it was built against. Empty maps hash like nil ones.
func planFingerprint(plan AssessmentPlan, toolVersions, credentialRevisions map[string]string) string {
	data, _ := json.Marshal(struct {
		Config              assessment.AssessmentConfig     `json:"config"`
		Capabilities        []assessment.CapabilityEvidence `json:"capabilities"`
		Decisions           []PlanDecision                  `json:"decisions"`
		Jobs                []PlanJob                       `json:"jobs"`
		RegistryVersion     string                          `json:"registry_version"`
		ToolVersions        map[string]string               `json:"tool_versions,omitempty"`
		CredentialRevisions map[string]string               `json:"credential_revisions,omitempty"`
	}{plan.Config, plan.Capabilities, plan.Decisions, plan.Jobs, plan.RegistryVersion, toolVersions, credentialRevisions})
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
