package scanner

import (
	"slices"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

type Phase string

const (
	PhaseRecon      Phase = "recon"
	PhaseWeb        Phase = "web"
	PhaseServer     Phase = "server"
	PhaseSAST       Phase = "sast"
	PhaseCloud      Phase = "cloud"
	PhaseKubernetes Phase = "kubernetes"
	PhaseFinalize   Phase = "finalize"
)

type Weight string

const (
	WeightLight Weight = "light"
	WeightHeavy Weight = "heavy"
)

type Descriptor struct {
	Name    string
	Summary string // Summary is a one-line description of what the tool does and needs, shown in the UI.
	Phase   Phase
	Tracks  []Track
	Weight  Weight
	Applies func(Scope) bool
}

// ToolInfo describes one pipeline tool for the UI's tool catalog.
type ToolInfo struct {
	Name       string `json:"name"`
	Phase      Phase  `json:"phase"`
	Selectable bool   `json:"selectable"`
	Summary    string `json:"summary"`
}

// ScannerDefinition is the registry entry used by planning and discovery UI.
// Availability is supplied at planning time because installed tools and
// configured services vary by deployment.
// Scanner groups organize the catalog for the New Assessment UI. They are a
// presentation dimension independent of Category (the execution phase): e.g.
// nmap's Category is recon but its Group is network/servers.
const (
	GroupWebAPI     = "web_api"
	GroupNetwork    = "network_servers"
	GroupCloud      = "cloud"
	GroupKubernetes = "kubernetes"
	GroupCode       = "code" // source, dependencies, containers
)

type ScannerDefinition struct {
	ID                     string                  `json:"id"`
	Name                   string                  `json:"name"`
	Category               Phase                   `json:"category"`
	Group                  string                  `json:"group"`
	AssessmentTypes        []assessment.Type       `json:"assessment_types"`
	TargetKinds            []assessment.TargetKind `json:"target_types"`
	RequiredCapabilities   []assessment.Capability `json:"required_capabilities,omitempty"`
	OptionalCapabilities   []assessment.Capability `json:"optional_capabilities,omitempty"`
	SupportsAuthentication bool                    `json:"supports_authentication"`
	DefaultSelection       string                  `json:"default_selection"`
	Risk                   string                  `json:"risk"`
	Selectable             bool                    `json:"selectable"`
	Available              bool                    `json:"available"`
	AvailabilityReason     string                  `json:"availability_reason,omitempty"`
	Summary                string                  `json:"summary"`
	// Stage is the workflow stage the scanner runs in (see stageForScanner).
	Stage string `json:"stage,omitempty"`
	// PolicySupport lists the request-policy controls the adapter can enforce
	// or must be gated on (Policy* constants), sorted.
	PolicySupport []string `json:"policy_support,omitempty"`
	// OutputFormat is the machine-readable format the adapter parses:
	// jsonl, json, text or xml.
	OutputFormat string `json:"output_format,omitempty"`
}

// Workflow stages, in dependency order. Each stage consumes the outputs of the
// stages listed for it in stagePrerequisites; a job never depends on a job in
// the same or a later stage, so ordering by stage rank is a topological order.
const (
	StageScope        = "scope"
	StageDiscovery    = "discovery"
	StageDNS          = "dns"
	StageReachability = "reachability"
	StageAuth         = "auth"
	StageCrawl        = "crawl"
	StageInventory    = "inventory"
	StagePassive      = "passive"
	StageTemplates    = "templates"
	StageTLS          = "tls"
	StageDAST         = "dast"
	StageValidation   = "validation"
	StageWrite        = "write_validation"
	StageResults      = "results"
)

var stageOrder = []string{StageScope, StageDiscovery, StageDNS, StageReachability, StageAuth, StageCrawl, StageInventory, StagePassive, StageTemplates, StageTLS, StageDAST, StageValidation, StageWrite, StageResults}

// stagePrerequisites names the stages whose outputs a stage consumes. When a
// prerequisite stage has no job for the target, its own prerequisites stand in
// for it. Analysis stages share the inventory; TLS needs only reachability.
var stagePrerequisites = map[string][]string{
	StageDiscovery:    {StageScope},
	StageDNS:          {StageDiscovery},
	StageReachability: {StageDNS},
	StageAuth:         {StageReachability},
	StageCrawl:        {StageAuth},
	StageInventory:    {StageCrawl},
	StagePassive:      {StageInventory},
	StageTemplates:    {StageInventory},
	StageTLS:          {StageReachability},
	StageDAST:         {StageInventory},
	StageValidation:   {StageInventory},
	StageWrite:        {StageValidation},
	StageResults:      {StagePassive, StageTemplates, StageTLS, StageDAST, StageValidation, StageWrite},
}

// stageForScanner maps a registry ID onto the workflow stage ladder. Network,
// host, code, cloud and Kubernetes scanners have no web-workflow inputs and run
// in the main testing stage (dast); port discovery runs with reachability.
func stageForScanner(id string) string {
	switch id {
	case "subfinder", "amass":
		return StageDiscovery
	case "dnsx":
		return StageDNS
	case "httpx", "nmap", "masscan":
		return StageReachability
	case "auth":
		return StageAuth
	case "katana", "gau", "waybackurls":
		return StageCrawl
	case "nuclei", "nikto":
		return StageTemplates
	case "testssl", "sslyze":
		return StageTLS
	case "dalfox":
		return StageValidation
	case "apichecks":
		return StageValidation
	case "apiwrites":
		return StageWrite
	default:
		return StageDAST
	}
}

// stageRank is the position of a stage in the ladder, or -1 if unknown.
func stageRank(stage string) int {
	for i, s := range stageOrder {
		if s == stage {
			return i
		}
	}
	return -1
}

// Policy controls a scanner adapter supports (ScannerDefinition.PolicySupport).
const (
	PolicyGetHeadOnly  = "get_head_only" // sends only GET/HEAD requests to the target
	PolicyExclusions   = "exclusions"    // honours path/method exclusions natively
	PolicyRateLimited  = "rate_limited"  // honours a request-rate limit
	PolicyScopeRegex   = "scope_regex"   // confines requests with an in-scope regex
	PolicyWriteCapable = "write_capable" // may send state-changing requests
	PolicyOASTDisabled = "oast_disabled" // out-of-band interaction can be disabled
)

// Catalog lists every tool a scan runs: the recon tools, which always run, then
// the scan runners in pipeline order (grouped by phase). It is derived from the
// runners' own descriptors so the UI never needs its own tool list. Selectable
// tools are exactly those a scan may deselect (OrderedNames).
func Catalog() []ToolInfo {
	defs := ScannerRegistry()
	out := make([]ToolInfo, 0, 12)
	for _, d := range defs {
		if !d.Available || (d.Category != PhaseRecon && !slices.Contains(OrderedNames, d.ID)) {
			continue
		}
		out = append(out, ToolInfo{Name: d.Name, Phase: d.Category, Selectable: d.Selectable, Summary: d.Summary})
	}
	return out
}
