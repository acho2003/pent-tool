package scanner

import "github.com/xalgord/xalgorix/v4/internal/assessment"

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
	Summary                string                  `json:"summary"`
}

// Catalog lists every tool a scan runs: the recon tools, which always run, then
// the scan runners in pipeline order (grouped by phase). It is derived from the
// runners' own descriptors so the UI never needs its own tool list. Selectable
// tools are exactly those a scan may deselect (OrderedNames).
func Catalog() []ToolInfo {
	defs := ScannerRegistry()
	out := make([]ToolInfo, 0, 12)
	for _, d := range defs {
		if !d.Available {
			continue
		}
		out = append(out, ToolInfo{Name: d.Name, Phase: d.Category, Selectable: d.Selectable, Summary: d.Summary})
	}
	return out
}
