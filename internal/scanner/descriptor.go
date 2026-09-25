package scanner

import "slices"

type Phase string

const (
	PhaseRecon    Phase = "recon"
	PhaseWeb      Phase = "web"
	PhaseServer   Phase = "server"
	PhaseSAST     Phase = "sast"
	PhaseFinalize Phase = "finalize"
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

// Catalog lists every tool a scan runs: the recon tools, which always run, then
// the scan runners in pipeline order (grouped by phase). It is derived from the
// runners' own descriptors so the UI never needs its own tool list. Selectable
// tools are exactly those a scan may deselect (OrderedNames).
func Catalog() []ToolInfo {
	runners := append([]Runner{subfinderRunner{}, httpxRunner{}, nmapRunner{}}, NewPipeline(Config{}).Runners...)
	out := make([]ToolInfo, 0, len(runners))
	for _, r := range runners {
		d := r.Descriptor()
		out = append(out, ToolInfo{Name: d.Name, Phase: d.Phase, Selectable: slices.Contains(OrderedNames, d.Name), Summary: d.Summary})
	}
	return out
}
