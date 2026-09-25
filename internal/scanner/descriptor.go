package scanner

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
	Phase   Phase
	Tracks  []Track
	Weight  Weight
	Applies func(Scope) bool
}
