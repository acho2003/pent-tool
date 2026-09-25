// internal/scanner/scope.go
package scanner

type ScopeKind string

const (
	ScopeHost   ScopeKind = "host"
	ScopeSource ScopeKind = "source"
)

type Track string

const (
	TrackWeb    Track = "web"
	TrackServer Track = "server"
)

type Port struct {
	Number   int
	Protocol string
	Service  string
	Product  string
}

type HostEvidence struct {
	ResolvedIPs []string
	OpenPorts   []Port
	LiveURLs    []string
	TLS         bool
}

type SourceRef struct {
	Path       string
	Provenance string
}

type Scope struct {
	ID       string
	Kind     ScopeKind
	Target   string
	Evidence HostEvidence
	Source   SourceRef
	Tracks   []Track
}

func HostScope(target string) Scope {
	return Scope{ID: "host:" + target, Kind: ScopeHost, Target: target}
}

func (s Scope) Key() string { return s.ID }
