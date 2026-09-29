// internal/scanner/scope.go
package scanner

type ScopeKind string

const (
	ScopeHost        ScopeKind = "host"
	ScopeApplication ScopeKind = "application"
	ScopeSource      ScopeKind = "source"
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
	// WebEndpoints is the legacy flattened compatibility view. New runs persist
	// and dispatch the normalized AttackSurface instead.
	WebEndpoints []string
	// AttackSurface is loaded from the versioned per-scope snapshot. It is not
	// duplicated inside recon-scopes.json.
	AttackSurface *AttackSurface `json:"-"`
}

type SourceRef struct {
	Path       string
	Provenance string
}

type Scope struct {
	ID         string
	Kind       ScopeKind
	Target     string
	Evidence   HostEvidence
	Source     SourceRef
	Tracks     []Track
	Origin     string `json:"origin,omitempty"`
	PathPrefix string `json:"path_prefix,omitempty"`
}

func HostScope(target string) Scope {
	return Scope{ID: "host:" + target, Kind: ScopeHost, Target: target}
}

func (s Scope) Key() string { return s.ID }

func ApplicationScope(entry string) Scope {
	return Scope{ID: "app:" + entry, Kind: ScopeApplication, Target: entry, Origin: entry}
}
