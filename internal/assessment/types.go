// Package assessment holds the shared, dependency-light domain model for
// Xalgorix assessments: modes, assessment types, targets, access bindings, and
// derived capability evidence. It deliberately imports neither internal/web nor
// the scanner command implementations so the planner and the web layer can both
// depend on it without a cycle.
package assessment

// Mode is the assessment mode. It establishes the ALLOWED access for an
// assessment; it is not a scanner list and not a spelling of scan_mode
// (single/wildcard) or a web profile.
type Mode string

const (
	ModeBlackBox Mode = "BLACK_BOX"
	ModeGrayBox  Mode = "GRAY_BOX"
	ModeWhiteBox Mode = "WHITE_BOX"
)

// Valid reports whether m is one of the three business modes. LEGACY is not a
// mode and is never valid here.
func (m Mode) Valid() bool {
	switch m {
	case ModeBlackBox, ModeGrayBox, ModeWhiteBox:
		return true
	default:
		return false
	}
}

// Type is a requested assessment coverage type.
type Type string

const (
	TypeNetwork        Type = "NETWORK"
	TypeWebApplication Type = "WEB_APPLICATION"
	TypeAPI            Type = "API"
	TypeSourceCode     Type = "SOURCE_CODE"
	TypeDependencies   Type = "DEPENDENCIES"
	TypeContainer      Type = "CONTAINER"
	TypeHost           Type = "HOST"
	TypeCloud          Type = "CLOUD"
	TypeKubernetes     Type = "KUBERNETES"
	TypeIaC            Type = "INFRASTRUCTURE_AS_CODE"
	TypeCompliance     Type = "COMPLIANCE"
)

// AllTypes is the stable ordered set of assessment type identifiers.
var AllTypes = []Type{
	TypeNetwork, TypeWebApplication, TypeAPI, TypeSourceCode, TypeDependencies,
	TypeContainer, TypeHost, TypeCloud, TypeKubernetes, TypeIaC, TypeCompliance,
}

func (t Type) Valid() bool {
	for _, v := range AllTypes {
		if v == t {
			return true
		}
	}
	return false
}

// TargetKind classifies an assessment target or resource.
type TargetKind string

const (
	KindDomain            TargetKind = "DOMAIN"
	KindURL               TargetKind = "URL"
	KindIP                TargetKind = "IP"
	KindCIDR              TargetKind = "CIDR"
	KindRepository        TargetKind = "REPOSITORY"
	KindLocalSourcePath   TargetKind = "LOCAL_SOURCE_PATH"
	KindDockerImage       TargetKind = "DOCKER_IMAGE"
	KindHost              TargetKind = "HOST"
	KindCloudAccount      TargetKind = "CLOUD_ACCOUNT"
	KindKubernetesCluster TargetKind = "KUBERNETES_CLUSTER"
	KindSBOM              TargetKind = "SBOM"
)

var AllTargetKinds = []TargetKind{
	KindDomain, KindURL, KindIP, KindCIDR, KindRepository, KindLocalSourcePath,
	KindDockerImage, KindHost, KindCloudAccount, KindKubernetesCluster, KindSBOM,
}

func (k TargetKind) Valid() bool {
	for _, v := range AllTargetKinds {
		if v == k {
			return true
		}
	}
	return false
}

// Capability is a derived ability to exercise a class of testing against a
// specific target/resource. Capabilities are derived per target and are never
// unioned across unrelated targets.
type Capability string

const (
	CapNetwork    Capability = "network"
	CapWeb        Capability = "web"
	CapAuthWeb    Capability = "authenticated_web"
	CapAPI        Capability = "api"
	CapSchema     Capability = "schema"
	CapSource     Capability = "source"
	CapGit        Capability = "git"
	CapDependency Capability = "dependency"
	CapImage      Capability = "image"
	CapHost       Capability = "host"
	CapSSH        Capability = "ssh"
	CapWindows    Capability = "windows"
	CapCloud      Capability = "cloud"
	CapKubernetes Capability = "kubernetes"
	CapIaC        Capability = "iac"
	CapSBOM       Capability = "sbom"
)

// AccessKind is the kind of access an AccessBinding grants to its targets.
type AccessKind string

const (
	AccessApplicationHeaders AccessKind = "APPLICATION_HEADERS"
	AccessApplicationCookies AccessKind = "APPLICATION_COOKIES"
	AccessBearerToken        AccessKind = "BEARER_TOKEN"
	AccessAPIKey             AccessKind = "API_KEY"
	AccessFormLogin          AccessKind = "FORM_LOGIN"
	AccessRepositoryCreds    AccessKind = "REPOSITORY_CREDENTIALS"
	AccessSSH                AccessKind = "SSH"
	AccessWindows            AccessKind = "WINDOWS"
	AccessCloud              AccessKind = "CLOUD"
	AccessKubernetes         AccessKind = "KUBERNETES"
)

var AllAccessKinds = []AccessKind{
	AccessApplicationHeaders, AccessApplicationCookies, AccessBearerToken,
	AccessAPIKey, AccessFormLogin, AccessRepositoryCreds, AccessSSH,
	AccessWindows, AccessCloud, AccessKubernetes,
}

func (a AccessKind) Valid() bool {
	for _, v := range AllAccessKinds {
		if v == a {
			return true
		}
	}
	return false
}

// EvidenceState is the derivation state of a CapabilityEvidence entry. Reports
// distinguish declared/available from verified, and unavailable from
// not-applicable.
type EvidenceState string

const (
	StateDeclared    EvidenceState = "declared"
	StateAvailable   EvidenceState = "available"
	StateVerified    EvidenceState = "verified"
	StateUnavailable EvidenceState = "unavailable"
)

// Target is one assessment target or resource. ID is an opaque, stable
// identifier used everywhere the target is referenced (access bindings, plan
// jobs, scope). Value retains its original meaningful form — for URLs the
// scheme, port, and path case are preserved.
type Target struct {
	ID        string     `json:"id"`
	Kind      TargetKind `json:"type"`
	Value     string     `json:"value"`
	Branch    string     `json:"branch,omitempty"`     // repository branch, when Kind==REPOSITORY
	RelatedTo string     `json:"related_to,omitempty"` // optional related-target ID (e.g. image built from a repo)
}

// AccessBinding grants an access kind to one or more targets, referencing a
// credential by opaque ID. It never carries resolved secret values in response
// DTOs.
type AccessBinding struct {
	TargetIDs     []string   `json:"target_ids"`
	Kind          AccessKind `json:"kind"`
	CredentialID  string     `json:"credential_id,omitempty"`
	VerifyURL     string     `json:"verify_url,omitempty"`
	APIOperations []string   `json:"api_operations,omitempty"`
}

// CapabilityEvidence records why a capability is (or is not) available for a
// specific target/resource, with provenance and a human-readable reason.
type CapabilityEvidence struct {
	Capability  Capability    `json:"capability"`
	TargetID    string        `json:"target_id"`
	ReferenceID string        `json:"reference_id,omitempty"`
	AccessKind  AccessKind    `json:"access_kind,omitempty"`
	State       EvidenceState `json:"state"`
	Provenance  string        `json:"provenance"`
	Reason      string        `json:"reason"`
}

// APIDefinitionBinding associates one immutable uploaded schema with a single
// target. A definition's server URLs never establish or expand scan scope.
type APIDefinitionBinding struct {
	TargetID     string `json:"target_id"`
	DefinitionID string `json:"definition_id"`
}

// AssessmentConfig is the canonical, normalized configuration for one
// assessment.
type AssessmentConfig struct {
	Mode               Mode                   `json:"assessment_mode"`
	Types              []Type                 `json:"assessment_types"`
	Targets            []Target               `json:"assessment_targets"`
	Access             []AccessBinding        `json:"access,omitempty"`
	Profile            string                 `json:"profile,omitempty"`
	ScannerSelection   ScannerSelection       `json:"scanner_selection,omitempty"`
	APIDefinitionIDs   []string               `json:"api_definition_ids,omitempty"`
	APIDefinitions     []APIDefinitionBinding `json:"api_definitions,omitempty"`
	SubdomainDiscovery bool                   `json:"subdomain_discovery,omitempty"`
}

// ScannerSelection chooses auto planning or an explicit custom variant list.
type ScannerSelection struct {
	Mode     string   `json:"mode,omitempty"` // "auto" (default) or "custom"
	Variants []string `json:"variants,omitempty"`
}

// Lifecycle statuses for planned jobs. These are the lowercase wire strings the
// rest of the system already uses; "queued" is the one new nonterminal state.
const (
	StatusQueued        = "queued"
	StatusRunning       = "running"
	StatusCompleted     = "completed"
	StatusFailed        = "failed"
	StatusSkipped       = "skipped"
	StatusNotApplicable = "not_applicable"
	StatusCancelled     = "cancelled"
)
