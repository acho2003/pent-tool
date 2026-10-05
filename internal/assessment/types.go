// Package assessment holds the shared, dependency-light domain model for
// Xalgorix assessments: modes, assessment types, targets, access bindings, and
// derived capability evidence. It deliberately imports neither internal/web nor
// the scanner command implementations so the planner and the web layer can both
// depend on it without a cycle.
package assessment

import "strings"

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
	// StateFailed means verification ran and was rejected (wrong marker,
	// negative control matched anonymously, login refused). It is distinct from
	// unavailable, which covers configuration/vault problems where nothing ran.
	StateFailed EvidenceState = "failed"
	// StateExpired means a previously verified session was lost mid-scan.
	StateExpired EvidenceState = "expired"
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
	TargetIDs    []string   `json:"target_ids"`
	Kind         AccessKind `json:"kind"`
	CredentialID string     `json:"credential_id,omitempty"`
	Identity     string     `json:"identity,omitempty"`
	Role         string     `json:"role,omitempty"`
	VerifyURL    string     `json:"verify_url,omitempty"`
	VerifyMarker string     `json:"verify_marker,omitempty"`
	// NegativeMarker is the text whose presence on an anonymous request proves
	// the verify page is public (negative control). Empty falls back to
	// VerifyMarker.
	NegativeMarker string   `json:"negative_marker,omitempty"`
	APIOperations  []string `json:"api_operations,omitempty"`
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

// APIOperationInput supplies explicit values for one OpenAPI operation. Bodies
// are referenced by content hash so scan records never duplicate fixture data.
type APIOperationInput struct {
	DefinitionID   string            `json:"definition_id"`
	OperationID    string            `json:"operation_id"`
	PathParams     map[string]string `json:"path_params,omitempty"`
	Query          map[string]string `json:"query,omitempty"`
	RequestBodyRef string            `json:"request_body_ref,omitempty"`
}

// WriteApproval opts one operation into a single, non-retried write attempt.
// Fixture and cleanup are content-addressed references, not inline bodies.
type WriteApproval struct {
	TargetID           string `json:"target_id"`
	Method             string `json:"method"`
	Path               string `json:"path"`
	OperationID        string `json:"operation_id"`
	FixtureRef         string `json:"fixture_ref"`
	ContentType        string `json:"content_type,omitempty"`
	CleanupMethod      string `json:"cleanup_method,omitempty"`
	CleanupPath        string `json:"cleanup_path,omitempty"`
	CleanupRef         string `json:"cleanup_ref"`
	CleanupContentType string `json:"cleanup_content_type,omitempty"`
}

// AuthorizationExpectation declares expected access for a supplied test
// identity against a controlled resource fixture.
type AuthorizationExpectation struct {
	OperationID        string `json:"operation_id"`
	Identity           string `json:"identity"`
	Expect             string `json:"expect"`
	ResourceFixtureRef string `json:"resource_fixture_ref"`
}

// AssessmentConfig is the canonical, normalized configuration for one
// assessment.
type AssessmentConfig struct {
	WorkflowVersion            string                     `json:"workflow_version,omitempty"`
	ParentAssessmentID         string                     `json:"parent_assessment_id,omitempty"`
	ParentPlanFingerprint      string                     `json:"parent_plan_fingerprint,omitempty"`
	ApprovalPreviewFingerprint string                     `json:"approval_preview_fingerprint,omitempty"`
	Mode                       Mode                       `json:"assessment_mode"`
	Types                      []Type                     `json:"assessment_types"`
	Targets                    []Target                   `json:"assessment_targets"`
	Access                     []AccessBinding            `json:"access,omitempty"`
	Profile                    string                     `json:"profile,omitempty"`
	ScannerSelection           ScannerSelection           `json:"scanner_selection,omitempty"`
	APIDefinitionIDs           []string                   `json:"api_definition_ids,omitempty"`
	APIDefinitions             []APIDefinitionBinding     `json:"api_definitions,omitempty"`
	APIOperationInputs         []APIOperationInput        `json:"api_operation_inputs,omitempty"`
	WriteApprovals             []WriteApproval            `json:"write_approvals,omitempty"`
	AuthorizationExpectations  []AuthorizationExpectation `json:"authorization_expectations,omitempty"`
	SubdomainDiscovery         bool                       `json:"subdomain_discovery,omitempty"`
	// ApprovedOrigins are the explicit scheme/host/port/path destinations of
	// each application target. When a target has none, AppScopeForTarget
	// derives its boundary from Target.Value.
	ApprovedOrigins []ApprovedOrigin `json:"approved_origins,omitempty"`
	// Exclusions are routes no tool may request (logout, deletion, purchases,
	// administrative or operator-specified routes), whatever the method.
	Exclusions []Exclusion `json:"exclusions,omitempty"`
	// TestEnvironment declares the targets are disposable test systems. It is a
	// prerequisite for state-changing tests and is forbidden in Black Box.
	TestEnvironment    bool                `json:"test_environment,omitempty"`
	DiscoveryProviders *DiscoveryProviders `json:"discovery_providers,omitempty"`
	// ManualSeeds are operator-supplied entry URLs merged into the inventory.
	// Each must lie inside some target's AppScope and not be excluded.
	ManualSeeds []string `json:"manual_seeds,omitempty"`
}

// ApprovedOrigin is one approved application/API destination. It always
// belongs to exactly one target so access bindings stay target-keyed; sharing
// a host with another origin never merges applications or authorizes other
// ports. After Normalize, Scheme and Host are lower-case, Host is bare (IPv6
// without brackets), Port is explicit (80/443 filled for the defaults) and
// PathPrefix is a cleaned absolute path ("/" for the whole origin).
type ApprovedOrigin struct {
	TargetID   string `json:"target_id"`
	Scheme     string `json:"scheme"`
	Host       string `json:"host"`
	Port       int    `json:"port,omitempty"`
	PathPrefix string `json:"path_prefix,omitempty"`
}

// Exclusion forbids requests to matching routes. An empty TargetID or Origin
// applies to every approved origin; an empty Method applies to every method
// (GET is not inherently side-effect-free). PathPattern is an absolute path
// in which "*" matches any run of characters; it matches the path itself and
// everything below it, case-insensitively.
type Exclusion struct {
	TargetID    string `json:"target_id,omitempty"`
	Origin      string `json:"origin,omitempty"`
	Method      string `json:"method,omitempty"`
	PathPattern string `json:"path_pattern"`
	Reason      string `json:"reason,omitempty"`
}

// Discovery provider identifiers.
const (
	ProviderSubfinder   = "subfinder"
	ProviderAmass       = "amass"
	ProviderGau         = "gau"
	ProviderWaybackurls = "waybackurls"
	ProviderNone        = "none"
	ProviderTestssl     = "testssl"
	ProviderSSLyze      = "sslyze"
)

// DiscoveryProviders selects optional discovery tools. Subdomain providers
// additionally require SubdomainDiscovery and a Domain target. Historical and
// TLS are single-valued: waybackurls is an alternative to gau and sslyze an
// alternative to testssl, never run together. A Historical provider other than
// ""/"none" is the explicit authorization to query external archives.
type DiscoveryProviders struct {
	Subdomain  []string `json:"subdomain,omitempty"`
	Historical string   `json:"historical,omitempty"`
	TLS        string   `json:"tls,omitempty"`
}

// HistoricalAuthorized reports whether external archive queries were
// explicitly authorized. It is nil-safe.
func (d *DiscoveryProviders) HistoricalAuthorized() bool {
	if d == nil {
		return false
	}
	h := strings.ToLower(strings.TrimSpace(d.Historical))
	return h != "" && h != ProviderNone
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
