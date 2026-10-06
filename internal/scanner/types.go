// Package scanner implements Xalgorix's deterministic security-scanner
// pipeline. It deliberately has no dependency on internal/agent or internal/llm.
package scanner

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/credentials"
)

const SchemaVersion = 2

var OrderedNames = []string{"nuclei", "zap", "testssl", "openvas", "trivy", "semgrep", "gitleaks", "vuls", "osv"}

// NormalizeScanners validates an operator's scanner selection and returns it in
// pipeline order, deduplicated. An empty selection means the whole pipeline, so
// it normalizes to nil rather than to every name: a scan saved today keeps
// running whatever the pipeline contains tomorrow.
func NormalizeScanners(names []string) ([]string, error) {
	selected := map[string]bool{}
	for _, raw := range names {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		if !slices.Contains(OrderedNames, name) {
			return nil, fmt.Errorf("unknown scanner %q (known: %s)", raw, strings.Join(OrderedNames, ", "))
		}
		selected[name] = true
	}
	if len(selected) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(selected))
	for _, name := range OrderedNames {
		if selected[name] {
			out = append(out, name)
		}
	}
	return out, nil
}

type Artifact struct {
	Kind string `json:"kind,omitempty"`
	Ref  string `json:"ref,omitempty"`
}

type Request struct {
	AuthContextID             string                                `json:"-"`
	AuthContexts              []AuthContext                         `json:"-"`
	AuthorizationExpectations []assessment.AuthorizationExpectation `json:"-"`
	Inventory                 *AttackSurface                        `json:"-"`
	ReplayStore               *credentials.ReplayStore              `json:"-"`
	ReplayScope               string                                `json:"-"`
	BrowserStorage            *credentials.BrowserStorage           `json:"-"`
	BrowserAccessTest         bool                                  `json:"-"`
	BrowserCheckpointMarker   string                                `json:"-"`
	WorkflowVersion           string                                `json:"-"`
	Gateway                   *RecordingGateway                     `json:"-"`
	GatewayURL                string                                `json:"-"`
	GatewayCAPath             string                                `json:"-"`
	NetworkPorts              []int                                 `json:"-"`
	AttemptID                 string                                `json:"-"`
	PlanFingerprint           string                                `json:"-"`
	InputRequests             []ScannerRequestInput                 `json:"-"`
	Target                    string                                `json:"target"`
	// Scanners restricts this request to the named scanners. Empty runs the
	// whole pipeline; every name must be one of OrderedNames.
	Scanners []string `json:"-"`
	ScanDir  string   `json:"-"`
	// Scope stamps every Run a runner constructs (including the initial "running"
	// record whose scanner_started event is emitted) so live-emitted events — and
	// the crash-persisted record built from them — carry their per-host scope
	// instead of collapsing per-host same-named runs. Pipeline.Run sets it per
	// scope; recon sets it per tool. Not serialized: it is derived, not input.
	Scope              string                                            `json:"-"`
	Artifact           Artifact                                          `json:"artifact,omitempty"`
	VulsSSHHost        string                                            `json:"vuls_ssh_host,omitempty"`
	GVMSSHCredentialID string                                            `json:"-"`
	GVMSSHPort         int                                               `json:"-"`
	TargetAuth         string                                            `json:"-"`
	AuthKind           string                                            `json:"-"`
	AuthRefresh        func(context.Context, []string) ([]string, error) `json:"-"`
	Profile            string                                            `json:"-"`
	ApplicationURL     string                                            `json:"-"`
	TypedAssessment    bool                                              `json:"-"`
	APIEndpoints       []APIEndpoint                                     `json:"-"`
	// EndpointTargets is the dispatcher-approved subset of the normalized attack
	// surface for this scanner job. WebEndpoints remains as a compatibility input
	// for callers/tests that have not yet constructed a structured inventory.
	EndpointMethods    map[string]string `json:"-"`
	EndpointTargets    []string          `json:"-"`
	WebEndpoints       []string          `json:"-"`
	StructuredDispatch bool              `json:"-"`
	// CloudCredential is the resolved, target-bound cloud credential for the cloud
	// audit adapters (prowler/scoutsuite). Runtime-only; never serialized.
	CloudCredential CloudCredential `json:"-"`
	// Secrets are extra values redacted from every runner's output, such as the
	// credentials embedded in a clone URL. Pipeline.Run derives them once from
	// the original request, so they survive per-scope copies whose Target no
	// longer holds that URL. Not serialized.
	Secrets []string `json:"-"`
	// AppScope is the approved request boundary (origins plus exclusions) of
	// the application this request tests, so web builders can apply scope and
	// exclusions without new parameters. Nil means the legacy behavior: the
	// builder derives its boundary from Target. Runtime-only.
	AppScope *assessment.AppScope `json:"-"`
	// TestEnvironment records that the operator declared the target a test
	// environment. It informs builders; it never enables writes on its own.
	TestEnvironment bool `json:"-"`
	// WriteApprovals are target-filtered, previewed approvals. Only apiwrites
	// consumes them, after prerequisites pass and with a persistent write journal.
	WriteApprovals  []assessment.WriteApproval `json:"-"`
	WriteJournalDir string                     `json:"-"`
	// APIFixtureDir is the private content-addressed fixture store used by the
	// native approved-write adapter.
	APIFixtureDir         string        `json:"-"`
	APIOperationEndpoints []APIEndpoint `json:"-"`
}

// GapKind classifies why planned coverage did not happen. It is a stable
// machine token, separate from the free-text Run.Reason, so coverage and
// reports never substring-match prose. Empty means no gap.
type GapKind string

const (
	// GapPrerequisiteFailed: a required capability or earlier stage failed.
	GapPrerequisiteFailed GapKind = "prerequisite_failed"
	// GapToolUnavailable: the scanner binary or service is not available.
	GapToolUnavailable GapKind = "tool_unavailable"
	// GapRequestFailed: the native request adapter could not complete one or more requests.
	GapRequestFailed GapKind = "request_failed"
	// GapExcluded: the work was excluded by scope, exclusions or policy.
	GapExcluded GapKind = "excluded"
	// GapEmptyInput: the scanner had nothing to test (no endpoints, no files).
	GapEmptyInput GapKind = "empty_input"
	// GapBudgetExhausted: the assessment time, endpoint or rate budget ran out.
	GapBudgetExhausted GapKind = "budget_exhausted"
	// GapAuthFailed: authentication was required and could not be established.
	GapAuthFailed GapKind = "auth_failed"
	// GapAuthExpired: the authenticated session expired and was not restored.
	GapAuthExpired GapKind = "auth_expired"
	// GapCancelled: the operator or the process cancelled the work.
	GapCancelled GapKind = "cancelled"
	// GapInterruptedWrite: the run's results were not durably written.
	GapInterruptedWrite GapKind = "interrupted_write"
)

// Run limitation kinds: categories a completed run deliberately did not cover.
const (
	// LimitationHeadlessExcluded: nuclei headless templates were not run.
	LimitationHeadlessExcluded = "headless_excluded"
	// LimitationStandardEngineFallback: katana fell back from the headless
	// browser engine to its standard (non-JavaScript) engine.
	LimitationStandardEngineFallback = "standard_engine_fallback"
)

// RunLimitation records a category of coverage a run that otherwise completed
// excluded, so a completed status is not read as full coverage.
type RunLimitation struct {
	Kind   string `json:"kind"`
	Reason string `json:"reason,omitempty"`
}

type Run struct {
	AuthContextID         string                `json:"auth_context_id,omitempty"`
	AuthIdentity          string                `json:"auth_identity,omitempty"`
	AuthRole              string                `json:"auth_role,omitempty"`
	AuthorizationResults  []AuthorizationResult `json:"authorization_results,omitempty"`
	WorkflowVersion       string                `json:"workflow_version,omitempty"`
	TemplateInventoryPath string                `json:"template_inventory_path,omitempty"`
	DefinitionImports     []DefinitionImport    `json:"definition_imports,omitempty"`
	ApplicationRevision   string                `json:"application_revision,omitempty"`
	CoverageEventsPath    string                `json:"coverage_events_path,omitempty"`
	BatchRuns             []Run                 `json:"batch_runs,omitempty"`
	NetworkPorts          []int                 `json:"network_ports,omitempty"`
	InputManifestPath     string                `json:"input_manifest_path,omitempty"`
	NativeScanIDs         []string              `json:"native_scan_ids,omitempty"`
	Submissions           []EndpointSubmission  `json:"submissions,omitempty"`
	Outcome               string                `json:"outcome,omitempty"`
	ExecutionOutcome      string                `json:"execution_outcome,omitempty"`
	ParserOutcome         string                `json:"parser_outcome,omitempty"`
	Completeness          string                `json:"completeness,omitempty"`
	Scanner               string                `json:"scanner"`
	Authenticated         bool                  `json:"authenticated,omitempty"`
	Variant               string                `json:"variant,omitempty"`
	AssessmentTypes       []assessment.Type     `json:"assessment_types,omitempty"`
	PlanFingerprint       string                `json:"plan_fingerprint,omitempty"`
	AttemptID             string                `json:"attempt_id,omitempty"`
	Scope                 string                `json:"scope,omitempty"`
	Target                string                `json:"target"`
	Status                string                `json:"status"`
	LastActivityAt        string                `json:"last_activity_at,omitempty"`
	StartedAt             string                `json:"started_at,omitempty"`
	FinishedAt            string                `json:"finished_at,omitempty"`
	ExitCode              int                   `json:"exit_code,omitempty"`
	Reason                string                `json:"reason,omitempty"`
	StdoutPath            string                `json:"stdout_path,omitempty"`
	StderrPath            string                `json:"stderr_path,omitempty"`
	TranscriptPath        string                `json:"transcript_path,omitempty"`
	ArtifactPath          string                `json:"artifact_path,omitempty"`
	DNSResolution         *DNSResolution        `json:"dns_resolution,omitempty"`
	CandidateHosts        []string              `json:"candidate_hosts,omitempty"`
	HTTPObservations      []HTTPObservation     `json:"http_observations,omitempty"`
	HistoricalCandidates  []HistoricalCandidate `json:"historical_candidates,omitempty"`
	Checksum              string                `json:"checksum,omitempty"`
	Truncated             bool                  `json:"truncated,omitempty"`
	APIEndpointResults    []APIEndpointResult   `json:"api_endpoint_results,omitempty"`
	// Progress is a scanner-reported 0–100 completion of ProgressStage while
	// the run is in flight (OpenVAS task progress, ZAP spider/active scan).
	// Only scanners with a native progress signal set it.
	Progress      int    `json:"progress,omitempty"`
	ProgressStage string `json:"progress_stage,omitempty"`
	// GapKind classifies a run that did not deliver its planned coverage;
	// empty means no gap. Reason stays the human explanation.
	GapKind GapKind `json:"gap_kind,omitempty"`
	// Stage is the planner stage this run belongs to.
	Stage string `json:"stage,omitempty"`
	// AuthState is the structured outcome of the run's authenticated-session
	// check (verified, failed, expired, ...) as of AuthCheckedAt (RFC 3339).
	// Coverage reads it instead of matching Reason text.
	AuthState     assessment.EvidenceState `json:"auth_state,omitempty"`
	AuthCheckedAt string                   `json:"auth_checked_at,omitempty"`
	// Limitations lists categories a completed run excluded.
	Limitations []RunLimitation `json:"limitations,omitempty"`
}

func (r Run) Terminal() bool {
	switch r.Status {
	case "completed", "failed", "cancelled", "not_applicable", "skipped":
		return true
	default:
		return false
	}
}

type Event struct {
	Type     string
	Scanner  string
	Stream   string
	Sequence int64
	Output   string
	Run      Run
}

type Config struct {
	ReplayKey          []byte `json:"-"`
	NucleiPath         string
	NucleiTemplatesDir string
	TrivyPath          string
	VulsPath           string
	VulsSSHConfigPath  string
	SubfinderPath      string
	AmassPath          string
	DNSXPath           string
	GauPath            string
	WaybackurlsPath    string
	SSLyzePath         string
	HttpxPath          string
	NmapPath           string
	MasscanPath        string
	NiktoPath          string
	KatanaPath         string
	KatanaChromePath   string
	DalfoxPath         string
	WapitiPath         string
	KubeBenchPath      string
	ProwlerPath        string
	ScoutSuitePath     string
	SSHPath            string
	TestsslPath        string
	SemgrepPath        string
	GitleaksPath       string
	OsvPath            string

	ZAPURL       string
	ZAPAPIKey    string
	ZAPDedicated bool
	GVMHost      string
	GVMPort      int
	GVMSocket    string
	GVMUser      string
	GVMPass      string

	RateRPS         int
	WebProfile      string
	WebMaxEndpoints int
	WebBudget       time.Duration
	WebBrowser      bool
	MaxWorkers      int
	ScanHeaders     []string
	// AssessmentAuthHeaders contains runtime-only, target-bound credentials for
	// typed jobs. It must never be serialized or logged.
	AssessmentBrowserStorage map[string]*credentials.BrowserStorage `json:"-"`
	AssessmentAuthContexts   []AuthContext                          `json:"-"`
	AssessmentAuthHeaders    map[string][]string
	// AssessmentAuthRefresh checks an authenticated session during a typed job.
	// It returns replacement header lines after at most one form re-login.
	// Callbacks and returned secrets remain runtime-only.
	AssessmentAuthRefresh  map[string]func(context.Context, []string) ([]string, error)
	AssessmentSSHAliases   map[string]string
	AssessmentGVMSSH       map[string]GVMSSHCredential
	AssessmentSSHRequested map[string]bool
	// AssessmentCloudCreds holds runtime-only, target-bound cloud credentials
	// (resolved from the vault) for prowler/scoutsuite, keyed by target ID. Passed
	// to the runner via env, never persisted in scan records.
	AssessmentCloudCreds map[string]CloudCredential
	// AssessmentRepoCreds holds runtime-only, target-bound tokens for cloning
	// private repositories, keyed by target ID. Handed to git via env only.
	AssessmentRepoCreds map[string]RepoCredential
	MaxOutputBytes      int64
	NucleiTimeout       time.Duration
	ZAPTimeout          time.Duration
	OpenVASTimeout      time.Duration
	TrivyTimeout        time.Duration
	VulsTimeout         time.Duration
	SubfinderTimeout    time.Duration
	AmassTimeout        time.Duration
	DNSXTimeout         time.Duration
	GauTimeout          time.Duration
	WaybackurlsTimeout  time.Duration
	SSLyzeTimeout       time.Duration
	HttpxTimeout        time.Duration
	NmapTimeout         time.Duration
	MasscanTimeout      time.Duration
	MasscanRate         int
	NiktoTimeout        time.Duration
	KatanaTimeout       time.Duration
	DalfoxTimeout       time.Duration
	WapitiTimeout       time.Duration
	KubeBenchTimeout    time.Duration
	ProwlerTimeout      time.Duration
	ScoutSuiteTimeout   time.Duration
	LynisTimeout        time.Duration
	TestsslTimeout      time.Duration
	SemgrepTimeout      time.Duration
	GitleaksTimeout     time.Duration
	OsvTimeout          time.Duration

	// ScopeGuard re-runs the caller's self-listener/local-target guard at
	// execution time, so this package can refuse a URL without importing the
	// web layer. resolved holds the addresses the URL's host resolved to, when
	// known. Nil means no extra guard. Runtime-only.
	ScopeGuard    func(rawURL string, resolved []string) (blocked bool, reason string) `json:"-"`
	APIFixtureDir string                                                               `json:"-"`
	// APIOperationEndpoints is a target-filtered immutable OpenAPI inventory
	// supplied to the approved-write adapter for operation matching.
	APIOperationEndpoints []APIEndpoint `json:"-"`
	// Budget is the assessment-wide rate, endpoint and time budget shared by
	// every scanner and target of one assessment. RateRPS remains the single
	// rate source; Budget enforces it across callers. Nil means no shared
	// budget (legacy scans). Runtime-only.
	Budget *AssessmentBudget `json:"-"`
}

type GVMSSHCredential struct {
	ID   string
	Port int
}

// CloudCredential is a runtime-only, target-bound cloud credential for the cloud
// posture-audit adapters (prowler/scoutsuite). Provider is "aws"/"gcp"/"azure";
// Env carries the credential environment variables (e.g. AWS_ACCESS_KEY_ID). It
// is resolved from the vault at scan start and never written to scan records.
type CloudCredential struct {
	Provider string
	Env      map[string]string
}

// RepoCredential authenticates a repository clone. Username defaults to
// "x-access-token", which GitHub accepts for personal access tokens.
type RepoCredential struct {
	Username string
	Token    string
}

type EmitFunc func(Event)

type Runner interface {
	Name() string
	Descriptor() Descriptor
	Run(context.Context, Request, Config, EmitFunc) Run
}
