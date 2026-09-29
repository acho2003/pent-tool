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
	Target string `json:"target"`
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
	EndpointTargets    []string `json:"-"`
	WebEndpoints       []string `json:"-"`
	StructuredDispatch bool     `json:"-"`
	// SQLMapApprovedURLs are the parameterized URLs an operator has EXPLICITLY
	// approved for SQL-injection detection. SQLMap runs only against these — never
	// against auto-discovered URLs — enforcing the opt-in, approved-request policy.
	SQLMapApprovedURLs []string `json:"-"`
	// CloudCredential is the resolved, target-bound cloud credential for the cloud
	// audit adapters (prowler/scoutsuite). Runtime-only; never serialized.
	CloudCredential CloudCredential `json:"-"`
	// Secrets are extra values redacted from every runner's output, such as the
	// credentials embedded in a clone URL. Pipeline.Run derives them once from
	// the original request, so they survive per-scope copies whose Target no
	// longer holds that URL. Not serialized.
	Secrets []string `json:"-"`
}

type Run struct {
	Scanner            string              `json:"scanner"`
	Authenticated      bool                `json:"authenticated,omitempty"`
	Variant            string              `json:"variant,omitempty"`
	AssessmentTypes    []assessment.Type   `json:"assessment_types,omitempty"`
	PlanFingerprint    string              `json:"plan_fingerprint,omitempty"`
	AttemptID          string              `json:"attempt_id,omitempty"`
	Scope              string              `json:"scope,omitempty"`
	Target             string              `json:"target"`
	Status             string              `json:"status"`
	StartedAt          string              `json:"started_at,omitempty"`
	FinishedAt         string              `json:"finished_at,omitempty"`
	ExitCode           int                 `json:"exit_code,omitempty"`
	Reason             string              `json:"reason,omitempty"`
	StdoutPath         string              `json:"stdout_path,omitempty"`
	StderrPath         string              `json:"stderr_path,omitempty"`
	TranscriptPath     string              `json:"transcript_path,omitempty"`
	ArtifactPath       string              `json:"artifact_path,omitempty"`
	Checksum           string              `json:"checksum,omitempty"`
	Truncated          bool                `json:"truncated,omitempty"`
	APIEndpointResults []APIEndpointResult `json:"api_endpoint_results,omitempty"`
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
	NucleiPath        string
	TrivyPath         string
	VulsPath          string
	VulsSSHConfigPath string
	SubfinderPath     string
	HttpxPath         string
	NmapPath          string
	MasscanPath       string
	NiktoPath         string
	KatanaPath        string
	KatanaChromePath  string
	DalfoxPath        string
	WapitiPath        string
	SqlmapPath        string
	KubeBenchPath     string
	ProwlerPath       string
	ScoutSuitePath    string
	SSHPath           string
	TestsslPath       string
	SemgrepPath       string
	GitleaksPath      string
	OsvPath           string

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
	AssessmentAuthHeaders map[string][]string
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
	MaxOutputBytes       int64
	NucleiTimeout        time.Duration
	ZAPTimeout           time.Duration
	OpenVASTimeout       time.Duration
	TrivyTimeout         time.Duration
	VulsTimeout          time.Duration
	SubfinderTimeout     time.Duration
	HttpxTimeout         time.Duration
	NmapTimeout          time.Duration
	MasscanTimeout       time.Duration
	MasscanRate          int
	NiktoTimeout         time.Duration
	KatanaTimeout        time.Duration
	DalfoxTimeout        time.Duration
	WapitiTimeout        time.Duration
	SqlmapTimeout        time.Duration
	KubeBenchTimeout     time.Duration
	ProwlerTimeout       time.Duration
	ScoutSuiteTimeout    time.Duration
	LynisTimeout         time.Duration
	TestsslTimeout       time.Duration
	SemgrepTimeout       time.Duration
	GitleaksTimeout      time.Duration
	OsvTimeout           time.Duration
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

type EmitFunc func(Event)

type Runner interface {
	Name() string
	Descriptor() Descriptor
	Run(context.Context, Request, Config, EmitFunc) Run
}
