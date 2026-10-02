package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/storage"
)

// WorkflowManifestSchemaVersion is the only manifest schema LoadWorkflowManifest
// accepts. Any other value (including a missing one) reads as "no manifest".
const WorkflowManifestSchemaVersion = 1

// StageStatus is the recorded outcome of one workflow stage.
type StageStatus string

const (
	StageStatusRunning   StageStatus = "running"
	StageStatusCompleted StageStatus = "completed"
	StageStatusPartial   StageStatus = "partial"
	StageStatusFailed    StageStatus = "failed"
	StageStatusSkipped   StageStatus = "skipped"
)

// WorkflowManifest is a DERIVED record of a typed assessment's execution: the
// executor writes it after each stage from the same resume decision it already
// makes (run key plus VerifyChecksum). It is never consulted as a second gate;
// it exists so operators and later runs can see which stages ran under which
// policy, inputs and tool versions. It never holds credentials or credential
// references.
type WorkflowManifest struct {
	SchemaVersion   int            `json:"schema_version"`
	PlanFingerprint string         `json:"plan_fingerprint"`
	AcceptedPolicy  WorkflowPolicy `json:"accepted_policy"`
	UpdatedAt       string         `json:"updated_at,omitempty"`
	Stages          []StageRecord  `json:"stages"`
}

// WorkflowPolicy is the credential-free subset of the accepted assessment
// configuration that governs what traffic is allowed. Hash covers every other
// field and feeds StageInputChecksum.
type WorkflowPolicy struct {
	Hash               string                         `json:"hash"`
	RegistryVersion    string                         `json:"registry_version,omitempty"`
	Mode               assessment.Mode                `json:"assessment_mode,omitempty"`
	Types              []assessment.Type              `json:"assessment_types,omitempty"`
	Profile            string                         `json:"profile,omitempty"`
	ApprovedOrigins    []assessment.ApprovedOrigin    `json:"approved_origins,omitempty"`
	Exclusions         []assessment.Exclusion         `json:"exclusions,omitempty"`
	TestEnvironment    bool                           `json:"test_environment,omitempty"`
	SubdomainDiscovery bool                           `json:"subdomain_discovery,omitempty"`
	DiscoveryProviders *assessment.DiscoveryProviders `json:"discovery_providers,omitempty"`
}

// StageRecord is one stage's derived outcome. InputChecksum comes from
// StageInputChecksum; OutputChecksums are the sealed Run.Checksum values of the
// stage's runs (RunOutputChecksums). Timestamps are RFC 3339.
type StageRecord struct {
	Stage           string            `json:"stage"`
	JobIDs          []string          `json:"job_ids,omitempty"`
	Status          StageStatus       `json:"status"`
	GapKind         GapKind           `json:"gap_kind,omitempty"`
	InputChecksum   string            `json:"input_checksum,omitempty"`
	OutputChecksums []string          `json:"output_checksums,omitempty"`
	ToolVersions    map[string]string `json:"tool_versions,omitempty"`
	StartedAt       string            `json:"started_at,omitempty"`
	FinishedAt      string            `json:"finished_at,omitempty"`
}

// WorkflowManifestPath is <scanDir>/workflow/workflow-v1.json.
func WorkflowManifestPath(scanDir string) string {
	return filepath.Join(scanDir, "workflow", "workflow-v1.json")
}

// AcceptedPolicyFromConfig extracts the credential-free policy of an accepted
// configuration (access bindings are deliberately left out) and seals it.
func AcceptedPolicyFromConfig(cfg assessment.AssessmentConfig, registryVersion string) WorkflowPolicy {
	p := WorkflowPolicy{
		RegistryVersion: registryVersion, Mode: cfg.Mode, Types: slices.Clone(cfg.Types), Profile: cfg.Profile,
		ApprovedOrigins: slices.Clone(cfg.ApprovedOrigins), Exclusions: slices.Clone(cfg.Exclusions),
		TestEnvironment: cfg.TestEnvironment, SubdomainDiscovery: cfg.SubdomainDiscovery,
	}
	if cfg.DiscoveryProviders != nil {
		dp := *cfg.DiscoveryProviders
		dp.Subdomain = slices.Clone(dp.Subdomain)
		p.DiscoveryProviders = &dp
	}
	p.Hash = p.ComputeHash()
	return p
}

// ComputeHash hashes every policy field except Hash itself.
func (p WorkflowPolicy) ComputeHash() string {
	p.Hash = ""
	data, _ := json.Marshal(p)
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// StageInputChecksum seals everything a stage consumes: the accepted policy,
// the output checksums of its upstream stages and any other input artifacts
// (fixtures, API definitions). Because upstream outputs are part of the input,
// re-running discovery invalidates downstream DAST and validation. Both lists
// are treated as sets (order-insensitive, nil == empty, blanks ignored) and are
// domain separated from each other.
func StageInputChecksum(policyHash string, upstreamOutputChecksums, artifactChecksums []string) string {
	data, _ := json.Marshal(struct {
		Version   int      `json:"v"`
		Policy    string   `json:"policy"`
		Upstream  []string `json:"upstream"`
		Artifacts []string `json:"artifacts"`
	}{1, policyHash, checksumSet(upstreamOutputChecksums), checksumSet(artifactChecksums)})
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// RunOutputChecksums returns the sorted, de-duplicated sealed checksums of
// runs; runs without a checksum (failed, not run) contribute nothing.
func RunOutputChecksums(runs []Run) []string {
	out := make([]string, 0, len(runs))
	for _, run := range runs {
		out = append(out, run.Checksum)
	}
	return checksumSet(out)
}

func checksumSet(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v != "" {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// StageReusable reports whether a stage's prior outcome may ever be reused on
// resume. Authentication is never reused: sessions expire between attempts, so
// it is always reverified before resumed authenticated work.
func StageReusable(stage string) bool {
	return stage != StageAuth
}

// Reusable reports whether this record describes a cleanly completed stage
// whose inputs and per-stage tool versions match the current ones, so only
// stages whose inputs or tools changed are invalidated. It is advisory: the
// executor's run key and VerifyChecksum remain the authority over reuse.
func (r StageRecord) Reusable(inputChecksum string, toolVersions map[string]string) bool {
	if !StageReusable(r.Stage) || r.Status != StageStatusCompleted || r.GapKind != "" {
		return false
	}
	if r.InputChecksum == "" || r.InputChecksum != inputChecksum {
		return false
	}
	return maps.Equal(r.ToolVersions, toolVersions)
}

// SetStage inserts or replaces the record for rec.Stage.
func (m *WorkflowManifest) SetStage(rec StageRecord) {
	for i := range m.Stages {
		if m.Stages[i].Stage == rec.Stage {
			m.Stages[i] = rec
			return
		}
	}
	m.Stages = append(m.Stages, rec)
}

// Stage returns the record for a stage, if one was written.
func (m *WorkflowManifest) Stage(stage string) (StageRecord, bool) {
	if m == nil {
		return StageRecord{}, false
	}
	for _, rec := range m.Stages {
		if rec.Stage == stage {
			return rec, true
		}
	}
	return StageRecord{}, false
}

// SaveWorkflowManifest atomically writes the manifest with the current schema
// version, stages in workflow order. The caller's value is not modified.
func SaveWorkflowManifest(scanDir string, manifest *WorkflowManifest) error {
	if manifest == nil {
		return fmt.Errorf("nil workflow manifest")
	}
	out := *manifest
	out.SchemaVersion = WorkflowManifestSchemaVersion
	out.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	out.Stages = slices.Clone(manifest.Stages)
	if out.Stages == nil {
		out.Stages = []StageRecord{}
	}
	sort.SliceStable(out.Stages, func(i, j int) bool {
		ri, rj := stageRank(out.Stages[i].Stage), stageRank(out.Stages[j].Stage)
		if ri != rj {
			return ri < rj
		}
		return out.Stages[i].Stage < out.Stages[j].Stage
	})
	path := WorkflowManifestPath(scanDir)
	if err := storage.EnsureSecureDir(filepath.Dir(path)); err != nil {
		return err
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return storage.WriteAtomic(path, append(data, '\n'))
}

// LoadWorkflowManifest reads the manifest strictly: a missing, unreadable,
// corrupt or other-schema file returns (nil, false), which callers treat as a
// legacy scan with no manifest.
func LoadWorkflowManifest(scanDir string) (*WorkflowManifest, bool) {
	data, err := os.ReadFile(WorkflowManifestPath(scanDir))
	if err != nil {
		return nil, false
	}
	var manifest WorkflowManifest
	if json.Unmarshal(data, &manifest) != nil || manifest.SchemaVersion != WorkflowManifestSchemaVersion {
		return nil, false
	}
	return &manifest, true
}
