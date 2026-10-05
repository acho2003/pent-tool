package scanner

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/storage"
)

type DiscoveryCandidate struct {
	Actions     []DiscoveryAction `json:"actions,omitempty"`
	ID          string            `json:"id"`
	Kind        string            `json:"kind"`
	Value       string            `json:"value"`
	Source      string            `json:"source"`
	EvidenceRef string            `json:"evidence_reference,omitempty"`
	State       string            `json:"state"`
}
type DiscoveryPreview struct {
	ApprovedRevision  *DiscoveryRevision   `json:"approved_revision,omitempty"`
	ParentFingerprint string               `json:"parent_fingerprint"`
	Fingerprint       string               `json:"fingerprint"`
	State             string               `json:"state"`
	Candidates        []DiscoveryCandidate `json:"candidates"`
}
type DiscoveryRevision struct {
	ParentFingerprint  string         `json:"parent_fingerprint"`
	PreviewFingerprint string         `json:"preview_fingerprint"`
	AcceptedAt         string         `json:"accepted_at"`
	SelectedIDs        []string       `json:"selected_ids"`
	Plan               AssessmentPlan `json:"plan"`
}

func expandedWorkflowRequest(req Request) bool {
	return UnifiedWorkflowEnabled() && req.WorkflowVersion == "unified-v1"
}

func UnifiedWorkflowEnabled() bool { return os.Getenv("XALGORIX_UNIFIED_WORKFLOW") == "1" }

func BuildDiscoveryPreview(plan AssessmentPlan, runs []Run, surfaces []AttackSurface) DiscoveryPreview {
	p := DiscoveryPreview{ParentFingerprint: plan.Fingerprint, State: "awaiting_approval", Candidates: []DiscoveryCandidate{}}
	known := map[string]bool{}
	for _, t := range plan.Config.Targets {
		known[t.Value] = true
		known[hostFromTarget(t.Value)] = true
		for _, o := range assessment.AppScopeForTarget(plan.Config, t.ID).Origins() {
			if o.PathPrefix == "/" {
				known[o.Origin()] = true
			}
		}
	}
	for _, o := range plan.Config.ApprovedOrigins {
		if o.PathPrefix == "" || o.PathPrefix == "/" {
			known[o.Origin()] = true
		}
	}
	seen := map[string]bool{}
	add := func(kind, value, source, ref string) {
		value = strings.TrimSpace(value)
		if value == "" || known[value] || seen[kind+value] {
			return
		}
		if kind == "host" {
			if strings.ContainsAny(value, "/:@ \\?#") {
				return
			}
		} else {
			u, e := url.Parse(value)
			if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || (u.Scheme != "http" && u.Scheme != "https") {
				return
			}
		}
		seen[kind+value] = true
		actions := proposedDiscoveryActions(plan.Config, kind)
		p.Candidates = append(p.Candidates, DiscoveryCandidate{Actions: actions, ID: inventoryID(kind, value), Kind: kind, Value: value, Source: source, EvidenceRef: ref, State: "candidate"})
	}
	for _, r := range runs {
		for _, h := range r.CandidateHosts {
			add("host", h, r.Scanner, r.ArtifactPath)
		}
		for _, o := range r.HTTPObservations {
			if origin, e := assessment.ParseApprovedOrigin("", o.URL); e == nil {
				add("origin", origin.Origin(), r.Scanner, r.ArtifactPath)
			}
		}
	}
	for _, s := range surfaces {
		for _, e := range s.Endpoints {
			if e.State == EndpointStateOutOfScope {
				if o, err := assessment.ParseApprovedOrigin("", e.URL); err == nil {
					add("origin", o.Origin(), "inventory", "")
				}
			}
		}
		for _, definition := range s.Definitions {
			for _, origin := range definition.CandidateOrigins {
				add("origin", origin, "schema", definition.EvidenceRef)
			}
		}
		for _, service := range s.Services {
			if service.Origin != "" {
				add("origin", service.Origin, "service", service.EvidenceRef)
			}
		}
	}
	sort.Slice(p.Candidates, func(i, j int) bool { return p.Candidates[i].ID < p.Candidates[j].ID })
	b, _ := json.Marshal(p)
	p.Fingerprint = inventoryID(string(b))
	if len(p.Candidates) == 0 {
		p.State = "no_candidates"
	}
	return p
}

// Approval copies configuration; it never transfers credentials to new targets.
func ApproveDiscoveryConfig(plan AssessmentPlan, preview DiscoveryPreview, fingerprint string, selected []string) (assessment.AssessmentConfig, error) {
	if fingerprint != preview.Fingerprint {
		return assessment.AssessmentConfig{}, fmt.Errorf("stale discovery preview")
	}
	b, _ := json.Marshal(plan.Config)
	var cfg assessment.AssessmentConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	candidates := map[string]DiscoveryCandidate{}
	for _, c := range preview.Candidates {
		candidates[c.ID] = c
	}
	seen := map[string]bool{}
	for _, id := range selected {
		c, ok := candidates[id]
		if !ok {
			return cfg, fmt.Errorf("unknown candidate")
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		kind := assessment.KindHost
		if c.Kind == "host" && !slices.Contains(cfg.Types, assessment.TypeNetwork) {
			cfg.Types = append(cfg.Types, assessment.TypeNetwork)
		}
		if c.Kind == "origin" {
			kind = assessment.KindURL
		}
		targetID := "discovered-" + id
		cfg.Targets = append(cfg.Targets, assessment.Target{ID: targetID, Kind: kind, Value: c.Value})
	}
	if len(seen) == 0 {
		return cfg, fmt.Errorf("select at least one candidate")
	}
	cfg.SubdomainDiscovery = false
	if cfg.DiscoveryProviders != nil {
		cfg.DiscoveryProviders.Subdomain = nil
	}
	for _, problem := range assessment.Validate(cfg) {
		if problem.Blocking {
			return cfg, fmt.Errorf("%s", problem.Message)
		}
	}
	return cfg, nil
}
func SaveDiscoveryRevision(dir string, revision DiscoveryRevision) error {
	if err := storage.EnsureSecureDir(filepath.Join(dir, "revisions")); err != nil {
		return err
	}
	if revision.AcceptedAt == "" {
		revision.AcceptedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	b, err := json.MarshalIndent(revision, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "revisions", inventoryID(revision.Plan.Fingerprint)+".json")
	temporary, err := os.CreateTemp(filepath.Dir(path), ".revision-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err = temporary.Write(b); err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	// An atomic exclusive link publishes a fully written revision. Never rename
	// over an already accepted plan, including concurrent duplicate approvals.
	if err = os.Link(temporary.Name(), path); err != nil {
		if !os.IsExist(err) {
			return err
		}
		previous, loadErr := LoadDiscoveryRevision(dir, revision.Plan.Fingerprint)
		if loadErr != nil {
			return loadErr
		}
		revision.AcceptedAt = previous.AcceptedAt
		expected, _ := json.Marshal(revision)
		actual, _ := json.Marshal(previous)
		if string(expected) != string(actual) {
			return fmt.Errorf("accepted revision is immutable")
		}
		return nil
	}
	if parent, err := os.Open(filepath.Dir(path)); err == nil {
		defer parent.Close()
		return parent.Sync()
	}
	return nil
}

func scopeForInventoryJob(job PlanJob) string { return "app:" + job.TargetID }

func LoadDiscoveryRevision(dir, fingerprint string) (DiscoveryRevision, error) {
	var revision DiscoveryRevision
	data, err := os.ReadFile(filepath.Join(dir, "revisions", inventoryID(fingerprint)+".json"))
	if err != nil {
		return revision, err
	}
	err = json.Unmarshal(data, &revision)
	if err == nil && revision.Plan.Fingerprint != fingerprint {
		return revision, fmt.Errorf("revision fingerprint mismatch")
	}
	return revision, err
}
func FindApprovedDiscoveryRevision(dir, previewFingerprint string) *DiscoveryRevision {
	entries, err := os.ReadDir(filepath.Join(dir, "revisions"))
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, "revisions", entry.Name()))
		if err != nil {
			continue
		}
		var revision DiscoveryRevision
		if json.Unmarshal(data, &revision) == nil && revision.PreviewFingerprint == previewFingerprint {
			return &revision
		}
	}
	return nil
}
