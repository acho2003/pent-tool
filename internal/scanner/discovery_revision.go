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
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Value       string `json:"value"`
	Source      string `json:"source"`
	EvidenceRef string `json:"evidence_reference,omitempty"`
	State       string `json:"state"`
}
type DiscoveryPreview struct {
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

func UnifiedWorkflowEnabled() bool { return os.Getenv("XALGORIX_UNIFIED_WORKFLOW") == "1" }

func BuildDiscoveryPreview(plan AssessmentPlan, runs []Run, surfaces []AttackSurface) DiscoveryPreview {
	p := DiscoveryPreview{ParentFingerprint: plan.Fingerprint, State: "awaiting_approval", Candidates: []DiscoveryCandidate{}}
	known := map[string]bool{}
	for _, t := range plan.Config.Targets {
		known[t.Value] = true
		known[hostFromTarget(t.Value)] = true
	}
	for _, o := range plan.Config.ApprovedOrigins {
		known[o.Origin()] = true
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
		p.Candidates = append(p.Candidates, DiscoveryCandidate{ID: inventoryID(kind, value), Kind: kind, Value: value, Source: source, EvidenceRef: ref, State: "candidate"})
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
	return storage.WriteAtomic(filepath.Join(dir, "revisions", inventoryID(revision.Plan.Fingerprint)+".json"), b)
}

func scopeForInventoryJob(job PlanJob) string { return "app:" + job.TargetID }
