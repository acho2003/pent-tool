package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/acho2003/pent-tool/internal/assessment"
)

// sourceRouteSeeds returns inventory operations for the routes declared in the
// source target a URL target is explicitly linked to with related_to. Without
// that link, or outside White Box mode, it returns nothing: a source tree is
// never associated with a URL by guesswork. The extracted route list is saved
// beside the target's discovery artifacts as evidence.
func (p *Pipeline) sourceRouteSeeds(ctx context.Context, cfg assessment.AssessmentConfig, scanDir string, target assessment.Target, targetByID map[string]assessment.Target, repoCheckouts map[string]repoCheckout, surface *AttackSurface) []APIEndpoint {
	if target.RelatedTo == "" || cfg.Mode != assessment.ModeWhiteBox {
		return nil
	}
	source, ok := targetByID[target.RelatedTo]
	if !ok {
		return nil
	}
	var dir string
	switch source.Kind {
	case assessment.KindLocalSourcePath:
		if reason := prepareLocalAssessmentResource(cfg.Mode, source.Kind, source.Value, sourceRoutesTool); reason != "" {
			surface.DiscoveryGaps = append(surface.DiscoveryGaps, "routes from linked source were not read: "+reason)
			return nil
		}
		dir = source.Value
	case assessment.KindRepository:
		checkout, reason := prepareRepositoryCheckout(ctx, scanDir, source.ID, source.Value, p.Config.AssessmentRepoCreds[source.ID], repoCheckouts, source.Branch)
		if reason != "" {
			surface.DiscoveryGaps = append(surface.DiscoveryGaps, "routes from linked source were not read: "+reason)
			return nil
		}
		dir = checkout
	default:
		return nil
	}
	routes, gaps := ExtractSourceRoutes(ctx, dir)
	for _, gap := range gaps {
		surface.DiscoveryGaps = append(surface.DiscoveryGaps, "linked source routes: "+gap)
	}
	evidenceDir := filepath.Join(scanDir, "discovery", stableJobPath(target.ID))
	if err := os.MkdirAll(evidenceDir, 0700); err == nil {
		if body, err := json.MarshalIndent(struct {
			SourceTargetID string        `json:"source_target_id"`
			Routes         []SourceRoute `json:"routes"`
			Gaps           []string      `json:"gaps,omitempty"`
		}{source.ID, routes, gaps}, "", "  "); err == nil {
			_ = os.WriteFile(filepath.Join(evidenceDir, "source-routes.json"), body, 0600)
		}
	}
	return SourceRoutesToAPIEndpoints(routes, target.ID, source.ID)
}
