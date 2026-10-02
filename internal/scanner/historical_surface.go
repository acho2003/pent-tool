package scanner

import "time"

// MergeHistoricalCandidates retains every scoped archive observation with its
// source and eligibility. A previously crawled live endpoint is not demoted by
// a duplicate archived observation.
func MergeHistoricalCandidates(surface *AttackSurface, candidates []HistoricalCandidate) {
	if surface == nil {
		return
	}
	byID := make(map[string]int, len(surface.Endpoints))
	for i := range surface.Endpoints {
		byID[surface.Endpoints[i].ID] = i
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, candidate := range candidates {
		if candidate.URL == "" {
			continue
		}
		params := make([]EndpointParameter, 0, len(candidate.QueryKeys))
		for _, key := range candidate.QueryKeys {
			params = append(params, EndpointParameter{Name: key, Location: "query"})
		}
		ep, ok := normalizeAttackSurfaceEndpoint(candidate.URL, "GET", candidate.Provider, now, candidate.Status, "", params, false, false)
		if !ok {
			continue
		}
		ep.State, ep.StateReason = candidate.State, candidate.Reason
		ep.Provenance = []EndpointProvenance{{Tool: candidate.Provider, Source: "archive", ObservedAt: now}}
		if i, exists := byID[ep.ID]; exists && endpointStateDispatchable(surface.Endpoints[i].State) {
			ep.State, ep.StateReason = surface.Endpoints[i].State, surface.Endpoints[i].StateReason
		}
		mergeSurfaceEndpoint(surface, byID, ep)
	}
}
