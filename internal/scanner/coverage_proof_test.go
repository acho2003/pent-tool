package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestCoverageSeparatesSeedingFromActiveEvidence(t *testing.T) {
	surface := NewSeedAttackSurface("app:test", "https://app.test/?q=1")
	id := surface.Endpoints[0].ID
	events := []CoverageEvent{{Kind: "observed", Phase: "seeding", EndpointIDs: []string{id}}, {Kind: "submitted", Phase: "routing", EndpointIDs: []string{id}}}
	p := filepath.Join(t.TempDir(), "events.jsonl")
	f, _ := os.Create(p)
	for _, e := range events {
		json.NewEncoder(f).Encode(e)
	}
	f.Close()
	proof := BuildCoverageProof([]AttackSurface{*surface}, []Run{{Scanner: "zap", Scope: "app:test", CoverageEventsPath: p}})
	if len(proof.Scanners) != 1 || proof.Scanners[0].Exercised == nil || *proof.Scanners[0].Exercised != 0 || proof.Scanners[0].Submitted != 1 {
		t.Fatal(proof)
	}
}
func TestEveryOneOf684RequestsHasInputDisposition(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	surface := NewSeedAttackSurface("app:test", "https://app.test/")
	byID := map[string]int{}
	for i := 0; i < 684; i++ {
		raw := fmt.Sprintf("https://app.test/api/%d?q=1", i)
		ep, _ := normalizeAttackSurfaceEndpoint(raw, "GET", "fixture", "", 200, "application/json", endpointParameters(raw), false, false)
		mergeSurfaceEndpoint(surface, byID, ep)
	}
	for _, name := range []string{"nuclei", "zap", "wapiti", "dalfox"} {
		req := Request{EndpointTargets: DispatchTargets(surface, name, 700), AttemptID: "attempt", PlanFingerprint: "plan", ScanDir: t.TempDir()}
		req.InputRequests = BuildScannerInputs(surface, req, name)
		path, err := SaveScannerInputs(req, name)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(path)
		var manifest ScannerInputManifest
		json.Unmarshal(data, &manifest)
		selected := 0
		for _, input := range manifest.Requests {
			if input.Selected {
				selected++
			} else if input.Reason == "" {
				t.Fatalf("%s lacks disposition for %s", name, input.EndpointID)
			}
		}
		want := 684
		if name == "zap" || name == "nuclei" {
			want = 685
		}
		if selected != want || len(manifest.Requests) != 685 {
			t.Fatalf("%s selected=%d total=%d", name, selected, len(manifest.Requests))
		}
	}
}

func TestProofDrilldownMatchesCountsAndUsesInventoryScope(t *testing.T) {
	surface := NewSeedAttackSurface("host:app", "https://app.test/?q=1")
	req := Request{EndpointTargets: []string{surface.Endpoints[0].URL}, ScanDir: t.TempDir()}
	req.InputRequests = BuildScannerInputs(surface, req, "zap")
	path, err := SaveScannerInputs(req, "zap")
	if err != nil {
		t.Fatal(err)
	}
	proof := BuildCoverageProof([]AttackSurface{*surface}, []Run{{Scanner: "zap", Scope: "app:app", AttemptID: "attempt", InputManifestPath: path, Submissions: []EndpointSubmission{{EndpointID: surface.Endpoints[0].ID, Status: "acknowledged"}}}})
	if len(proof.Scanners) != 1 || proof.Scanners[0].Selected != 1 || proof.Scanners[0].Acknowledged != 1 {
		t.Fatal(proof.Scanners)
	}
	for metric, count := range map[string]int{"discovered": proof.Discovered, "seeds": proof.Seeds, "approved": proof.Approved, "eligible": proof.Eligible, "zap:selected": proof.Scanners[0].Selected, "zap:acknowledged": proof.Scanners[0].Acknowledged, "zap:unknown": proof.Scanners[0].Unknown} {
		if len(proof.Items[metric]) != count {
			t.Fatalf("%s count=%d items=%v", metric, count, proof.Items[metric])
		}
	}
	if proof.Items["zap:acknowledged"][0].Scope != "host:app" {
		t.Fatal("lost inventory relationship")
	}
}

func TestEmptyCoverageProofCollectionsRemainJSONArrays(t *testing.T) {
	proof := BuildCoverageProof(nil, nil)
	data, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"scanners", "definitions", "not_tracked", "discovery_gaps"} {
		var items []any
		if string(decoded[field]) == "null" || json.Unmarshal(decoded[field], &items) != nil {
			t.Fatalf("%s is not an array: %s", field, decoded[field])
		}
	}
}
