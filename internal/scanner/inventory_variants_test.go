package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInventoryPreservesRequestSemantics(t *testing.T) {
	urls := []string{"https://app.test/a/", "https://app.test/a", "https://app.test/a%2Fb", "https://app.test/a/b", "https://app.test/a?q=1&q=2", "https://app.test/a?q=1", "https://app.test/a?q=2"}
	seen := map[string]bool{}
	for _, u := range urls {
		ep, ok := normalizeAttackSurfaceEndpoint(u, "GET", "test", "", 200, "", endpointParameters(u), false, false)
		if !ok || seen[ep.ID] || ep.URL != u {
			t.Fatalf("collapsed or changed %s: %+v", u, ep)
		}
		seen[ep.ID] = true
	}
	p := filepath.Join(t.TempDir(), "crawl.jsonl")
	os.WriteFile(p, []byte(`{"request":{"endpoint":"https://app.test/api","method":"POST","body":"id=1","headers":{"content-type":"application/x-www-form-urlencoded"}}}
{"request":{"endpoint":"https://app.test/api","method":"POST","body":"id=2","headers":{"content-type":"application/x-www-form-urlencoded"}}}`), 0600)
	s, err := ParseKatanaAttackSurface(p, "app:test", "https://app.test", false)
	if err != nil || len(s.Endpoints) != 2 || s.Endpoints[0].BodyDigest == s.Endpoints[1].BodyDigest {
		t.Fatalf("body variants lost %+v %v", s, err)
	}
}
func TestCoverageRetainsSeparateAttempts(t *testing.T) {
	s := NewSeedAttackSurface("test", "https://app.test/?q=1")
	for _, id := range []string{"first", "second"} {
		DispatchTargets(s, "zap", 100)
		CompleteEndpointCoverage(s, "zap", Run{Status: "completed", AttemptID: id, PlanFingerprint: "plan", ArtifactPath: "evidence"})
	}
	history := s.Endpoints[0].CoverageHistory
	if len(history) != 2 || history[0].AttemptID != "first" || history[1].AttemptID != "second" || history[1].Status != EndpointCoverageBatchCompleted {
		t.Fatal(history)
	}
}
