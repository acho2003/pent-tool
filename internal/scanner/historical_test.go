package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestHistoricalCandidatesRedactAndNeverFetchExcludedRoutes(t *testing.T) {
	var contacts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { contacts.Add(1); w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	u.Host = "localhost:" + u.Port()
	base := u.String()
	ac := assessment.Normalize(assessment.AssessmentConfig{Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: base}}, Exclusions: []assessment.Exclusion{{PathPattern: "/logout"}}})
	scope := assessment.AppScopeForTarget(ac, "app")
	dir := t.TempDir()
	tool := filepath.Join(dir, "gau")
	script := "#!/bin/sh\nprintf '%s\\n' '" + base + "/logout?token=secret-value' 'http://other.example.test/?key=other-secret'\n"
	if err := os.WriteFile(tool, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	run := (historicalRunner{provider: "gau"}).Run(context.Background(), Request{Target: base, ScanDir: dir, AppScope: &scope}, Config{GauPath: tool}, nil)
	if run.Status != "completed" || len(run.HistoricalCandidates) != 2 || contacts.Load() != 0 {
		t.Fatalf("historical scope/revalidation failure: %+v contacts=%d", run, contacts.Load())
	}
	if run.HistoricalCandidates[0].State != EndpointStateExcluded || run.HistoricalCandidates[1].State != EndpointStateOutOfScope {
		t.Fatalf("bad candidate states: %+v", run.HistoricalCandidates)
	}
	artifact, err := os.ReadFile(run.ArtifactPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(artifact), "secret-value") || strings.Contains(string(artifact), "other-secret") {
		t.Fatalf("archived query secrets persisted: %s", artifact)
	}
}

func TestMergeHistoricalCandidateDoesNotDemoteLiveEndpoint(t *testing.T) {
	surface := NewSeedAttackSurface("app:one", "https://example.test/app")
	MergeHistoricalCandidates(surface, []HistoricalCandidate{{URL: "https://example.test/app", Provider: "gau", State: EndpointStateHistoricalUnverified, Reason: "archive only"}})
	if len(surface.Endpoints) != 1 || !endpointStateDispatchable(surface.Endpoints[0].State) || len(surface.Endpoints[0].Provenance) == 0 {
		t.Fatalf("historical duplicate demoted a live seed: %+v", surface.Endpoints)
	}
}
