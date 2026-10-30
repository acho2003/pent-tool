package web

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/apifixture"
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

func TestNextjsBoundaryPreviewRequiresScopedUntamperedFixtures(t *testing.T) {
	for _, mode := range []string{"valid", "unapproved-destination", "missing-manifest", "tampered-manifest", "wrong-kind", "missing-reset-body"} {
		t.Run(mode, func(t *testing.T) {
			s := newTestServer(t, nil)
			store := apifixture.Store{Dir: filepath.Join(s.dataDir, "_api_fixtures")}
			f := scanner.NextjsBoundaryFixture{Kind: "proxy", URL: "https://app.test/proxy?url=%2Fcontrolled", Parameter: "url", CallbackURL: "https://collector.test/hit", EventsURL: "https://collector.test/events"}
			if mode == "missing-reset-body" {
				f = scanner.NextjsBoundaryFixture{Kind: "cache", URL: "https://app.test/private", Representation: "pages-json", PrivateMarker: "PRIVATE_CONTROLLED_42", DeniedMarker: "DENIED_CONTROLLED_42", BypassURL: "https://app.test/private?uncached=1", Isolated: true, CleanupURL: "https://app.test/reset", CleanupMethod: "PUT", CleanupBodyRef: strings.Repeat("b", 64), CleanupContentType: "application/json"}
			}
			raw, _ := json.Marshal(f)
			meta, err := store.Put(bytes.NewReader(raw), "application/json")
			if err != nil {
				t.Fatal(err)
			}
			targetOrigin, _ := assessment.ParseApprovedOrigin("app", "https://app.test/")
			collectorOrigin, _ := assessment.ParseApprovedOrigin("app", "https://collector.test/")
			plan := scanner.AssessmentPlan{Config: assessment.AssessmentConfig{Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.test/"}}, ApprovedOrigins: []assessment.ApprovedOrigin{targetOrigin, collectorOrigin}, NextjsBoundaryApprovals: []assessment.NextjsBoundaryApproval{{TargetID: "app", Kind: f.Kind, FixtureRef: meta.Ref}}}}
			switch mode {
			case "unapproved-destination":
				plan.Config.ApprovedOrigins = nil
			case "missing-manifest":
				plan.Config.NextjsBoundaryApprovals[0].FixtureRef = strings.Repeat("f", 64)
			case "tampered-manifest":
				if err := os.WriteFile(filepath.Join(store.Dir, meta.Ref+".body"), []byte(`{"kind":"proxy"}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-kind":
				plan.Config.NextjsBoundaryApprovals[0].Kind = "redirect"
			}
			s.validateNextjsBoundaryFixtures(&plan)
			if (mode == "valid") != (len(plan.Errors) == 0) {
				t.Fatalf("unexpected preview errors: %+v", plan.Errors)
			}
		})
	}
}
func TestBoundaryReportPreservesAttributionAndCallbackProof(t *testing.T) {
	proof := scanner.BuildCoverageProof(nil, []scanner.Run{{AuthorizationResults: []scanner.AuthorizationResult{{CaseID: "cache-probe", Representation: "cache-boundary", CacheAttribution: "unverified", CleanupStatus: "verified"}, {CaseID: "fetch-probe", Representation: "proxy-boundary", CorrelationDigest: "controlled-correlation-digest"}}}})
	lines := strings.Join(assessmentCoverageLines(assessmentCoverageResponse{Proof: &proof}), "\n")
	for _, value := range []string{"Cache attribution: unverified", "Callback correlation digest: controlled-correlation-digest", "cache-boundary"} {
		if !strings.Contains(lines, value) {
			t.Fatalf("boundary proof missing: %s", lines)
		}
	}
}
