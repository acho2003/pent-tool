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

func TestNextjsActionPreviewValidatesManifestAndNestedBodyChecksums(t *testing.T) {
	for _, mode := range []string{"valid", "missing-body", "corrupt-body", "foreign-cleanup", "excluded", "unsupported-field"} {
		t.Run(mode, func(t *testing.T) {
			s := newTestServer(t, nil)
			store := apifixture.Store{Dir: filepath.Join(s.dataDir, "_api_fixtures")}
			body, err := store.Put(strings.NewReader(`["controlled"]`), "text/plain")
			if err != nil {
				t.Fatal(err)
			}
			manifest := scanner.NextjsActionFixture{URL: "https://app.test/action", ActionID: strings.Repeat("a", 40), ContentType: "text/plain", BodyRef: body.Ref, VerificationURL: "https://app.test/state", ReadyMarker: "CONTROLLED_READY", ChangedMarker: "CONTROLLED_CHANGED", CleanupURL: "https://app.test/reset", CleanupMethod: "DELETE"}
			if mode == "missing-body" {
				manifest.BodyRef = strings.Repeat("b", 64)
			}
			if mode == "corrupt-body" {
				if err := os.WriteFile(filepath.Join(store.Dir, body.Ref+".body"), []byte("tampered"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "foreign-cleanup" {
				manifest.CleanupURL = "https://other.test/reset"
			}
			raw, _ := json.Marshal(manifest)
			if mode == "unsupported-field" {
				raw = append(raw[:len(raw)-1], []byte(`,"headers":{"Host":"other.test"}}`)...)
			}
			meta, err := store.Put(bytes.NewReader(raw), "application/json")
			if err != nil {
				t.Fatal(err)
			}
			plan := scanner.AssessmentPlan{Config: assessment.AssessmentConfig{Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.test/"}}, NextjsActionApprovals: []assessment.NextjsActionApproval{{TargetID: "app", FixtureRef: meta.Ref}}}}
			if mode == "excluded" {
				plan.Config.Exclusions = []assessment.Exclusion{{Method: "POST", PathPattern: "/action"}}
			}
			s.validateNextjsActionFixtures(&plan)
			if (mode == "valid") != (len(plan.Errors) == 0) {
				t.Fatalf("preview errors for %s: %+v", mode, plan.Errors)
			}
		})
	}
}
