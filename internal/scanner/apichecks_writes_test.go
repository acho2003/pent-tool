package scanner

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/apifixture"
	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestAPIWriteIsJournaledExecutedOnceAndCleanedWithoutBody(t *testing.T) {
	var creates, deletes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/items":
			creates.Add(1)
			body, _ := io.ReadAll(r.Body)
			if string(body) != `{"name":"fixture"}` || r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("unexpected write body/content-type: %q %q", body, r.Header.Get("Content-Type"))
			}
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/items/test-item":
			deletes.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer server.Close()
	scanDir, fixtureDir := t.TempDir(), filepath.Join(t.TempDir(), "fixtures")
	fixture, err := (apifixture.Store{Dir: fixtureDir}).Put(bytes.NewReader([]byte(`{"name":"fixture"}`)), "application/json")
	if err != nil {
		t.Fatal(err)
	}
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeGrayBox, Types: []assessment.Type{assessment.TypeAPI}, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: server.URL + "/api"}}}
	scope := assessment.AppScopeForTarget(cfg, "app")
	approval := assessment.WriteApproval{TargetID: "app", Method: "POST", Path: "/items", OperationID: "createItem", FixtureRef: fixture.Ref, ContentType: fixture.ContentType, CleanupMethod: http.MethodDelete, CleanupPath: "/items/test-item"}
	req := Request{Target: server.URL + "/api", Scope: "app:app", ScanDir: scanDir, TypedAssessment: true, TestEnvironment: true, AppScope: &scope, APIFixtureDir: fixtureDir, APIOperationEndpoints: []APIEndpoint{{Method: "POST", Path: "/items", OperationID: "createItem"}}, WriteApprovals: []assessment.WriteApproval{approval}}
	run := (apiWritesRunner{}).Run(context.Background(), req, Config{APIFixtureDir: fixtureDir, Budget: NewAssessmentBudget(100, 10, time.Minute)}, nil)
	if run.Status != "completed" || len(run.APIEndpointResults) != 1 || run.APIEndpointResults[0].Status != "completed" {
		t.Fatalf("write result=%+v", run)
	}
	entries, err := LoadWriteJournal(scanDir)
	if err != nil || len(entries) != 1 || entries[0].State != WriteStateCleanupDone || entries[0].CleanupMethod != http.MethodDelete {
		t.Fatalf("journal entries=%+v err=%v", entries, err)
	}
	// The duplicate request is denied by the persistent journal even if a caller
	// mistakenly asks the runner to execute this plan again.
	again := (apiWritesRunner{}).Run(context.Background(), req, Config{APIFixtureDir: fixtureDir, Budget: NewAssessmentBudget(100, 10, time.Minute)}, nil)
	if again.Status != "failed" || creates.Load() != 1 || deletes.Load() != 1 {
		t.Fatalf("write replayed: status=%s creates=%d deletes=%d", again.Status, creates.Load(), deletes.Load())
	}
	data, err := os.ReadFile(run.ArtifactPath)
	if err != nil || !bytes.Contains(data, []byte(`"status":"completed"`)) {
		t.Fatalf("write evidence missing: %s err=%v", data, err)
	}
}

func TestAPIWriteRefusesMissingFixtureAndExclusionsBeforeSending(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeGrayBox, Types: []assessment.Type{assessment.TypeAPI}, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: server.URL + "/api"}}, Exclusions: []assessment.Exclusion{{TargetID: "app", Method: http.MethodPost, PathPattern: "/api/items"}}}
	scope := assessment.AppScopeForTarget(cfg, "app")
	req := Request{Target: server.URL + "/api", Scope: "app:app", ScanDir: t.TempDir(), TypedAssessment: true, TestEnvironment: true, AppScope: &scope,
		APIOperationEndpoints: []APIEndpoint{{Method: "POST", Path: "/items", OperationID: "create"}}, WriteApprovals: []assessment.WriteApproval{{TargetID: "app", Method: http.MethodPost, Path: "/items", OperationID: "create", FixtureRef: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ContentType: "application/json", CleanupMethod: http.MethodDelete, CleanupPath: "/items/1"}}}
	run := (apiWritesRunner{}).Run(context.Background(), req, Config{APIFixtureDir: t.TempDir(), Budget: NewAssessmentBudget(100, 10, time.Minute)}, nil)
	if requests.Load() != 0 || run.Status != "failed" || len(run.APIEndpointResults) != 1 || run.APIEndpointResults[0].Status != "skipped" {
		t.Fatalf("excluded request sent or not recorded: requests=%d run=%+v", requests.Load(), run)
	}
}

func TestAPIWriteRequiresExactBoundOpenAPIOperation(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	fixtureDir := filepath.Join(t.TempDir(), "fixtures")
	fixture, err := (apifixture.Store{Dir: fixtureDir}).Put(bytes.NewReader([]byte(`{"name":"fixture"}`)), "application/json")
	if err != nil {
		t.Fatal(err)
	}
	assessmentCfg := assessment.AssessmentConfig{Mode: assessment.ModeGrayBox, Types: []assessment.Type{assessment.TypeAPI}, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: server.URL + "/api"}}}
	scope := assessment.AppScopeForTarget(assessmentCfg, "app")
	req := Request{Target: server.URL + "/api", Scope: "app:app", ScanDir: t.TempDir(), TypedAssessment: true, TestEnvironment: true, AppScope: &scope, APIFixtureDir: fixtureDir,
		APIOperationEndpoints: []APIEndpoint{{Method: http.MethodPost, Path: "/items", OperationID: "another-operation"}},
		WriteApprovals:        []assessment.WriteApproval{{TargetID: "app", Method: http.MethodPost, Path: "/items", OperationID: "create", FixtureRef: fixture.Ref, ContentType: fixture.ContentType, CleanupMethod: http.MethodDelete, CleanupPath: "/items/1"}}}
	run := (apiWritesRunner{}).Run(context.Background(), req, Config{Budget: NewAssessmentBudget(100, 10, time.Minute)}, nil)
	if requests.Load() != 0 || run.Status != "failed" {
		t.Fatalf("unmatched operation reached target: requests=%d run=%+v", requests.Load(), run)
	}
}

func TestSentWriteWithBodylessCleanupRemainsUnresolvedUntilCleanupRecord(t *testing.T) {
	scanDir := t.TempDir()
	journal, err := OpenWriteJournal(scanDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordIntent(WriteJournalEntry{OperationID: "bodyless-cleanup", Method: "POST", RedactedURL: "https://app.test/items", CleanupMethod: http.MethodDelete, CleanupURL: "https://app.test/items/1"}); err != nil {
		t.Fatal(err)
	}
	if err := journal.MarkSent("bodyless-cleanup"); err != nil {
		t.Fatal(err)
	}
	if unresolved, err := UnresolvedWrites(scanDir); err != nil || len(unresolved) != 1 {
		t.Fatalf("bodyless cleanup did not gate resume: %+v %v", unresolved, err)
	}
}
