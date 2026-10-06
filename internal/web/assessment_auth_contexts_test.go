package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/credentials"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

func TestNamedAuthenticationContextsNeverMergeCredentialsOrCheckpoints(t *testing.T) {
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := strings.TrimPrefix(r.URL.Path, "/verify/")
		if len(r.Header.Values("Authorization")) != 1 || r.Header.Get("Authorization") != "Bearer "+role+"-secret" {
			http.Error(w, "not authenticated", 401)
			return
		}
		w.Write([]byte(role + " authenticated"))
	}))
	defer lab.Close()
	server := newTestServer(t, nil)
	vault := authTestVault(t, server)
	plan := headerAuthPlan(lab.URL+"/", "", lab.URL+"/verify/owner", "owner authenticated")
	plan.Config.Access = nil
	plan.Capabilities = nil
	for _, role := range []string{"reader", "owner"} {
		meta, err := vault.Create(credentials.Record{Name: role, Kind: assessment.AccessApplicationHeaders, TargetIDs: []string{"app"}, Values: map[string]string{"Authorization": "Bearer " + role + "-secret"}})
		if err != nil {
			t.Fatal(err)
		}
		plan.Config.Access = append(plan.Config.Access, assessment.AccessBinding{TargetIDs: []string{"app"}, Kind: assessment.AccessApplicationHeaders, CredentialID: meta.ID, Identity: role, Role: role, VerifyURL: lab.URL + "/verify/" + role, VerifyMarker: role + " authenticated"})
		plan.Capabilities = append(plan.Capabilities, assessment.CapabilityEvidence{Capability: assessment.CapAuthWeb, TargetID: "app", ReferenceID: meta.ID, State: assessment.StateAvailable})
	}
	headers, err := server.prepareAssessmentAuthentication(t.Context(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(headers["app"], []string{"Authorization: Bearer owner-secret"}) || len(plan.AuthContexts) != 2 {
		t.Fatalf("roles merged: headers=%v contexts=%d", headers, len(plan.AuthContexts))
	}
	ids := map[string]bool{}
	for _, auth := range plan.AuthContexts {
		if auth.State != assessment.StateVerified || ids[auth.ID] || auth.Refresh == nil {
			t.Fatalf("unverified/duplicate context: %s %s", auth.ID, auth.State)
		}
		ids[auth.ID] = true
		refreshed, err := auth.Refresh(t.Context(), auth.Headers)
		if err != nil || !slices.Equal(refreshed, []string{"Authorization: Bearer " + auth.Identity + "-secret"}) {
			t.Fatalf("renewal used another role: %s %v", auth.Identity, err)
		}
		wrong := []string{"Authorization: Bearer reader-secret"}
		if auth.Identity == "reader" {
			wrong = []string{"Authorization: Bearer owner-secret"}
		}
		if _, err := auth.Refresh(t.Context(), wrong); err == nil {
			t.Fatal("other role passed context checkpoint")
		}
	}
	refreshers, err := server.assessmentAuthRefreshers(plan, headers)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := refreshers["app"](context.Background(), headers["app"]); err != nil {
		t.Fatal("primary checkpoint was replaced by secondary role", err)
	}
	encoded, err := json.Marshal(plan)
	if err != nil || strings.Contains(string(encoded), "owner-secret") || strings.Contains(string(encoded), "reader-secret") {
		t.Fatal("runtime credentials leaked into persisted plan")
	}
	for i := range plan.Config.Access {
		if plan.Config.Access[i].Identity == "owner" {
			plan.Config.Access[i].VerifyMarker = "not-present"
		}
	}
	failedHeaders, err := server.prepareAssessmentAuthentication(t.Context(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(failedHeaders["app"]) != 0 || len(plan.AuthContexts) != 2 || plan.AuthContexts[0].State != assessment.StateFailed || plan.AuthContexts[1].State != assessment.StateVerified {
		t.Fatal("failed primary silently used another verified identity")
	}

}

func TestBrowserStorageUsesOnlyPrimaryVerifiedContext(t *testing.T) {
	server := newTestServer(t, nil)
	owner := &credentials.BrowserStorage{Local: map[string]string{"token": "owner-secret"}}
	reader := &credentials.BrowserStorage{Local: map[string]string{"token": "reader-secret"}}
	plan := &scanner.AssessmentPlan{Config: assessment.AssessmentConfig{WorkflowVersion: "unified-v1"}, AuthContexts: []scanner.AuthContext{{TargetID: "app", Primary: true, State: assessment.StateVerified, BrowserStorage: owner}, {TargetID: "app", State: assessment.StateVerified, BrowserStorage: reader}}}
	if got := server.assessmentBrowserStorage(plan); got["app"] != owner {
		t.Fatal("secondary browser storage replaced primary identity")
	}
	plan.AuthContexts[0].State = assessment.StateFailed
	if got := server.assessmentBrowserStorage(plan); len(got) != 0 {
		t.Fatal("failed primary silently fell back to another identity")
	}
}
