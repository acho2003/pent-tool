package web

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/credentials"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

func TestAssessmentRegistryCredentialsResolveOnlyBoundImages(t *testing.T) {
	s := newTestServer(t, nil)
	vault := tokenTestVault(t, s)
	meta, err := vault.Create(credentials.Record{Name: "registry", Kind: assessment.AccessRegistryCreds, TargetIDs: []string{"img-auth"}, Values: map[string]string{"registry": "hub.example.test", "username": "ci", "password": "registry-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	plan := &scanner.AssessmentPlan{Config: assessment.AssessmentConfig{
		Targets: []assessment.Target{{ID: "img-auth", Kind: assessment.KindDockerImage, Value: "hub.example.test/bcrs/auth:6"}, {ID: "img-other", Kind: assessment.KindDockerImage, Value: "hub.example.test/bcrs/other:1"}},
		Access:  []assessment.AccessBinding{{Kind: assessment.AccessRegistryCreds, CredentialID: meta.ID, TargetIDs: []string{"img-auth", "img-other"}}},
	}}
	creds := s.assessmentRegistryCredentials(plan)
	if got := creds["img-auth"]; got.Username != "ci" || got.Password != "registry-secret" || got.Registry != "hub.example.test" {
		t.Fatalf("bound image credential not resolved: %+v", got)
	}
	if _, ok := creds["img-other"]; ok {
		t.Fatal("credential resolved for an image the vault record is not bound to")
	}
	encoded, _ := json.Marshal(plan)
	if strings.Contains(string(encoded), "registry-secret") {
		t.Fatal("registry password copied into the plan")
	}
}
