package web

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/credentials"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

func TestBrowserAccessRequiresEnabledWorkerAndMarker(t *testing.T) {
	server := newTestServer(t, nil)
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "0")
	if err := server.verifyBrowserCredential(context.Background(), "https://app.test/", "https://app.test/", "marker", []string{"Cookie: session=fixture"}, nil, true); err == nil || !strings.Contains(err.Error(), "flag") {
		t.Fatal(err)
	}
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	if err := server.verifyBrowserCredential(context.Background(), "https://app.test/", "https://app.test/", "", nil, nil, true); err == nil || !strings.Contains(err.Error(), "marker") {
		t.Fatal(err)
	}
}
func TestAssessmentBrowserStorageDoesNotBindAliasesOrLegacyPlans(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "credential-key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x31}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XALGORIX_CREDENTIAL_KEY_FILE", keyPath)
	server := newTestServer(t, nil)
	vault, err := server.credentialVault()
	if err != nil {
		t.Fatal(err)
	}
	meta, err := vault.Create(credentials.Record{Name: "storage", Kind: assessment.AccessApplicationHeaders, TargetIDs: []string{"app"}, Values: map[string]string{"Cookie": "fixture"}, BrowserStorage: &credentials.BrowserStorage{Local: map[string]string{"token": "secret"}}})
	if err != nil {
		t.Fatal(err)
	}
	plan := scanner.AssessmentPlan{Config: assessment.AssessmentConfig{WorkflowVersion: "unified-v1", Access: []assessment.AccessBinding{{CredentialID: meta.ID, Kind: assessment.AccessApplicationHeaders, TargetIDs: []string{"app", "alias"}}}}}
	got := server.assessmentBrowserStorage(&plan)
	if len(got) != 1 || got["app"].Local["token"] != "secret" || got["alias"] != nil {
		t.Fatal("storage crossed credential binding", got)
	}
	plan.Config.WorkflowVersion = ""
	if len(server.assessmentBrowserStorage(&plan)) != 0 {
		t.Fatal("legacy plan gained storage")
	}
}
