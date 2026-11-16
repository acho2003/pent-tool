package web

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withTempVaultKey(t *testing.T) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XALGORIX_CREDENTIAL_KEY_FILE", keyPath)
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")
}

func TestAICredentialStoreRoundTrip(t *testing.T) {
	withTempVaultKey(t)
	s := &Server{dataDir: t.TempDir()}

	if s.aiConnection().Configured {
		t.Fatal("should start unconfigured")
	}
	const secret = "sk-ant-SUPERSECRET-DO-NOT-LEAK"
	if err := s.aiCredentialSet("api_key", secret); err != nil {
		t.Fatalf("set: %v", err)
	}
	st := s.aiConnection()
	if !st.Configured || st.Kind != "api_key" || st.Source != "stored" {
		t.Fatalf("unexpected status %+v", st)
	}
	if !s.aiReportConfigured() {
		t.Fatal("a stored credential should enable the feature")
	}
	// The encrypted file must not contain the plaintext secret.
	raw, _ := os.ReadFile(s.aiCredentialPath())
	if strings.Contains(string(raw), secret) {
		t.Fatal("secret stored in plaintext on disk")
	}
	// Options carry the secret to the SDK (not over the API).
	if len(s.aiCredentialOptions()) == 0 {
		t.Fatal("expected request options for a stored credential")
	}
	if err := s.aiCredentialClear(); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if s.aiConnection().Configured {
		t.Fatal("should be unconfigured after clear")
	}
}

func TestAIConnectionHandlerNeverLeaksSecret(t *testing.T) {
	withTempVaultKey(t)
	s := &Server{dataDir: t.TempDir()}
	const secret = "sk-ant-TOPSECRET-1234567890"

	// POST a credential.
	post := httptest.NewRecorder()
	s.handleAIConnection(post, httptest.NewRequest(http.MethodPost, "/api/settings/ai-connection",
		strings.NewReader(`{"kind":"api_key","value":"`+secret+`"}`)))
	if post.Code != http.StatusOK {
		t.Fatalf("post status %d: %s", post.Code, post.Body.String())
	}
	if strings.Contains(post.Body.String(), secret) {
		t.Fatal("POST response leaked the secret")
	}
	// GET status must report configured but never the secret.
	get := httptest.NewRecorder()
	s.handleAIConnection(get, httptest.NewRequest(http.MethodGet, "/api/settings/ai-connection", nil))
	var st aiConnectionStatus
	_ = json.Unmarshal(get.Body.Bytes(), &st)
	if !st.Configured || st.Kind != "api_key" {
		t.Fatalf("status not reported: %s", get.Body.String())
	}
	if strings.Contains(get.Body.String(), secret) {
		t.Fatal("GET status leaked the secret")
	}
	// DELETE disconnects.
	del := httptest.NewRecorder()
	s.handleAIConnection(del, httptest.NewRequest(http.MethodDelete, "/api/settings/ai-connection", nil))
	if del.Code != http.StatusOK {
		t.Fatalf("delete status %d", del.Code)
	}
	if s.aiConnection().Configured {
		t.Fatal("should be disconnected after DELETE")
	}
}

func TestAIConnectionRejectsBadKind(t *testing.T) {
	withTempVaultKey(t)
	s := &Server{dataDir: t.TempDir()}
	rec := httptest.NewRecorder()
	s.handleAIConnection(rec, httptest.NewRequest(http.MethodPost, "/api/settings/ai-connection",
		strings.NewReader(`{"kind":"password","value":"x"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for bad kind, got %d", rec.Code)
	}
}

func TestAIConnectionEnvTakesPrecedence(t *testing.T) {
	withTempVaultKey(t)
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-env")
	s := &Server{dataDir: t.TempDir()}
	st := s.aiConnection()
	if !st.Configured || st.Source != "environment" {
		t.Fatalf("env credential should win: %+v", st)
	}
	// Storing is refused while env-managed.
	rec := httptest.NewRecorder()
	s.handleAIConnection(rec, httptest.NewRequest(http.MethodPost, "/api/settings/ai-connection",
		strings.NewReader(`{"kind":"api_key","value":"sk-ant-stored"}`)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("want 409 when env-managed, got %d", rec.Code)
	}
}
