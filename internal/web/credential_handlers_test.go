package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/credentials"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCredentialAPIEncryptsSecretsAndNeverReturnsValues(t *testing.T) {
	s := newTestServer(t, nil)
	keyPath := filepath.Join(t.TempDir(), "credential-key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x31}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XALGORIX_CREDENTIAL_KEY_FILE", keyPath)
	body := `{"name":"staging","kind":"APPLICATION_HEADERS","target_ids":["app-1"],"values":{"Authorization":"Bearer secret-token"}}`
	created := httptest.NewRecorder()
	s.handleCredentials(created, httptest.NewRequest(http.MethodPost, "/api/credentials", strings.NewReader(body)))
	if created.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	if strings.Contains(created.Body.String(), "secret-token") || strings.Contains(created.Body.String(), "Authorization") {
		t.Fatalf("create response leaked credential values: %s", created.Body.String())
	}
	var meta struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &meta); err != nil || meta.ID == "" {
		t.Fatalf("metadata decode=%+v err=%v", meta, err)
	}
	files, err := filepath.Glob(filepath.Join(s.dataDir, "_credentials", "*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("encrypted files=%v err=%v", files, err)
	}
	ciphertext, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte("secret-token")) {
		t.Fatal("stored credential contains plaintext secret")
	}
	list := httptest.NewRecorder()
	s.handleCredentials(list, httptest.NewRequest(http.MethodGet, "/api/credentials", nil))
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), "secret-token") {
		t.Fatalf("list status=%d body=%s", list.Code, list.Body.String())
	}
}

func TestCredentialAPIRequiresMountedKey(t *testing.T) {
	s := newTestServer(t, nil)
	t.Setenv("XALGORIX_CREDENTIAL_KEY_FILE", "")
	rr := httptest.NewRecorder()
	s.handleCredentials(rr, httptest.NewRequest(http.MethodGet, "/api/credentials", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestCredentialTestEndpointVerifiesBoundCredential(t *testing.T) {
	var authRequests, anonymousRequests atomic.Int32
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer auth-secret" {
			authRequests.Add(1)
			_, _ = fmt.Fprint(w, "private dashboard")
			return
		}
		anonymousRequests.Add(1)
		http.Redirect(w, r, "/login", http.StatusFound)
	}))
	defer app.Close()

	s := newTestServer(t, nil)
	s.cfg.AllowLocalTargets = true
	keyPath := filepath.Join(t.TempDir(), "credential-key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x42}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XALGORIX_CREDENTIAL_KEY_FILE", keyPath)
	vault, err := s.credentialVault()
	if err != nil {
		t.Fatal(err)
	}
	meta, err := vault.Create(credentials.Record{Name: "test", Kind: assessment.AccessApplicationHeaders, TargetIDs: []string{"target-1"}, Values: map[string]string{"Authorization": "Bearer auth-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	invoke := func(targetID string) *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"target_id":%q,"target_url":%q}`, targetID, app.URL)
		rr := httptest.NewRecorder()
		s.handleCredentialDetail(rr, httptest.NewRequest(http.MethodPost, "/api/credentials/"+meta.ID+"/test", strings.NewReader(body)))
		return rr
	}
	rr := invoke("target-1")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"verified":true`) {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "auth-secret") || strings.Contains(rr.Body.String(), "Bearer") {
		t.Fatalf("response leaked secret: %s", rr.Body.String())
	}
	if authRequests.Load() != 1 || anonymousRequests.Load() < 1 {
		t.Fatalf("auth requests=%d anonymous=%d", authRequests.Load(), anonymousRequests.Load())
	}

	wrong := invoke("other")
	if wrong.Code != http.StatusOK || !strings.Contains(wrong.Body.String(), `"state":"unavailable"`) {
		t.Fatalf("cross-target result: status=%d body=%s", wrong.Code, wrong.Body.String())
	}
	if authRequests.Load() != 1 {
		t.Fatal("cross-target credential was sent to target")
	}
}
