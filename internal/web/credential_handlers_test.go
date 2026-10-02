package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
