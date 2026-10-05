package credentials

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestVaultEncryptsTargetBoundCredentialsAndReturnsOnlyMetadata(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	key := bytes.Repeat([]byte{0x5a}, KeySize)
	vault, err := New(root, key)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := vault.Create(Record{Name: "staging app", Kind: assessment.AccessApplicationHeaders, TargetIDs: []string{"app-1", "app-1"}, Values: map[string]string{"Authorization": "Bearer highly-secret-value"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.TargetIDs) != 1 || meta.TargetIDs[0] != "app-1" {
		t.Fatalf("target bindings not normalized: %+v", meta)
	}
	blob, err := os.ReadFile(filepath.Join(root, meta.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte("highly-secret-value")) || bytes.Contains(blob, []byte("Authorization")) {
		t.Fatal("credential file contains plaintext secret material")
	}
	if _, err := vault.Get(meta.ID, "other-app"); err != ErrTargetNotBound {
		t.Fatalf("unbound target access error = %v", err)
	}
	got, err := vault.Get(meta.ID, "app-1")
	if err != nil || got.Values["Authorization"] != "Bearer highly-secret-value" {
		t.Fatalf("target-bound lookup = %+v, err=%v", got, err)
	}
	list, err := vault.List()
	if err != nil || len(list) != 1 || list[0].ID != meta.ID {
		t.Fatalf("metadata list = %+v, err=%v", list, err)
	}
}

func TestVaultWrongKeyAndTamperingFailClosed(t *testing.T) {
	root := t.TempDir()
	key := bytes.Repeat([]byte{0x01}, KeySize)
	vault, err := New(root, key)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := vault.Create(Record{Name: "login", Kind: assessment.AccessBearerToken, TargetIDs: []string{"api"}, Values: map[string]string{"token": "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	wrongKeyVault, err := New(root, bytes.Repeat([]byte{0x02}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongKeyVault.Get(meta.ID, "api"); err == nil {
		t.Fatal("wrong key decrypted credential")
	}
	path := filepath.Join(root, meta.ID+".json")
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	blob[len(blob)-1] ^= 0xff
	if err := os.WriteFile(path, blob, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Get(meta.ID, "api"); err == nil {
		t.Fatal("tampered credential decrypted")
	}
}

func TestLoadKeyFileRequiresExactly32RawBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, bytes.Repeat([]byte{1}, KeySize-1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyFile(path); err == nil {
		t.Fatal("accepted short key")
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte{1}, KeySize), 0600); err != nil {
		t.Fatal(err)
	}
	if key, err := LoadKeyFile(path); err != nil || len(key) != KeySize {
		t.Fatalf("valid key load length=%d err=%v", len(key), err)
	}
}

func TestVaultKeyRotationPreservesBindingsAndReEncryptsRecords(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	oldKey := bytes.Repeat([]byte{0x11}, KeySize)
	newKey := bytes.Repeat([]byte{0x22}, KeySize)
	vault, err := New(root, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := vault.Create(Record{Name: "api", Kind: assessment.AccessAPIKey, TargetIDs: []string{"api-1"}, Values: map[string]string{"key": "hidden"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.RotateKey(newKey); err != nil {
		t.Fatal(err)
	}
	if got, err := vault.Get(meta.ID, "api-1"); err != nil || got.Values["key"] != "hidden" {
		t.Fatalf("rotated vault read = %+v, err=%v", got, err)
	}
	oldVault, err := New(root, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oldVault.Get(meta.ID, "api-1"); err == nil {
		t.Fatal("old key decrypted rotated record")
	}
}

func TestVaultRequiresFormLoginFields(t *testing.T) {
	vault, err := New(filepath.Join(t.TempDir(), "vault"), bytes.Repeat([]byte{0x11}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	base := Record{Name: "form", Kind: assessment.AccessFormLogin, TargetIDs: []string{"app"}, Values: map[string]string{"login_url": "https://app.example.test/login", "username": "operator"}}
	if _, err := vault.Create(base); err == nil || !strings.Contains(err.Error(), "password") {
		t.Fatalf("missing password accepted: %v", err)
	}
	base.Values["password"] = "secret"
	meta, err := vault.Create(base)
	if err != nil {
		t.Fatal(err)
	}
	base.Values["login_url"] = "https://other.example.test/login#fragment"
	if _, err := vault.Replace(meta.ID, base); err == nil {
		t.Fatal("form login URL with a fragment was accepted")
	}
}

func TestVaultReplaceBumpsRevisionAndKeepsID(t *testing.T) {
	vault, err := New(filepath.Join(t.TempDir(), "vault"), bytes.Repeat([]byte{0x33}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	created, err := vault.Create(Record{Name: "api", Kind: assessment.AccessBearerToken, TargetIDs: []string{"api"}, Values: map[string]string{"token": "first"}, Revision: 7})
	if err != nil {
		t.Fatal(err)
	}
	if created.Revision != 1 || created.UpdatedAt.IsZero() || !created.UpdatedAt.Equal(created.CreatedAt) {
		t.Fatalf("created metadata revision=%d updated=%v created=%v", created.Revision, created.UpdatedAt, created.CreatedAt)
	}
	if rev, err := vault.RevisionOf(created.ID); err != nil || rev != 1 {
		t.Fatalf("RevisionOf after create = %d, err=%v", rev, err)
	}
	replaced, err := vault.Replace(created.ID, Record{Name: "api", Kind: assessment.AccessBearerToken, TargetIDs: []string{"api"}, Values: map[string]string{"token": "second"}, Revision: 99})
	if err != nil {
		t.Fatal(err)
	}
	if replaced.ID != created.ID || !replaced.CreatedAt.Equal(created.CreatedAt) {
		t.Fatalf("replace changed identity: before=%+v after=%+v", created, replaced)
	}
	if replaced.Revision != 2 || replaced.UpdatedAt.Before(created.UpdatedAt) {
		t.Fatalf("replace revision=%d updated=%v (created updated=%v)", replaced.Revision, replaced.UpdatedAt, created.UpdatedAt)
	}
	got, err := vault.Get(created.ID, "api")
	if err != nil || got.Revision != 2 || got.Values["token"] != "second" || !got.CreatedAt.Equal(created.CreatedAt) {
		t.Fatalf("stored record after replace = rev %d created %v err=%v", got.Revision, got.CreatedAt, err)
	}
	if rev, err := vault.RevisionOf(created.ID); err != nil || rev != 2 {
		t.Fatalf("RevisionOf after replace = %d, err=%v", rev, err)
	}
	if _, err := vault.RevisionOf("not-an-id"); err != ErrNotFound {
		t.Fatalf("RevisionOf unknown id err = %v", err)
	}
}

func TestVaultMetadataExposesRevisionNoSecrets(t *testing.T) {
	vault, err := New(filepath.Join(t.TempDir(), "vault"), bytes.Repeat([]byte{0x44}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	meta, err := vault.Create(Record{Name: "hdr", Kind: assessment.AccessApplicationHeaders, TargetIDs: []string{"app"}, Values: map[string]string{"Authorization": "Bearer revision-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	list, err := vault.List()
	if err != nil || len(list) != 1 || list[0].Revision != 1 || list[0].UpdatedAt.IsZero() {
		t.Fatalf("metadata list = %+v, err=%v", list, err)
	}
	encoded, err := json.Marshal(list[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"revision":1`)) || !bytes.Contains(encoded, []byte(`"updated_at"`)) {
		t.Fatalf("metadata JSON lacks revision fields: %s", encoded)
	}
	if bytes.Contains(encoded, []byte("revision-secret")) || bytes.Contains(encoded, []byte("Authorization")) || bytes.Contains(encoded, []byte(`"values"`)) {
		t.Fatalf("metadata JSON leaks credential values: %s", encoded)
	}
	if meta.Revision != 1 {
		t.Fatalf("create metadata revision = %d", meta.Revision)
	}
}

func TestVaultReadsLegacyRecordWithoutRevisionAsZero(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	vault, err := New(root, bytes.Repeat([]byte{0x55}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	// Seal a record using the pre-revision payload shape: same AAD (record
	// ID) and nonce||ciphertext layout, but no revision or updated_at keys.
	id := strings.Repeat("ab", 16)
	created := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	legacy := map[string]any{"id": id, "name": "legacy", "kind": assessment.AccessBearerToken, "target_ids": []string{"api"}, "values": map[string]string{"token": "old-secret"}, "created_at": created}
	plain, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, vault.aead.NonceSize())
	payload := append(nonce, vault.aead.Seal(nil, nonce, plain, []byte(id))...)
	if err := os.WriteFile(filepath.Join(root, id+".json"), payload, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := vault.Get(id, "api")
	if err != nil || got.Revision != 0 || !got.UpdatedAt.IsZero() || got.Values["token"] != "old-secret" {
		t.Fatalf("legacy read = rev %d updated %v err=%v", got.Revision, got.UpdatedAt, err)
	}
	if rev, err := vault.RevisionOf(id); err != nil || rev != 0 {
		t.Fatalf("legacy RevisionOf = %d, err=%v", rev, err)
	}
	list, err := vault.List()
	if err != nil || len(list) != 1 || list[0].Revision != 0 {
		t.Fatalf("legacy metadata list = %+v, err=%v", list, err)
	}
	encoded, err := json.Marshal(list[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(`"revision"`)) || bytes.Contains(encoded, []byte(`"updated_at"`)) {
		t.Fatalf("legacy metadata JSON should omit absent revision fields: %s", encoded)
	}
	replaced, err := vault.Replace(id, Record{Name: "legacy", Kind: assessment.AccessBearerToken, TargetIDs: []string{"api"}, Values: map[string]string{"token": "new-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	if replaced.Revision != 1 || !replaced.CreatedAt.Equal(created) || replaced.UpdatedAt.IsZero() {
		t.Fatalf("legacy replace metadata = %+v", replaced)
	}
}

func TestBrowserStorageIsEncryptedAndTargetBound(t *testing.T) {
	root := t.TempDir()
	vault, err := New(root, bytes.Repeat([]byte{0x51}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	record := Record{Name: "browser", Kind: assessment.AccessApplicationHeaders, TargetIDs: []string{"app"}, Values: map[string]string{"Cookie": "session=fixture"}, BrowserStorage: &BrowserStorage{Local: map[string]string{"authToken": "browser-storage-secret"}, Session: map[string]string{"role": "reviewer"}}}
	meta, err := vault.Create(record)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := os.ReadFile(filepath.Join(root, meta.ID+".json"))
	public, _ := json.Marshal(meta)
	if bytes.Contains(encoded, []byte("browser-storage-secret")) || bytes.Contains(public, []byte("authToken")) {
		t.Fatal("storage secret exposed")
	}
	got, err := vault.Get(meta.ID, "app")
	if err != nil || got.BrowserStorage.Local["authToken"] != "browser-storage-secret" {
		t.Fatal(got, err)
	}
	if _, err := vault.Get(meta.ID, "alias"); err != ErrTargetNotBound {
		t.Fatal("storage crossed target binding", err)
	}
	record.BrowserStorage = &BrowserStorage{Local: map[string]string{"": "secret"}}
	if _, err := vault.Replace(meta.ID, record); err == nil {
		t.Fatal("invalid storage accepted")
	}
}
