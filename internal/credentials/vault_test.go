package credentials

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

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
