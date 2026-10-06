package credentials

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReplayEncryptionIntegrityAndBindings(t *testing.T) {
	root := t.TempDir()
	key := bytes.Repeat([]byte{7}, KeySize)
	store, err := NewReplayStore(root, key)
	if err != nil {
		t.Fatal(err)
	}
	request := ReplayRequest{EndpointID: "request-1", URL: "https://app.test/a%2Fb/?x=1&x=2&token=private-token", Method: "POST", ContentType: "application/json", Body: `{"query":"query { viewer { id } }","variables":{"token":"private-body"}}`, Headers: map[string]string{"Cookie": "session=private-cookie"}}
	ref, err := store.Put("app:1", "role:a", request)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(filepath.Join(root, ref+".enc"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-token", "private-body", "private-cookie", "query", "app.test"} {
		if bytes.Contains(blob, []byte(secret)) {
			t.Fatalf("plaintext %q", secret)
		}
	}
	duplicate, err := store.Put("app:1", "role:a", request)
	if err != nil || duplicate != ref {
		t.Fatalf("immutable duplicate: %s %v", duplicate, err)
	}
	got, err := store.Get("app:1", "role:a", ref)
	if err != nil || !reflect.DeepEqual(got, request) {
		t.Fatalf("exact request lost: %+v %v", got, err)
	}
	for _, binding := range [][2]string{{"app:2", "role:a"}, {"app:1", "role:b"}} {
		if _, err := store.Get(binding[0], binding[1], ref); err == nil {
			t.Fatal("unbound replay accepted")
		}
	}
	wrong, _ := NewReplayStore(root, bytes.Repeat([]byte{8}, KeySize))
	if _, err := wrong.Get("app:1", "role:a", ref); err == nil {
		t.Fatal("wrong key accepted")
	}
	request.Body += " "
	other, err := store.Put("app:1", "role:a", request)
	if err != nil || other == ref {
		t.Fatal("body variant collapsed")
	}
	blob[len(blob)-1] ^= 1
	if err := os.WriteFile(filepath.Join(root, ref+".enc"), blob, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("app:1", "role:a", ref); err == nil {
		t.Fatal("corrupt replay accepted")
	}
	if _, err := store.Put("app:1", "role:a", got); err == nil {
		t.Fatal("corrupt immutable file replaced")
	}
}
func TestReplayRejectsMissingStoreAndSymlink(t *testing.T) {
	var unavailable *ReplayStore
	if _, err := unavailable.Get("app:a", "", "bad"); err == nil {
		t.Fatal("nil store accepted")
	}
	if _, err := unavailable.Put("app:a", "", ReplayRequest{}); err == nil {
		t.Fatal("nil store accepted")
	}
	root := t.TempDir()
	store, _ := NewReplayStore(root, bytes.Repeat([]byte{3}, KeySize))
	request := ReplayRequest{EndpointID: "id", URL: "https://app.test/", Method: "GET"}
	ref, err := store.Put("app:a", "", request)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ref+".enc")
	data, _ := os.ReadFile(path)
	os.Remove(path)
	target := filepath.Join(t.TempDir(), "outside")
	os.WriteFile(target, data, 0600)
	os.Symlink(target, path)
	if _, err := store.Get("app:a", "", ref); err == nil {
		t.Fatal("symlink replay accepted")
	}
}
