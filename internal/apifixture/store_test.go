package apifixture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreContentAddressedPrivateAndValidated(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fixtures")
	store := Store{Dir: dir}
	body := []byte(`{"name":"sample","secret":"kept by reference"}`)
	a, err := store.Put(bytes.NewReader(body), "application/json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := store.Put(bytes.NewReader(body), "application/json")
	if err != nil || a.Ref != b.Ref {
		t.Fatalf("duplicate fixture IDs differ: %+v %+v err=%v", a, b, err)
	}
	want := sha256.Sum256(body)
	if a.Ref != hex.EncodeToString(want[:]) || a.SizeBytes != len(body) || a.ContentType != "application/json" {
		t.Fatalf("unexpected metadata: %+v", a)
	}
	f, err := store.Open(a.Ref)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(f.Name())
	f.Close()
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("fixture content mismatch: %q err=%v", got, err)
	}
	info, err := os.Stat(f.Name())
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("fixture permissions=%v err=%v", info, err)
	}
	if _, err := store.Open("../../outside"); err != ErrInvalidRef {
		t.Fatalf("invalid ref error=%v", err)
	}
	if _, err := store.Put(strings.NewReader(""), "application/json"); err == nil {
		t.Fatal("empty fixture accepted")
	}
	if _, err := store.Put(strings.NewReader(strings.Repeat("x", MaxBytes+1)), "text/plain"); err == nil {
		t.Fatal("oversize fixture accepted")
	}
}
