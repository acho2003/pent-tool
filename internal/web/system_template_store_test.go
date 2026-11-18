package web

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/acho2003/pent-tool/internal/assessment"
)

func sampleTemplate(id string) assessment.SystemTemplate {
	return assessment.SystemTemplate{
		ID:             id,
		Name:           "EMIS NestJS",
		BaseURL:        "https://dev-emis.systems.gov.bt",
		PathTemplate:   "/svc/{name}",
		VerifyTemplate: "/svc/{name}/health",
	}
}

func TestSystemTemplateStoreRoundTrip(t *testing.T) {
	store := newSystemTemplateStore(t.TempDir())
	id, err := newTemplateID()
	if err != nil {
		t.Fatal(err)
	}
	tpl := sampleTemplate(id)
	if err := store.Put(tpl); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := store.Get(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != tpl.Name || got.PathTemplate != tpl.PathTemplate {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	list, err := store.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v (len %d)", err, len(list))
	}
	if err := store.Delete(id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := store.Get(id); err == nil {
		t.Fatalf("expected get to fail after delete")
	}
}

func TestSystemTemplateStorePermissions(t *testing.T) {
	dir := t.TempDir()
	store := newSystemTemplateStore(dir)
	id, _ := newTemplateID()
	if err := store.Put(sampleTemplate(id)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "_system_templates", id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("template file perm = %o, want 600", perm)
	}
	dirInfo, _ := os.Stat(filepath.Join(dir, "_system_templates"))
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Fatalf("template dir perm = %o, want 700", perm)
	}
}

func TestSystemTemplateStoreRejectsBadID(t *testing.T) {
	store := newSystemTemplateStore(t.TempDir())
	if _, err := store.path("../escape"); err == nil {
		t.Fatalf("expected bad id to be rejected")
	}
	if _, err := store.Get("not-hex"); err == nil {
		t.Fatalf("expected non-hex id to be rejected")
	}
}

func TestSystemTemplateStoreEmptyList(t *testing.T) {
	store := newSystemTemplateStore(t.TempDir())
	list, err := store.List()
	if err != nil {
		t.Fatalf("list on missing dir: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("want empty list, got %d", len(list))
	}
}
