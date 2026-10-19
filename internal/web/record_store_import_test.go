package web

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/credentials"
	"github.com/xalgord/xalgorix/v4/internal/recordstore"
)

// TestImportRealDataIntoPostgres is the prototype end-to-end proof: import the
// existing file-based records into Postgres, then read credentials back through
// a Postgres-backed vault and confirm they still decrypt. Opt-in: it needs a
// reachable Postgres, the real data directory, and the credential key, supplied
// via env so it skips in ordinary CI.
//
//	XALGORIX_STORE=postgres
//	XALGORIX_POSTGRES_DSN=...
//	XALGORIX_IMPORT_DIR=/data
//	XALGORIX_CREDENTIAL_KEY_FILE=/run/secrets/xalgorix_credential_key
func TestImportRealDataIntoPostgres(t *testing.T) {
	dataDir := os.Getenv("XALGORIX_IMPORT_DIR")
	if dataDir == "" || !recordstore.Enabled() {
		t.Skip("set XALGORIX_STORE=postgres and XALGORIX_IMPORT_DIR to run the prototype import")
	}
	ctx := context.Background()
	store, err := recordstore.Open(ctx, recordstore.DSN())
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer store.Close()

	sum, err := recordstore.ImportDataDir(ctx, store, dataDir)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	t.Logf("imported: %d credentials, %d scans, %d reports", sum.Credentials, sum.Scans, sum.Reports)

	// Counts in Postgres match what was imported.
	if n, _ := store.Count(ctx, "credentials"); n < sum.Credentials {
		t.Fatalf("credential count in postgres = %d, want >= %d", n, sum.Credentials)
	}
	if n, _ := store.Count(ctx, "scans"); n < sum.Scans {
		t.Fatalf("scan count in postgres = %d, want >= %d", n, sum.Scans)
	}

	// Read credentials back through a Postgres-backed vault and decrypt them.
	key, err := credentials.LoadKeyFile(os.Getenv("XALGORIX_CREDENTIAL_KEY_FILE"))
	if err != nil {
		t.Fatalf("credential key: %v", err)
	}
	vault, err := credentials.Open(filepath.Join(dataDir, "_credentials"), key)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	vault.UseBlobs(pgCredentialBlobs{store: store})

	metas, err := vault.List()
	if err != nil {
		t.Fatalf("list credentials from postgres: %v", err)
	}
	if len(metas) == 0 {
		t.Fatal("no credentials listed from postgres after import")
	}
	decrypted := 0
	for _, m := range metas {
		rec, err := vault.Get(m.ID, "")
		if err != nil {
			t.Fatalf("decrypt credential %s from postgres: %v", m.ID, err)
		}
		if !rec.Kind.Valid() {
			t.Fatalf("credential %s decrypted to an invalid kind", m.ID)
		}
		decrypted++
	}
	t.Logf("decrypted %d/%d credentials from postgres", decrypted, len(metas))
	if decrypted != len(metas) {
		t.Fatalf("decrypted %d of %d credentials", decrypted, len(metas))
	}
}

// TestScanReadsFromPostgres proves the rerouted read paths serve scans from
// Postgres (not the filesystem walk) when the prototype flag is set. Same opt-in
// env as TestImportRealDataIntoPostgres.
func TestScanReadsFromPostgres(t *testing.T) {
	dataDir := os.Getenv("XALGORIX_IMPORT_DIR")
	if dataDir == "" || !recordstore.Enabled() {
		t.Skip("set XALGORIX_STORE=postgres and XALGORIX_IMPORT_DIR to run the prototype scan-read test")
	}
	ctx := context.Background()
	store, err := recordstore.Open(ctx, recordstore.DSN())
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer store.Close()
	if _, err := recordstore.ImportDataDir(ctx, store, dataDir); err != nil {
		t.Fatalf("import: %v", err)
	}
	want, _ := store.Count(ctx, "scans")
	if want == 0 {
		t.Skip("no scans imported")
	}

	srv := &Server{dataDir: dataDir}

	full := srv.findAllScans()
	if len(full) != want {
		t.Fatalf("findAllScans returned %d, want %d (from postgres)", len(full), want)
	}
	// Each entry's reconstructed artifact dir must exist on the volume.
	for _, e := range full {
		if e.rec.ID == "" {
			t.Fatal("scan from postgres has no id")
		}
		if fi, err := os.Stat(e.dir); err != nil || !fi.IsDir() {
			t.Fatalf("reconstructed dir %q does not exist for scan %s", e.dir, e.rec.ID)
		}
	}
	// Summaries path also serves from postgres and drops events.
	summaries := srv.findAllScanSummaries()
	if len(summaries) != want {
		t.Fatalf("findAllScanSummaries returned %d, want %d", len(summaries), want)
	}
	// Lookup by id resolves through the postgres-backed walk.
	id := full[0].rec.ID
	dir, rec := srv.findScanByID(id)
	if rec == nil || rec.ID != id || dir == "" {
		t.Fatalf("findScanByID(%s) = %q, %+v", id, dir, rec)
	}
	t.Logf("served %d scans from postgres, all artifact dirs present, lookup by id works", len(full))
}

// TestSchedulesInPostgres proves schedule records round-trip through the store.
func TestSchedulesInPostgres(t *testing.T) {
	if !recordstore.Enabled() {
		t.Skip("set XALGORIX_STORE=postgres to run the prototype schedule test")
	}
	ctx := context.Background()
	store, err := recordstore.Open(ctx, recordstore.DSN())
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer store.Close()
	// clean slate
	if ids, _ := store.ListIDs(ctx, "schedules"); len(ids) > 0 {
		for _, id := range ids {
			_ = store.Delete(ctx, "schedules", id)
		}
	}
	srv := &Server{}
	mirrorScheduleToRecordStore("sched-1", []byte(`{"id":"sched-1","name":"nightly"}`))
	docs, ok := srv.recordStoreSchedules()
	if !ok || len(docs) != 1 {
		t.Fatalf("recordStoreSchedules ok=%v len=%d, want 1", ok, len(docs))
	}
	deleteFromRecordStore("sched-1", scheduleCollection)
	docs, _ = srv.recordStoreSchedules()
	if len(docs) != 0 {
		t.Fatalf("after delete len=%d, want 0", len(docs))
	}
}

// TestCredentialDualWrite proves a credential saved through the dual-write
// backend lands in BOTH Postgres and the encrypted file tree, so a Postgres
// loss never loses credentials.
func TestCredentialDualWrite(t *testing.T) {
	if !recordstore.Enabled() {
		t.Skip("set XALGORIX_STORE=postgres to run the dual-write test")
	}
	ctx := context.Background()
	store, err := recordstore.Open(ctx, recordstore.DSN())
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer store.Close()

	root := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 7)
	}
	vault, err := credentials.Open(root, key)
	if err != nil {
		t.Fatal(err)
	}
	vault.UseBlobs(dualBlobs{
		primary:   pgCredentialBlobs{store: store},
		secondary: credentials.FileBlobStore(root),
	})

	meta, err := vault.Create(credentials.Record{
		Name: "dual", Kind: "APPLICATION_HEADERS",
		TargetIDs: []string{"target-1"}, Values: map[string]string{"Cookie": "x"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = store.Delete(ctx, "credentials", meta.ID) })

	// In Postgres:
	if blob, err := store.GetBytes(ctx, "credentials", meta.ID); err != nil || blob == nil {
		t.Fatalf("credential not in postgres: %v", err)
	}
	// In the file tree:
	if fi, err := os.Stat(filepath.Join(root, meta.ID+".json")); err != nil || fi.Size() == 0 {
		t.Fatalf("credential not written to file tree: %v", err)
	}
	// And it decrypts back through the vault:
	rec, err := vault.Get(meta.ID, "target-1")
	if err != nil || rec.Name != "dual" {
		t.Fatalf("read back: %v (%+v)", err, rec)
	}
}
