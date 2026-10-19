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
