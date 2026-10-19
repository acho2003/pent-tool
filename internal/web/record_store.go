package web

// PROTOTYPE: Postgres-backed record storage, gated behind XALGORIX_STORE=postgres.
// This wires the credentials vault (and, via the import tool, scan records) to
// the prototype recordstore. It is not committed and not on by default; with the
// flag unset every path below is skipped and the app uses files as before.

import (
	"context"
	"errors"
	"log"
	"sync"

	"github.com/xalgord/xalgorix/v4/internal/credentials"
	"github.com/xalgord/xalgorix/v4/internal/recordstore"
)

var (
	pgOnce  sync.Once
	pgStore *recordstore.Store
	pgErr   error
)

// recordStore lazily opens the prototype Postgres store (once per process).
func recordStore() (*recordstore.Store, error) {
	pgOnce.Do(func() {
		pgStore, pgErr = recordstore.Open(context.Background(), recordstore.DSN())
		if pgErr == nil {
			log.Printf("[recordstore] PROTOTYPE Postgres store enabled (%s)", "records in postgres, artifacts on disk")
		} else {
			log.Printf("[recordstore] postgres unavailable, falling back to files: %v", pgErr)
		}
	})
	return pgStore, pgErr
}

// pgCredentialBlobs adapts the generic record store to the credentials.BlobStore
// interface. Credentials stay encrypted; only where the ciphertext lives changes.
type pgCredentialBlobs struct {
	store *recordstore.Store
}

const credentialCollection = "credentials"

func (p pgCredentialBlobs) Put(id string, data []byte) error {
	return p.store.PutBytes(context.Background(), credentialCollection, id, data)
}

func (p pgCredentialBlobs) Get(id string) ([]byte, error) {
	data, err := p.store.GetBytes(context.Background(), credentialCollection, id)
	if errors.Is(err, recordstore.ErrNotFound) {
		return nil, nil
	}
	return data, err
}

func (p pgCredentialBlobs) List() ([]string, error) {
	return p.store.ListIDs(context.Background(), credentialCollection)
}

func (p pgCredentialBlobs) Delete(id string) error {
	data, err := p.store.GetBytes(context.Background(), credentialCollection, id)
	if errors.Is(err, recordstore.ErrNotFound) {
		return credentials.ErrNotFound
	}
	if err != nil {
		return err
	}
	if data == nil {
		return credentials.ErrNotFound
	}
	return p.store.Delete(context.Background(), credentialCollection, id)
}

// applyRecordStore points the vault at Postgres when the prototype flag is set.
// On any store error it leaves the file-backed default in place.
func applyRecordStore(v *credentials.Vault) *credentials.Vault {
	if v == nil || !recordstore.Enabled() {
		return v
	}
	store, err := recordStore()
	if err != nil {
		return v
	}
	v.UseBlobs(pgCredentialBlobs{store: store})
	return v
}
