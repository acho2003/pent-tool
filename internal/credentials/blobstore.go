package credentials

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// BlobStore is the per-credential encrypted-blob backend the Vault reads and
// writes through. The default is file-backed (one <id>.json per record); the
// prototype Postgres store injects an alternative so credential records live in
// the database while staying encrypted. Get returns (nil, nil) when the id is
// absent so callers need not match a backend-specific not-found error.
type BlobStore interface {
	Put(id string, data []byte) error
	Get(id string) ([]byte, error)
	List() ([]string, error)
	Delete(id string) error
}

// fileBlobs is the original on-disk backend: encrypted records as <id>.json in
// the vault directory, written atomically with 0600 permissions.
type fileBlobs struct{ root string }

func (f fileBlobs) path(id string) string { return filepath.Join(f.root, id+".json") }

func (f fileBlobs) Put(id string, data []byte) error {
	tmp, err := os.CreateTemp(f.root, ".credential-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, f.path(id))
}

func (f fileBlobs) Get(id string) ([]byte, error) {
	data, err := os.ReadFile(f.path(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return data, err
}

func (f fileBlobs) List() ([]string, error) {
	entries, err := os.ReadDir(f.root)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		ids = append(ids, strings.TrimSuffix(entry.Name(), ".json"))
	}
	return ids, nil
}

func (f fileBlobs) Delete(id string) error {
	if err := os.Remove(f.path(id)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotFound
		}
		return err
	}
	return nil
}
