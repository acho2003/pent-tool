// Package apifixture stores API request bodies by content hash. Callers persist
// only the returned reference in scan plans and records, never fixture bytes.
package apifixture

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const MaxBytes = 1 << 20

var ErrInvalidRef = errors.New("invalid API fixture reference")

type Metadata struct {
	Ref         string `json:"ref"`
	SizeBytes   int    `json:"size_bytes"`
	ContentType string `json:"content_type,omitempty"`
}

type Store struct{ Dir string }

func (s Store) Put(r io.Reader, contentType string) (Metadata, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil {
		return Metadata{}, err
	}
	if len(data) > MaxBytes {
		return Metadata{}, fmt.Errorf("API fixture exceeds %d byte limit", MaxBytes)
	}
	if len(data) == 0 {
		return Metadata{}, errors.New("API fixture must not be empty")
	}
	sum := sha256.Sum256(data)
	ref := hex.EncodeToString(sum[:])
	if err := os.MkdirAll(s.Dir, 0700); err != nil {
		return Metadata{}, err
	}
	path := filepath.Join(s.Dir, ref+".body")
	if _, err := os.Stat(path); err == nil {
		return Metadata{Ref: ref, SizeBytes: len(data), ContentType: contentType}, nil
	} else if !os.IsNotExist(err) {
		return Metadata{}, err
	}
	tmp, err := os.CreateTemp(s.Dir, ".fixture-*.tmp")
	if err != nil {
		return Metadata{}, err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return Metadata{}, err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return Metadata{}, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return Metadata{}, err
	}
	if err := tmp.Close(); err != nil {
		return Metadata{}, err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		if _, statErr := os.Stat(path); statErr != nil {
			return Metadata{}, err
		}
	}
	return Metadata{Ref: ref, SizeBytes: len(data), ContentType: contentType}, nil
}

func (s Store) Open(ref string) (*os.File, error) {
	decoded, err := hex.DecodeString(ref)
	if err != nil || len(decoded) != sha256.Size {
		return nil, ErrInvalidRef
	}
	return os.Open(filepath.Join(s.Dir, ref+".body"))
}
