// Package credentials stores target-bound scanner credentials encrypted at rest.
package credentials

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

const KeySize = 32

var ErrNotFound = errors.New("credential not found")
var ErrTargetNotBound = errors.New("credential is not bound to this target")

// Record contains secret values and is never returned directly by API handlers.
type Record struct {
	ID        string                `json:"id"`
	Name      string                `json:"name"`
	Kind      assessment.AccessKind `json:"kind"`
	TargetIDs []string              `json:"target_ids"`
	Values    map[string]string     `json:"values"`
	CreatedAt time.Time             `json:"created_at"`
}

// Metadata is safe to return to clients; it contains no credential values.
type Metadata struct {
	ID        string                `json:"id"`
	Name      string                `json:"name"`
	Kind      assessment.AccessKind `json:"kind"`
	TargetIDs []string              `json:"target_ids"`
	CreatedAt time.Time             `json:"created_at"`
}

type Vault struct {
	root string
	aead cipher.AEAD
}

func New(root string, key []byte) (*Vault, error) {
	vault, err := Open(root, key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, fmt.Errorf("create credential vault: %w", err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		return nil, fmt.Errorf("secure credential vault: %w", err)
	}
	return vault, nil
}

// Open constructs a vault reader without creating or changing its directory.
// It is used by read-only plan previews, which must not mutate storage.
func Open(root string, key []byte) (*Vault, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return &Vault{root: root, aead: aead}, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("credential key must be exactly %d bytes", KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead, nil
}

func LoadKeyFile(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("XALGORIX_CREDENTIAL_KEY_FILE is not configured")
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read credential key: %w", err)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("credential key file must contain exactly %d raw bytes", KeySize)
	}
	return key, nil
}

func (v *Vault) Create(record Record) (Metadata, error) {
	if v == nil {
		return Metadata{}, errors.New("credential vault is unavailable")
	}
	record.Name = strings.TrimSpace(record.Name)
	if record.Name == "" {
		return Metadata{}, errors.New("credential name is required")
	}
	if !record.Kind.Valid() {
		return Metadata{}, fmt.Errorf("unsupported credential kind %q", record.Kind)
	}
	record.TargetIDs = normalizeTargets(record.TargetIDs)
	if len(record.TargetIDs) == 0 {
		return Metadata{}, errors.New("at least one target binding is required")
	}
	if len(record.Values) == 0 {
		return Metadata{}, errors.New("credential values are required")
	}
	for key, value := range record.Values {
		if strings.TrimSpace(key) == "" || value == "" {
			return Metadata{}, errors.New("credential keys and values must be non-empty")
		}
	}
	if err := validateFormValues(record); err != nil {
		return Metadata{}, err
	}
	id, err := randomID()
	if err != nil {
		return Metadata{}, err
	}
	record.ID = id
	record.CreatedAt = time.Now().UTC()
	if err := v.write(record); err != nil {
		return Metadata{}, err
	}
	return metadata(record), nil
}

func (v *Vault) Get(id, targetID string) (Record, error) {
	record, err := v.read(id)
	if err != nil {
		return Record{}, err
	}
	if targetID != "" && !contains(record.TargetIDs, targetID) {
		return Record{}, ErrTargetNotBound
	}
	return record, nil
}

func (v *Vault) List() ([]Metadata, error) {
	entries, err := os.ReadDir(v.root)
	if err != nil {
		return nil, err
	}
	out := make([]Metadata, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		record, err := v.read(strings.TrimSuffix(entry.Name(), ".json"))
		if err != nil {
			return nil, fmt.Errorf("read credential %s: %w", entry.Name(), err)
		}
		out = append(out, metadata(record))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (v *Vault) Replace(id string, replacement Record) (Metadata, error) {
	old, err := v.read(id)
	if err != nil {
		return Metadata{}, err
	}
	replacement.ID = old.ID
	replacement.CreatedAt = old.CreatedAt
	replacement.Name = strings.TrimSpace(replacement.Name)
	if replacement.Name == "" {
		return Metadata{}, errors.New("credential name is required")
	}
	if !replacement.Kind.Valid() {
		return Metadata{}, fmt.Errorf("unsupported credential kind %q", replacement.Kind)
	}
	replacement.TargetIDs = normalizeTargets(replacement.TargetIDs)
	if len(replacement.TargetIDs) == 0 || len(replacement.Values) == 0 {
		return Metadata{}, errors.New("target bindings and credential values are required")
	}
	for key, value := range replacement.Values {
		if strings.TrimSpace(key) == "" || value == "" {
			return Metadata{}, errors.New("credential keys and values must be non-empty")
		}
	}
	if err := validateFormValues(replacement); err != nil {
		return Metadata{}, err
	}
	if err := v.write(replacement); err != nil {
		return Metadata{}, err
	}
	return metadata(replacement), nil
}

func validateFormValues(record Record) error {
	if record.Kind != assessment.AccessFormLogin {
		return nil
	}
	for _, field := range []string{"login_url", "username", "password"} {
		if strings.TrimSpace(record.Values[field]) == "" {
			return fmt.Errorf("form login credential requires %s", field)
		}
	}
	login, err := url.Parse(record.Values["login_url"])
	if err != nil || (login.Scheme != "http" && login.Scheme != "https") || login.Host == "" || login.User != nil || login.Fragment != "" || login.RawQuery != "" {
		return errors.New("form login URL must be an absolute HTTP(S) URL without credentials, query, or fragment")
	}
	return nil
}

func (v *Vault) Delete(id string) error {
	if !validID(id) {
		return ErrNotFound
	}
	if err := os.Remove(filepath.Join(v.root, id+".json")); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

// RotateKey re-encrypts every credential into a staging directory before
// swapping it into place. If installation of the staged vault fails, it
// restores the original directory and keeps the old key active.
func (v *Vault) RotateKey(newKey []byte) error {
	newAEAD, err := newAEAD(newKey)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(v.root)
	if err != nil {
		return err
	}
	stage := v.root + ".rotate-" + randomSuffix()
	backup := v.root + ".backup-" + randomSuffix()
	if err := os.Mkdir(stage, 0700); err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	staged := &Vault{root: stage, aead: newAEAD}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		record, err := v.read(strings.TrimSuffix(entry.Name(), ".json"))
		if err != nil {
			return fmt.Errorf("cannot rotate unreadable credential %s: %w", entry.Name(), err)
		}
		if err := staged.write(record); err != nil {
			return err
		}
	}
	if err := os.Rename(v.root, backup); err != nil {
		return err
	}
	if err := os.Rename(stage, v.root); err != nil {
		_ = os.Rename(backup, v.root)
		return err
	}
	v.aead = newAEAD
	if err := os.RemoveAll(backup); err != nil {
		return fmt.Errorf("credential key rotated but old encrypted backup could not be removed: %w", err)
	}
	return nil
}

func (v *Vault) write(record Record) error {
	plain, err := json.Marshal(record)
	if err != nil {
		return err
	}
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	sealed := v.aead.Seal(nil, nonce, plain, []byte(record.ID))
	payload := append(nonce, sealed...)
	path := filepath.Join(v.root, record.ID+".json")
	tmp, err := os.CreateTemp(v.root, ".credential-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(payload); err != nil {
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
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return nil
}

func (v *Vault) read(id string) (Record, error) {
	if !validID(id) {
		return Record{}, ErrNotFound
	}
	payload, err := os.ReadFile(filepath.Join(v.root, id+".json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Record{}, ErrNotFound
		}
		return Record{}, err
	}
	if len(payload) < v.aead.NonceSize() {
		return Record{}, errors.New("credential ciphertext is truncated")
	}
	nonce := payload[:v.aead.NonceSize()]
	plain, err := v.aead.Open(nil, nonce, payload[v.aead.NonceSize():], []byte(id))
	if err != nil {
		return Record{}, errors.New("credential decryption failed")
	}
	var record Record
	if err := json.Unmarshal(plain, &record); err != nil {
		return Record{}, errors.New("credential record is invalid")
	}
	if record.ID != id {
		return Record{}, errors.New("credential record ID mismatch")
	}
	return record, nil
}

func metadata(record Record) Metadata {
	return Metadata{ID: record.ID, Name: record.Name, Kind: record.Kind, TargetIDs: append([]string(nil), record.TargetIDs...), CreatedAt: record.CreatedAt}
}

func randomID() (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func randomSuffix() string {
	id, err := randomID()
	if err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return id
}

func validID(id string) bool {
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded) == 16
}

func normalizeTargets(ids []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func contains(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}
