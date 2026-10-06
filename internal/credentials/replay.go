package credentials

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/xalgord/xalgorix/v4/internal/storage"
)

// ReplayRequest is private request material encrypted using the existing
// credential key. Public inventories and manifests contain only its reference.
type ReplayRequest struct {
	EndpointID  string            `json:"endpoint_id"`
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	ContentType string            `json:"content_type,omitempty"`
	Body        string            `json:"body,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
}
type ReplayStore struct {
	root string
	aead cipher.AEAD
}

func NewReplayStore(root string, key []byte) (*ReplayStore, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if err := storage.EnsureSecureDir(root); err != nil {
		return nil, err
	}
	return &ReplayStore{root: root, aead: aead}, nil
}
func replayAAD(scope, auth, ref string) []byte {
	return []byte("xalgorix:request-replay:v1\x00" + scope + "\x00" + auth + "\x00" + ref)
}
func (s *ReplayStore) Put(scope, auth string, request ReplayRequest) (string, error) {
	if s == nil || scope == "" || request.EndpointID == "" || request.URL == "" || request.Method == "" {
		return "", fmt.Errorf("bound request replay storage unavailable")
	}
	data, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	if len(data) > 3<<20 {
		return "", fmt.Errorf("request replay exceeds 3 MiB")
	}
	sum := sha256.Sum256(append(replayAAD(scope, auth, ""), data...))
	ref := hex.EncodeToString(sum[:])
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	encrypted := s.aead.Seal(nonce, nonce, data, replayAAD(scope, auth, ref))
	file, err := os.CreateTemp(s.root, ".replay-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(encrypted); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	dst := filepath.Join(s.root, ref+".enc")
	if err = os.Link(file.Name(), dst); err != nil {
		if !os.IsExist(err) {
			return "", err
		}
		old, getErr := s.Get(scope, auth, ref)
		if getErr != nil {
			return "", getErr
		}
		prior, _ := json.Marshal(old)
		if string(prior) != string(data) {
			return "", fmt.Errorf("immutable replay conflict")
		}
	}
	parent, err := os.Open(s.root)
	if err != nil {
		return "", err
	}
	defer parent.Close()
	if err = parent.Sync(); err != nil {
		return "", err
	}
	return ref, nil
}
func (s *ReplayStore) Get(scope, auth, ref string) (ReplayRequest, error) {
	var request ReplayRequest
	decoded, err := hex.DecodeString(ref)
	if s == nil || err != nil || len(decoded) != sha256.Size || scope == "" {
		return request, fmt.Errorf("invalid request replay binding")
	}
	path := filepath.Join(s.root, ref+".enc")
	info, err := os.Lstat(path)
	if err != nil {
		return request, err
	}
	if !info.Mode().IsRegular() || info.Size() > 4<<20 {
		return request, fmt.Errorf("invalid replay file")
	}
	encrypted, err := os.ReadFile(path)
	if err != nil {
		return request, err
	}
	size := s.aead.NonceSize()
	if len(encrypted) < size {
		return request, fmt.Errorf("invalid replay envelope")
	}
	data, err := s.aead.Open(nil, encrypted[:size], encrypted[size:], replayAAD(scope, auth, ref))
	if err != nil {
		return request, fmt.Errorf("request replay credential binding failed")
	}
	sum := sha256.Sum256(append(replayAAD(scope, auth, ""), data...))
	if hex.EncodeToString(sum[:]) != ref {
		return request, fmt.Errorf("request replay integrity failed")
	}
	if err = json.Unmarshal(data, &request); err != nil {
		return request, fmt.Errorf("invalid replay request")
	}
	return request, nil
}
