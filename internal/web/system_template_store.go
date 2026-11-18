package web

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/acho2003/pent-tool/internal/assessment"
)

// systemTemplateStore persists reusable microservice-system templates as one
// JSON file per template under <dataDir>/_system_templates. Templates hold only
// conventions (URL patterns, auth header name/prefix) — never secrets — so the
// store is plain JSON, unlike the encrypted credential vault.
type systemTemplateStore struct{ dir string }

func newSystemTemplateStore(dataDir string) *systemTemplateStore {
	return &systemTemplateStore{dir: filepath.Join(dataDir, "_system_templates")}
}

func (st *systemTemplateStore) ensure() error {
	return os.MkdirAll(st.dir, 0o700)
}

func validTemplateID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'f' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func newTemplateID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func (st *systemTemplateStore) path(id string) (string, error) {
	if !validTemplateID(id) {
		return "", fmt.Errorf("invalid template id")
	}
	return filepath.Join(st.dir, id+".json"), nil
}

func (st *systemTemplateStore) List() ([]assessment.SystemTemplate, error) {
	entries, err := os.ReadDir(st.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []assessment.SystemTemplate{}, nil
		}
		return nil, err
	}
	out := []assessment.SystemTemplate{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		tpl, err := st.Get(id)
		if err != nil {
			continue // skip unreadable entries rather than failing the whole list
		}
		out = append(out, tpl)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UpdatedAt.Equal(out[j].UpdatedAt) {
			return out[i].Name < out[j].Name
		}
		return out[i].UpdatedAt.After(out[j].UpdatedAt)
	})
	return out, nil
}

func (st *systemTemplateStore) Get(id string) (assessment.SystemTemplate, error) {
	p, err := st.path(id)
	if err != nil {
		return assessment.SystemTemplate{}, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return assessment.SystemTemplate{}, err
	}
	var tpl assessment.SystemTemplate
	if err := json.Unmarshal(raw, &tpl); err != nil {
		return assessment.SystemTemplate{}, err
	}
	return tpl, nil
}

// Put writes the template atomically (temp file + rename, 0600).
func (st *systemTemplateStore) Put(tpl assessment.SystemTemplate) error {
	if err := st.ensure(); err != nil {
		return err
	}
	p, err := st.path(tpl.ID)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(tpl, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(st.dir, ".system-template-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
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
	return os.Rename(tmpPath, p)
}

func (st *systemTemplateStore) Delete(id string) error {
	p, err := st.path(id)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
