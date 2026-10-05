package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

type apiDefinitionMetadata struct {
	ID             string `json:"id"`
	Format         string `json:"format"`
	OperationCount int    `json:"operation_count"`
	SizeBytes      int    `json:"size_bytes"`
}

func (s *Server) handleAPIDefinitions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, scanner.MaxOpenAPISpecBytes))
	if err != nil {
		http.Error(w, "API definition exceeds the 5 MiB upload limit", http.StatusRequestEntityTooLarge)
		return
	}
	endpoints, err := scanner.ParseAPIDefinition(body, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hash := sha256.Sum256(body)
	id := hex.EncodeToString(hash[:])
	dir := filepath.Join(s.dataDir, "_api_definitions")
	if err := os.MkdirAll(dir, 0700); err != nil {
		http.Error(w, "failed to store API definition", http.StatusInternalServerError)
		return
	}
	path := filepath.Join(dir, id+".spec")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		tmp, err := os.CreateTemp(dir, ".api-definition-*.tmp")
		if err != nil {
			http.Error(w, "failed to store API definition", http.StatusInternalServerError)
			return
		}
		tmpPath := tmp.Name()
		defer os.Remove(tmpPath)
		if err := tmp.Chmod(0600); err != nil {
			tmp.Close()
			http.Error(w, "failed to store API definition", http.StatusInternalServerError)
			return
		}
		if _, err := tmp.Write(body); err != nil {
			tmp.Close()
			http.Error(w, "failed to store API definition", http.StatusInternalServerError)
			return
		}
		if err := tmp.Sync(); err != nil {
			tmp.Close()
			http.Error(w, "failed to store API definition", http.StatusInternalServerError)
			return
		}
		if err := tmp.Close(); err != nil {
			http.Error(w, "failed to store API definition", http.StatusInternalServerError)
			return
		}
		if err := os.Rename(tmpPath, path); err != nil {
			http.Error(w, "failed to store API definition", http.StatusInternalServerError)
			return
		}
	} else if err != nil {
		http.Error(w, "failed to read stored API definition", http.StatusInternalServerError)
		return
	}
	format := "graphql"
	if _, err := scanner.ParseOpenAPI(body, ""); err == nil {
		format = "yaml"
	}
	if json.Valid(body) {
		format = "json"
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(apiDefinitionMetadata{ID: id, Format: format, OperationCount: len(endpoints), SizeBytes: len(body)})
}

func loadAPIDefinition(dataDir, id string) ([]byte, error) {
	decoded, err := hex.DecodeString(id)
	if err != nil || len(decoded) != sha256.Size {
		return nil, fmt.Errorf("invalid API definition ID")
	}
	return os.ReadFile(filepath.Join(dataDir, "_api_definitions", id+".spec"))
}
