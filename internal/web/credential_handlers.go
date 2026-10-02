package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/credentials"
)

const maxCredentialRequestBytes = 64 << 10

type credentialRequest struct {
	Name      string                `json:"name"`
	Kind      assessment.AccessKind `json:"kind"`
	TargetIDs []string              `json:"target_ids"`
	Values    map[string]string     `json:"values"`
}

func (s *Server) credentialVault() (*credentials.Vault, error) {
	key, err := credentials.LoadKeyFile(os.Getenv("XALGORIX_CREDENTIAL_KEY_FILE"))
	if err != nil {
		return nil, err
	}
	return credentials.New(path.Join(s.dataDir, "_credentials"), key)
}

func (s *Server) openCredentialVault() (*credentials.Vault, error) {
	key, err := credentials.LoadKeyFile(os.Getenv("XALGORIX_CREDENTIAL_KEY_FILE"))
	if err != nil {
		return nil, err
	}
	return credentials.Open(path.Join(s.dataDir, "_credentials"), key)
}

func (s *Server) handleCredentials(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vault, err := s.credentialVault()
	if err != nil {
		http.Error(w, "encrypted credential storage is unavailable: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		list, err := vault.List()
		if err != nil {
			http.Error(w, "failed to read credential metadata", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(list)
	case http.MethodPost:
		var req credentialRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCredentialRequestBytes)).Decode(&req); err != nil {
			http.Error(w, "invalid credential request", http.StatusBadRequest)
			return
		}
		meta, err := vault.Create(credentials.Record{Name: req.Name, Kind: req.Kind, TargetIDs: req.TargetIDs, Values: req.Values})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(meta)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleCredentialDetail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/credentials/"), "/")
	if id == "" || strings.Contains(id, "/") {
		http.Error(w, "credential not found", http.StatusNotFound)
		return
	}
	vault, err := s.credentialVault()
	if err != nil {
		http.Error(w, "encrypted credential storage is unavailable: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		record, err := vault.Get(id, "")
		if credentialError(w, err) {
			return
		}
		_ = json.NewEncoder(w).Encode(credentials.Metadata{ID: record.ID, Name: record.Name, Kind: record.Kind, TargetIDs: record.TargetIDs, CreatedAt: record.CreatedAt})
	case http.MethodPut:
		var req credentialRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCredentialRequestBytes)).Decode(&req); err != nil {
			http.Error(w, "invalid credential request", http.StatusBadRequest)
			return
		}
		meta, err := vault.Replace(id, credentials.Record{Name: req.Name, Kind: req.Kind, TargetIDs: req.TargetIDs, Values: req.Values})
		if credentialError(w, err) {
			return
		}
		_ = json.NewEncoder(w).Encode(meta)
	case http.MethodDelete:
		if credentialError(w, vault.Delete(id)) {
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func credentialError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, credentials.ErrNotFound) {
		http.Error(w, "credential not found", http.StatusNotFound)
	} else {
		http.Error(w, "credential operation failed", http.StatusInternalServerError)
	}
	return true
}
