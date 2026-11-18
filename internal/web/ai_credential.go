package web

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/acho2003/pent-tool/internal/credentials"
	"github.com/anthropics/anthropic-sdk-go/v2/option"
)

// The AI-report Claude credential is entered from the dashboard and stored
// encrypted at rest (AES-256-GCM with the same key file as the credential
// vault). Only its presence and kind are ever returned over the API — never the
// secret value. It is the GUI alternative to a mounted ant/Claude Code profile
// or an ANTHROPIC_* environment variable.

type aiCredential struct {
	Kind      string    `json:"kind"` // "api_key" | "auth_token"
	Secret    string    `json:"secret"`
	UpdatedAt time.Time `json:"updated_at"`
}

type aiConnectionStatus struct {
	Configured bool      `json:"configured"`
	Kind       string    `json:"kind,omitempty"`
	Source     string    `json:"source,omitempty"` // "stored" | "environment"
	UpdatedAt  time.Time `json:"updated_at,omitzero"`
}

func (s *Server) aiCredentialPath() string {
	return filepath.Join(s.dataDir, "_ai_credential.enc")
}

func aiVaultAEAD() (cipher.AEAD, error) {
	key, err := credentials.LoadKeyFile(os.Getenv("XALGORIX_CREDENTIAL_KEY_FILE"))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func validAICredentialKind(kind string) bool {
	return kind == "api_key" || kind == "auth_token"
}

// aiCredentialSet encrypts and stores the credential, replacing any existing one.
func (s *Server) aiCredentialSet(kind, secret string) error {
	kind, secret = strings.TrimSpace(kind), strings.TrimSpace(secret)
	if !validAICredentialKind(kind) {
		return fmt.Errorf("kind must be \"api_key\" or \"auth_token\"")
	}
	if secret == "" {
		return errors.New("credential value is required")
	}
	aead, err := aiVaultAEAD()
	if err != nil {
		return err
	}
	plain, err := json.Marshal(aiCredential{Kind: kind, Secret: secret, UpdatedAt: time.Now().UTC()})
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	sealed := aead.Seal(nonce, nonce, plain, nil)
	tmp, err := os.CreateTemp(s.dataDir, ".ai-credential-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(sealed); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, s.aiCredentialPath())
}

func (s *Server) aiCredentialClear() error {
	if err := os.Remove(s.aiCredentialPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// aiCredentialLoad decrypts the stored credential, if any.
func (s *Server) aiCredentialLoad() (aiCredential, bool) {
	sealed, err := os.ReadFile(s.aiCredentialPath())
	if err != nil {
		return aiCredential{}, false
	}
	aead, err := aiVaultAEAD()
	if err != nil {
		return aiCredential{}, false
	}
	if len(sealed) < aead.NonceSize() {
		return aiCredential{}, false
	}
	nonce, ct := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return aiCredential{}, false
	}
	var cred aiCredential
	if err := json.Unmarshal(plain, &cred); err != nil {
		return aiCredential{}, false
	}
	return cred, true
}

// aiConnection reports whether a credential is available (stored or env) and
// from which source, without ever exposing the secret.
func (s *Server) aiConnection() aiConnectionStatus {
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		return aiConnectionStatus{Configured: true, Kind: "api_key", Source: "environment"}
	}
	if os.Getenv("ANTHROPIC_AUTH_TOKEN") != "" {
		return aiConnectionStatus{Configured: true, Kind: "auth_token", Source: "environment"}
	}
	if cred, ok := s.aiCredentialLoad(); ok {
		return aiConnectionStatus{Configured: true, Kind: cred.Kind, Source: "stored", UpdatedAt: cred.UpdatedAt}
	}
	return aiConnectionStatus{Configured: false}
}

// aiReportConfigured reports whether AI report generation can run: the operator
// opted in via XALGORIX_AI_REPORT=1, OR a credential has been connected (env or
// stored). Connecting a credential in the GUI implicitly enables the feature.
func (s *Server) aiReportConfigured() bool {
	if aiReportEnabled() {
		return true
	}
	return s.aiConnection().Configured
}

// aiCredentialOptions returns the SDK request options for the stored credential.
// Env credentials are resolved by the SDK itself, so this returns nil when no
// credential is stored (the bare client then uses the env/profile chain).
func (s *Server) aiCredentialOptions() []option.RequestOption {
	if os.Getenv("ANTHROPIC_API_KEY") != "" || os.Getenv("ANTHROPIC_AUTH_TOKEN") != "" {
		return nil // SDK resolves these from the environment
	}
	cred, ok := s.aiCredentialLoad()
	if !ok {
		return nil
	}
	switch cred.Kind {
	case "api_key":
		return []option.RequestOption{option.WithAPIKey(cred.Secret)}
	case "auth_token":
		return []option.RequestOption{option.WithAuthToken(cred.Secret), option.WithHeaderAdd("anthropic-beta", oauthBetaHeader)}
	}
	return nil
}

// handleAIConnection serves GET (connection status), POST (store a credential)
// and DELETE (disconnect) for the dashboard "Connect Claude" card. The secret
// value is never returned; the response only reports presence, kind and source.
func (s *Server) handleAIConnection(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(s.aiConnection())
	case http.MethodPost:
		var req struct {
			Kind  string `json:"kind"`
			Value string `json:"value"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if s.aiConnectionEnvManaged() {
			http.Error(w, "a Claude credential is already set from the environment; unset ANTHROPIC_API_KEY/ANTHROPIC_AUTH_TOKEN to manage it here", http.StatusConflict)
			return
		}
		if err := s.aiCredentialSet(req.Kind, req.Value); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(s.aiConnection())
	case http.MethodDelete:
		if s.aiConnectionEnvManaged() {
			http.Error(w, "the Claude credential is set from the environment and cannot be cleared here", http.StatusConflict)
			return
		}
		if err := s.aiCredentialClear(); err != nil {
			http.Error(w, "failed to disconnect", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(s.aiConnection())
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) aiConnectionEnvManaged() bool {
	return os.Getenv("ANTHROPIC_API_KEY") != "" || os.Getenv("ANTHROPIC_AUTH_TOKEN") != ""
}
