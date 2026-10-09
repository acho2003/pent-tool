package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/credentials"
)

const maxCredentialRequestBytes = 64 << 10

type credentialRequest struct {
	BrowserStorage *credentials.BrowserStorage `json:"browser_storage,omitempty"`
	Name           string                      `json:"name"`
	Kind           assessment.AccessKind       `json:"kind"`
	TargetIDs      []string                    `json:"target_ids"`
	Values         map[string]string           `json:"values"`
}

type testCredentialRequest struct {
	Browser      bool   `json:"browser,omitempty"`
	TargetID     string `json:"target_id"`
	TargetURL    string `json:"target_url"`
	VerifyURL    string `json:"verify_url"`
	VerifyMarker string `json:"verify_marker"`
}

type testCredentialResponse struct {
	Verified bool   `json:"verified"`
	State    string `json:"state"`
	Reason   string `json:"reason"`
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
		meta, err := vault.Create(credentials.Record{Name: req.Name, Kind: req.Kind, TargetIDs: req.TargetIDs, Values: req.Values, BrowserStorage: req.BrowserStorage})
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
	if strings.HasSuffix(id, "/test") {
		id = strings.TrimSuffix(id, "/test")
		if id == "" || strings.Contains(id, "/") {
			http.Error(w, "credential not found", http.StatusNotFound)
			return
		}
		s.handleTestCredential(w, r, id)
		return
	}
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
		_ = json.NewEncoder(w).Encode(credentials.Metadata{ID: record.ID, Name: record.Name, Kind: record.Kind, TargetIDs: record.TargetIDs, CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt, Revision: record.Revision})
	case http.MethodPut:
		var req credentialRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCredentialRequestBytes)).Decode(&req); err != nil {
			http.Error(w, "invalid credential request", http.StatusBadRequest)
			return
		}
		meta, err := vault.Replace(id, credentials.Record{Name: req.Name, Kind: req.Kind, TargetIDs: req.TargetIDs, Values: req.Values, BrowserStorage: req.BrowserStorage})
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

func (s *Server) handleTestCredential(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req testCredentialRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCredentialRequestBytes)).Decode(&req); err != nil {
		http.Error(w, "invalid credential test request", http.StatusBadRequest)
		return
	}
	result := testCredentialResponse{State: "unavailable"}
	if req.TargetID == "" || req.TargetURL == "" {
		result.Reason = "choose an HTTP(S) target before testing authentication"
		writeCredentialTestResult(w, result)
		return
	}
	if !strings.HasPrefix(strings.ToLower(req.TargetURL), "http://") && !strings.HasPrefix(strings.ToLower(req.TargetURL), "https://") {
		result.Reason = "authentication tests require an explicit HTTP(S) target"
		writeCredentialTestResult(w, result)
		return
	}
	if s.isBlockedTargetForScan(req.TargetURL, nil) {
		result.Reason = "target is blocked by the application scope guard"
		writeCredentialTestResult(w, result)
		return
	}
	verifyURL := req.VerifyURL
	if verifyURL == "" {
		verifyURL = req.TargetURL
	}
	if !urlWithinApplication(req.TargetURL, verifyURL) || !scopeAllowsRequest(applicationScope(req.TargetURL), verifyURL) {
		result.Reason = "verification URL is outside the target origin or path boundary"
		writeCredentialTestResult(w, result)
		return
	}
	vault, err := s.openCredentialVault()
	if err != nil {
		result.Reason = "encrypted credential storage is unavailable"
		writeCredentialTestResult(w, result)
		return
	}
	record, err := vault.Get(id, req.TargetID)
	if err != nil || !webAuthenticationKind(record.Kind) {
		result.Reason = "credential is unavailable or is not bound to this target"
		writeCredentialTestResult(w, result)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	scope := applicationScope(req.TargetURL)
	if record.Kind == assessment.AccessFormLogin {
		// A "browser" submit format logs in through a real browser (for
		// NextAuth/SPA logins the HTTP replayer cannot reproduce), then verifies
		// the captured session exactly as an operator-supplied credential. The
		// marker is optional here: without one the check falls back to the
		// authenticated-vs-anonymous contrast, as the header path does.
		if strings.EqualFold(strings.TrimSpace(record.Values["submit_format"]), "browser") {
			cookieHeader, capturedStorage, loginErr := s.captureBrowserLoginSession(ctx, req.TargetURL, verifyURL, req.VerifyMarker, record.Values)
			if loginErr != nil {
				result.State, result.Reason = "failed", "browser login failed: "+loginErr.Error()
				writeCredentialTestResult(w, result)
				return
			}
			lines := []string{cookieHeader}
			storage := capturedStorage
			if storage == nil {
				storage = record.BrowserStorage
			}
			if req.Browser || storage != nil {
				if err := s.verifyBrowserCredential(ctx, req.TargetURL, verifyURL, req.VerifyMarker, lines, storage, true); err != nil {
					result.State, result.Reason = "failed", err.Error()
					writeCredentialTestResult(w, result)
					return
				}
				result.State, result.Verified, result.Reason = "verified", true, "Browser login succeeded; protected-route marker and anonymous negative control passed"
				writeCredentialTestResult(w, result)
				return
			}
			positive, probeErr := probeHeaderSession(ctx, verifyURL, req.VerifyMarker, lines, req.TargetURL)
			if probeErr == nil && req.VerifyMarker != "" {
				probeErr = verifyNegativeControl(ctx, scope, verifyURL, req.VerifyMarker)
			} else if probeErr == nil {
				probeErr = verifyAnonymousContrast(ctx, scope, verifyURL, positive)
			}
			if probeErr != nil {
				result.State, result.Reason = "failed", probeErr.Error()
				writeCredentialTestResult(w, result)
				return
			}
			result.State, result.Verified, result.Reason = "verified", true, "Browser login succeeded and the captured session passed the protected-page and anonymous-control checks"
			writeCredentialTestResult(w, result)
			return
		}
		if req.VerifyMarker == "" {
			result.Reason = "form login requires a verification marker"
			writeCredentialTestResult(w, result)
			return
		}
		cookieHeader, loginErr := verifyFormSession(ctx, req.TargetURL, verifyURL, req.VerifyMarker, record.Values)
		if loginErr != nil {
			// Surface the specific reason (rejected status, missing session
			// cookie, marker not found at a path). These messages are written to
			// carry only status codes and paths, never credential values.
			result.State, result.Reason = "failed", "form login failed: "+loginErr.Error()
			writeCredentialTestResult(w, result)
			return
		}
		if req.Browser || record.BrowserStorage != nil {
			if err := s.verifyBrowserCredential(ctx, req.TargetURL, verifyURL, req.VerifyMarker, []string{cookieHeader}, record.BrowserStorage, true); err != nil {
				result.State, result.Reason = "failed", err.Error()
				writeCredentialTestResult(w, result)
				return
			}
			result.State, result.Verified, result.Reason = "verified", true, "Browser protected-route marker and anonymous negative control passed"
			writeCredentialTestResult(w, result)
			return
		}
		marker := req.VerifyMarker
		if err := verifyNegativeControl(ctx, scope, verifyURL, marker); err != nil {
			result.State, result.Reason = "failed", "anonymous negative-control check failed"
			writeCredentialTestResult(w, result)
			return
		}
	} else {
		lines, err := credentialHeaderLines(record.Kind, record.Values)
		if err != nil {
			result.Reason = "credential fields are not valid HTTP headers"
			writeCredentialTestResult(w, result)
			return
		}
		if req.Browser || record.BrowserStorage != nil {
			if err := s.verifyBrowserCredential(ctx, req.TargetURL, verifyURL, req.VerifyMarker, lines, record.BrowserStorage, true); err != nil {
				result.State, result.Reason = "failed", err.Error()
				writeCredentialTestResult(w, result)
				return
			}
			result.State, result.Verified, result.Reason = "verified", true, "Browser protected-route marker and anonymous negative control passed"
			writeCredentialTestResult(w, result)
			return
		}
		positive, err := probeHeaderSession(ctx, verifyURL, req.VerifyMarker, lines, req.TargetURL)
		if err == nil && req.VerifyMarker != "" {
			err = verifyNegativeControl(ctx, scope, verifyURL, req.VerifyMarker)
		} else if err == nil {
			err = verifyAnonymousContrast(ctx, scope, verifyURL, positive)
		}
		if err != nil {
			result.State, result.Reason = "failed", err.Error()
			writeCredentialTestResult(w, result)
			return
		}
	}
	result.Verified, result.State, result.Reason = true, "verified", "credentials passed the protected-page and anonymous-control checks"
	writeCredentialTestResult(w, result)
}

func writeCredentialTestResult(w http.ResponseWriter, result testCredentialResponse) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
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
