package web

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/apifixture"
)

func (s *Server) handleAPIFixtures(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, apifixture.MaxBytes)
	contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	meta, err := (apifixture.Store{Dir: filepath.Join(s.dataDir, "_api_fixtures")}).Put(r.Body, contentType)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) || strings.Contains(err.Error(), "limit") {
			http.Error(w, "API fixture exceeds 1 MiB upload limit", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSONStatus(w, http.StatusCreated, meta)
}

func (s *Server) handleAPIFixture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ref := strings.TrimPrefix(r.URL.Path, "/api/api-fixtures/")
	if ref == "" || strings.Contains(ref, "/") {
		http.NotFound(w, r)
		return
	}
	f, err := (apifixture.Store{Dir: filepath.Join(s.dataDir, "_api_fixtures")}).Open(ref)
	if err != nil {
		if errors.Is(err, apifixture.ErrInvalidRef) {
			http.Error(w, "invalid API fixture reference", http.StatusBadRequest)
			return
		}
		if errors.Is(err, os.ErrNotExist) {
			http.NotFound(w, r)
			return
		}
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, f)
}
