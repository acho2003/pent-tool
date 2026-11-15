package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

const maxSystemTemplateBytes = 1 << 16

// handleSystemTemplates serves GET (list) and POST (create) for reusable
// microservice-system templates.
func (s *Server) handleSystemTemplates(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	store := newSystemTemplateStore(s.dataDir)
	switch r.Method {
	case http.MethodGet:
		list, err := store.List()
		if err != nil {
			http.Error(w, "failed to read system templates", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(list)
	case http.MethodPost:
		tpl, ok := decodeSystemTemplate(w, r)
		if !ok {
			return
		}
		id, err := newTemplateID()
		if err != nil {
			http.Error(w, "failed to allocate template id", http.StatusInternalServerError)
			return
		}
		tpl.ID = id
		tpl.CreatedAt = time.Now().UTC()
		tpl.UpdatedAt = tpl.CreatedAt
		if err := store.Put(tpl); err != nil {
			http.Error(w, "failed to store system template", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(tpl)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSystemTemplateDetail serves GET/PUT/DELETE for one template by id.
func (s *Server) handleSystemTemplateDetail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/system-templates/"), "/")
	if id == "" || strings.Contains(id, "/") || !validTemplateID(id) {
		http.Error(w, "system template not found", http.StatusNotFound)
		return
	}
	store := newSystemTemplateStore(s.dataDir)
	switch r.Method {
	case http.MethodGet:
		tpl, err := store.Get(id)
		if err != nil {
			http.Error(w, "system template not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(tpl)
	case http.MethodPut:
		existing, err := store.Get(id)
		if err != nil {
			http.Error(w, "system template not found", http.StatusNotFound)
			return
		}
		tpl, ok := decodeSystemTemplate(w, r)
		if !ok {
			return
		}
		tpl.ID = id
		tpl.CreatedAt = existing.CreatedAt
		tpl.UpdatedAt = time.Now().UTC()
		if err := store.Put(tpl); err != nil {
			http.Error(w, "failed to store system template", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(tpl)
	case http.MethodDelete:
		if err := store.Delete(id); err != nil {
			http.Error(w, "failed to delete system template", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// decodeSystemTemplate reads and validates a template from the request body.
// It writes an error response and returns ok=false on any problem.
func decodeSystemTemplate(w http.ResponseWriter, r *http.Request) (assessment.SystemTemplate, bool) {
	var tpl assessment.SystemTemplate
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSystemTemplateBytes)).Decode(&tpl); err != nil {
		http.Error(w, "invalid system template request", http.StatusBadRequest)
		return assessment.SystemTemplate{}, false
	}
	tpl = tpl.WithDefaults()
	if p := assessment.FirstBlocking(tpl.Validate()); p != nil {
		http.Error(w, p.Message, http.StatusBadRequest)
		return assessment.SystemTemplate{}, false
	}
	return tpl, true
}
