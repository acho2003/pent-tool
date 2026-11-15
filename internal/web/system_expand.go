package web

import (
	"encoding/json"
	"net/http"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

const maxSystemExpandBytes = 1 << 16

// systemExpandRequest expands a saved template (by id) or an inline template
// over a list of operator-supplied service names into services-table rows.
type systemExpandRequest struct {
	TemplateID   string                     `json:"template_id,omitempty"`
	Template     *assessment.SystemTemplate `json:"template,omitempty"`
	ServiceNames []string                   `json:"service_names"`
	BaseOverride string                     `json:"base_override,omitempty"`
}

// handleSystemExpand returns the same shape as POST /api/services/parse so the
// New Scan services table reuses its existing row handling, scope derivation and
// shared-token binding. Each expanded service becomes one row with its /svc/<name>
// URL and a protected_path from the template's verify path (in-scope by
// construction), ready for the shared-login card to attach the token.
func (s *Server) handleSystemExpand(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req systemExpandRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSystemExpandBytes)).Decode(&req); err != nil {
		http.Error(w, "invalid expand request", http.StatusBadRequest)
		return
	}

	var tpl assessment.SystemTemplate
	switch {
	case req.Template != nil:
		tpl = *req.Template
	case req.TemplateID != "":
		stored, err := newSystemTemplateStore(s.dataDir).Get(req.TemplateID)
		if err != nil {
			http.Error(w, "system template not found", http.StatusNotFound)
			return
		}
		tpl = stored
	default:
		http.Error(w, "provide template_id or an inline template", http.StatusBadRequest)
		return
	}

	exp, err := assessment.ExpandSystemTemplate(tpl, req.ServiceNames, req.BaseOverride)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	services := make([]importedService, 0, len(exp.Items))
	for _, item := range exp.Items {
		services = append(services, importedService{
			Name:          item.Name,
			URLs:          []string{item.URL},
			ProtectedPath: item.VerifyPath,
		})
	}
	_ = json.NewEncoder(w).Encode(servicesImportResponse{Services: services, Errors: []serviceImportError{}})
}
