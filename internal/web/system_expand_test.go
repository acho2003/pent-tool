package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleSystemExpandInline(t *testing.T) {
	s := &Server{dataDir: t.TempDir()}
	body := `{"template":{"name":"EMIS","base_url":"https://dev-emis.systems.gov.bt","path_template":"/svc/{name}","verify_template":"/svc/{name}/health"},"service_names":["common","academic"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/systems/expand", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleSystemExpand(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp servicesImportResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Services) != 2 {
		t.Fatalf("want 2 services, got %d", len(resp.Services))
	}
	if resp.Services[0].URLs[0] != "https://dev-emis.systems.gov.bt/svc/common" {
		t.Fatalf("unexpected url %q", resp.Services[0].URLs[0])
	}
	if resp.Services[0].ProtectedPath != "/svc/common/health" {
		t.Fatalf("unexpected protected path %q", resp.Services[0].ProtectedPath)
	}
}

func TestHandleSystemExpandStoredTemplate(t *testing.T) {
	s := &Server{dataDir: t.TempDir()}
	// Create a template via the handler.
	create := `{"name":"EMIS","base_url":"https://h","path_template":"/svc/{name}","verify_template":"/svc/{name}/me"}`
	rec := httptest.NewRecorder()
	s.handleSystemTemplates(rec, httptest.NewRequest(http.MethodPost, "/api/system-templates", strings.NewReader(create)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status %d: %s", rec.Code, rec.Body.String())
	}
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatal("no id returned")
	}
	// Expand by stored id.
	rec2 := httptest.NewRecorder()
	s.handleSystemExpand(rec2, httptest.NewRequest(http.MethodPost, "/api/systems/expand",
		strings.NewReader(`{"template_id":"`+id+`","service_names":["student"]}`)))
	if rec2.Code != http.StatusOK {
		t.Fatalf("expand status %d: %s", rec2.Code, rec2.Body.String())
	}
	if !strings.Contains(rec2.Body.String(), "https://h/svc/student") {
		t.Fatalf("expand body missing expanded url: %s", rec2.Body.String())
	}
}

func TestHandleSystemTemplatesRejectsSecret(t *testing.T) {
	s := &Server{dataDir: t.TempDir()}
	bad := `{"name":"X","base_url":"https://h","path_template":"/svc/{name}","verify_marker":"eyJhbGciOiJIUzI1NiJ9.x.y"}`
	rec := httptest.NewRecorder()
	s.handleSystemTemplates(rec, httptest.NewRequest(http.MethodPost, "/api/system-templates", strings.NewReader(bad)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for secret-bearing template, got %d", rec.Code)
	}
}

func TestHandleSystemTemplateDetailLifecycle(t *testing.T) {
	s := &Server{dataDir: t.TempDir()}
	rec := httptest.NewRecorder()
	s.handleSystemTemplates(rec, httptest.NewRequest(http.MethodPost, "/api/system-templates",
		strings.NewReader(`{"name":"X","base_url":"https://h","path_template":"/svc/{name}","verify_template":"/svc/{name}/me"}`)))
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	id := created["id"].(string)

	// DELETE then confirm GET 404s.
	del := httptest.NewRecorder()
	s.handleSystemTemplateDetail(del, httptest.NewRequest(http.MethodDelete, "/api/system-templates/"+id, nil))
	if del.Code != http.StatusNoContent {
		t.Fatalf("delete status %d", del.Code)
	}
	get := httptest.NewRecorder()
	s.handleSystemTemplateDetail(get, httptest.NewRequest(http.MethodGet, "/api/system-templates/"+id, nil))
	if get.Code != http.StatusNotFound {
		t.Fatalf("want 404 after delete, got %d", get.Code)
	}
}
