package web

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

func TestMonitoringConfigurationAndValidation(t *testing.T) {
	s := &Server{dataDir: t.TempDir(), cfg: &config.Config{Username: "admin", Password: "test"}}
	bad := monitoringConfig{ManagerURL: "http://localhost:55000", IndexerURL: "https://example.com", ManagerUser: "m", ManagerPass: "secret", IndexerUser: "i", IndexerPass: "secret", AgentHost: "manager.example"}
	b, _ := json.Marshal(bad)
	w := httptest.NewRecorder()
	s.handleMonitoring(w, httptest.NewRequest("PUT", "/api/monitoring/connection", strings.NewReader(string(b))))
	if w.Code != 400 {
		t.Fatalf("HTTP URL accepted: %d %s", w.Code, w.Body.String())
	}
	bad.ManagerURL = "https://manager.example:55000"
	bad.AllowedCommands = []string{"restart", "restart"}
	b, _ = json.Marshal(bad)
	w = httptest.NewRecorder()
	s.handleMonitoring(w, httptest.NewRequest("PUT", "/api/monitoring/connection", strings.NewReader(string(b))))
	if w.Code != 400 {
		t.Fatalf("duplicate command accepted: %d", w.Code)
	}
	bad.AllowedCommands = []string{"restart"}
	b, _ = json.Marshal(bad)
	w = httptest.NewRecorder()
	s.handleMonitoring(w, httptest.NewRequest("PUT", "/api/monitoring/connection", strings.NewReader(string(b))))
	if w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.handleMonitoring(w, httptest.NewRequest("GET", "/api/monitoring/connection", nil))
	if strings.Contains(w.Body.String(), "secret") || !strings.Contains(w.Body.String(), "has_manager_password") {
		t.Fatalf("secret exposure or missing masked state: %s", w.Body.String())
	}
}

func TestMonitoringTLSAndResponseGuard(t *testing.T) {
	called := 0
	fake := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/security/user/authenticate":
			if user, pass, ok := r.BasicAuth(); !ok || user != "manager" || pass != "secret" {
				w.WriteHeader(401)
				return
			}
			_, _ = w.Write([]byte(`{"data":{"token":"jwt"}}`))
		case "/agents":
			if r.Header.Get("Authorization") != "Bearer jwt" {
				w.WriteHeader(401)
				return
			}
			_, _ = w.Write([]byte(`{"data":{"affected_items":[{"id":"001","name":"host"}],"total_affected_items":1}}`))
		case "/active-response":
			called++
			if r.URL.Query().Get("agents_list") != "001" {
				t.Errorf("wrong target: %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"data":{"affected_items":["001"]}}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer fake.Close()
	cert, err := x509.ParseCertificate(fake.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	s := &Server{dataDir: t.TempDir(), cfg: &config.Config{Username: "admin", Password: "test"}}
	if err := s.saveMonitoringConfig(monitoringConfig{ManagerURL: fake.URL, IndexerURL: fake.URL, ManagerUser: "manager", ManagerPass: "secret", IndexerUser: "indexer", IndexerPass: "secret", CAPEM: ca, AgentHost: "manager.test", AllowedCommands: []string{"restart"}}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.handleMonitoring(w, httptest.NewRequest("GET", "/api/monitoring/agents?page=1&limit=5", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"host"`) {
		t.Fatalf("agents: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.handleMonitoring(w, httptest.NewRequest("GET", "/api/monitoring/agents?page=0", nil))
	if w.Code != 400 {
		t.Fatalf("bad page: %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.handleMonitoring(w, httptest.NewRequest("POST", "/api/monitoring/agents/all/active-response", strings.NewReader(`{"command":"restart","confirm_agent":"all"}`)))
	if w.Code != 400 || called != 0 {
		t.Fatalf("bulk action accepted: %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.handleMonitoring(w, httptest.NewRequest("POST", "/api/monitoring/agents/001/active-response", strings.NewReader(`{"command":"arbitrary","confirm_agent":"001"}`)))
	if w.Code != 403 || called != 0 {
		t.Fatalf("unlisted command accepted: %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.handleMonitoring(w, httptest.NewRequest("POST", "/api/monitoring/agents/001/active-response", strings.NewReader(`{"command":"restart","confirm_agent":"001"}`)))
	if w.Code != 200 || called != 1 {
		t.Fatalf("approved command: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.handleMonitoring(w, httptest.NewRequest("GET", "/api/monitoring/audit", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "submitted") {
		t.Fatalf("audit: %d %s", w.Code, w.Body.String())
	}
}

func TestMonitoringEnrollmentPersists(t *testing.T) {
	s := &Server{dataDir: t.TempDir(), cfg: &config.Config{Username: "admin", Password: "test"}}
	w := httptest.NewRecorder()
	s.handleMonitoring(w, httptest.NewRequest("POST", "/api/monitoring/enrollments", strings.NewReader(`{"name":"server-01","os":"Linux"}`)))
	if w.Code != 201 {
		t.Fatalf("add enrollment: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.handleMonitoring(w, httptest.NewRequest("GET", "/api/monitoring/enrollments", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "server-01") {
		t.Fatalf("read enrollment: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.handleMonitoring(w, httptest.NewRequest("POST", "/api/monitoring/enrollments", strings.NewReader(`{"name":"server-01","os":"Linux"}`)))
	if w.Code != 409 {
		t.Fatalf("duplicate enrollment: %d", w.Code)
	}
}

func TestMonitoringRequiresDashboardAuthentication(t *testing.T) {
	s := &Server{dataDir: t.TempDir(), cfg: &config.Config{}}
	w := httptest.NewRecorder()
	s.handleMonitoring(w, httptest.NewRequest("GET", "/api/monitoring/connection", nil))
	if w.Code != 403 {
		t.Fatalf("monitoring exposed without dashboard auth: %d", w.Code)
	}
}

func TestMonitoringRejectsInvalidCA(t *testing.T) {
	if _, err := monitoringHTTPClient(monitoringConfig{CAPEM: "not a certificate"}); err == nil {
		t.Fatal("invalid CA accepted")
	}
}
