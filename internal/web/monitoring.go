package web

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Wazuh retains the event store. Only the connection and operator actions live
// in Xalgorix's data directory, entirely separate from assessment records.
type monitoringConfig struct {
	ManagerURL      string   `json:"manager_url"`
	IndexerURL      string   `json:"indexer_url"`
	ManagerUser     string   `json:"manager_user"`
	ManagerPass     string   `json:"manager_password"`
	IndexerUser     string   `json:"indexer_user"`
	IndexerPass     string   `json:"indexer_password"`
	CAPEM           string   `json:"ca_pem"`
	AgentHost       string   `json:"agent_host"`
	AllowedCommands []string `json:"allowed_commands"`
}

type monitoringAction struct {
	Time    time.Time `json:"time"`
	Actor   string    `json:"actor"`
	AgentID string    `json:"agent_id"`
	Command string    `json:"command"`
	Status  string    `json:"status"`
	Result  string    `json:"result,omitempty"`
}

type monitoringEnrollment struct {
	Name      string    `json:"name"`
	OS        string    `json:"os"`
	CreatedAt time.Time `json:"created_at"`
}

var monitoringEnrollmentName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

var monitoringAuditMu sync.Mutex
var monitoringAgentID = regexp.MustCompile(`^[0-9]{3,12}$`)
var monitoringCommand = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,64}$`)

func (s *Server) monitoringDir() string { return filepath.Join(s.dataDir, "monitoring") }

func (s *Server) readMonitoringConfig() (monitoringConfig, error) {
	var cfg monitoringConfig
	b, err := os.ReadFile(filepath.Join(s.monitoringDir(), "connection.json"))
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	err = json.Unmarshal(b, &cfg)
	return cfg, err
}

func (s *Server) saveMonitoringConfig(cfg monitoringConfig) error {
	dir := s.monitoringDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".connection-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(dir, "connection.json"))
}

func validMonitoringURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && (u.Path == "" || u.Path == "/")
}

func monitoringHTTPClient(cfg monitoringConfig) (*http.Client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if cfg.CAPEM != "" && !roots.AppendCertsFromPEM([]byte(cfg.CAPEM)) {
		return nil, errors.New("invalid CA certificate")
	}
	return &http.Client{
		Timeout:       12 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func monitoringRequest(ctx context.Context, client *http.Client, method, base, path, user, pass, token string, body any) (json.RawMessage, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+path, reader)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	} else {
		req.SetBasicAuth(user, pass)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("Wazuh returned HTTP %d", res.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if !json.Valid(b) {
		return nil, errors.New("Wazuh returned invalid JSON")
	}
	return b, nil
}

func managerToken(ctx context.Context, client *http.Client, cfg monitoringConfig) (string, error) {
	raw, err := monitoringRequest(ctx, client, http.MethodPost, cfg.ManagerURL, "/security/user/authenticate", cfg.ManagerUser, cfg.ManagerPass, "", nil)
	if err != nil {
		return "", err
	}
	var result struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", err
	}
	if result.Data.Token == "" {
		return "", errors.New("Wazuh manager did not return a token")
	}
	return result.Data.Token, nil
}

func (s *Server) handleMonitoring(w http.ResponseWriter, r *http.Request) {
	if !authConfigured(s.cfg) {
		writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": "Configure dashboard authentication before using monitoring"})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/monitoring/")
	switch {
	case path == "connection":
		s.handleMonitoringConnection(w, r)
	case path == "health" && r.Method == http.MethodGet:
		s.handleMonitoringHealth(w, r)
	case path == "agents" && r.Method == http.MethodGet:
		s.monitoringProxy(w, r, "/agents", nil)
	case strings.HasPrefix(path, "agents/"):
		s.handleMonitoringAgent(w, r, strings.TrimPrefix(path, "agents/"))
	case path == "alerts" && r.Method == http.MethodGet:
		s.monitoringSearch(w, r, "wazuh-alerts-*", "")
	case path == "vulnerabilities" && r.Method == http.MethodGet:
		s.monitoringSearch(w, r, "wazuh-states-vulnerabilities-*", "")
	case path == "audit" && r.Method == http.MethodGet:
		s.handleMonitoringAudit(w, r)
	case path == "enrollments":
		s.handleMonitoringEnrollments(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) readMonitoringEnrollments() ([]monitoringEnrollment, error) {
	b, err := os.ReadFile(filepath.Join(s.monitoringDir(), "enrollments.json"))
	if errors.Is(err, os.ErrNotExist) {
		return []monitoringEnrollment{}, nil
	}
	if err != nil {
		return nil, err
	}
	var items []monitoringEnrollment
	if err := json.Unmarshal(b, &items); err != nil {
		return nil, err
	}
	return items, nil
}

func (s *Server) handleMonitoringEnrollments(w http.ResponseWriter, r *http.Request) {
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	items, err := s.readMonitoringEnrollments()
	if err != nil {
		writeJSONStatus(w, 500, map[string]string{"error": "Could not load enrollments"})
		return
	}
	if r.Method == http.MethodGet {
		writeJSONStatus(w, 200, items)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	limitJSONBody(w, r)
	var input monitoringEnrollment
	if json.NewDecoder(r.Body).Decode(&input) != nil || !monitoringEnrollmentName.MatchString(input.Name) || (input.OS != "Linux" && input.OS != "Windows" && input.OS != "macOS") {
		writeJSONStatus(w, 400, map[string]string{"error": "Enter a valid agent name and operating system"})
		return
	}
	for _, item := range items {
		if strings.EqualFold(item.Name, input.Name) {
			writeJSONStatus(w, 409, map[string]string{"error": "Server already added"})
			return
		}
	}
	if len(items) >= 100 {
		writeJSONStatus(w, 409, map[string]string{"error": "Enrollment list is full"})
		return
	}
	input.CreatedAt = time.Now().UTC()
	items = append(items, input)
	if err := os.MkdirAll(s.monitoringDir(), 0700); err != nil {
		writeJSONStatus(w, 500, map[string]string{"error": "Could not save enrollment"})
		return
	}
	data, _ := json.MarshalIndent(items, "", "  ")
	f, err := os.CreateTemp(s.monitoringDir(), ".enrollments-*")
	if err != nil {
		writeJSONStatus(w, 500, map[string]string{"error": "Could not save enrollment"})
		return
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		f.Close()
		writeJSONStatus(w, 500, map[string]string{"error": "Could not save enrollment"})
		return
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		writeJSONStatus(w, 500, map[string]string{"error": "Could not save enrollment"})
		return
	}
	if err := f.Sync(); err != nil {
		f.Close()
		writeJSONStatus(w, 500, map[string]string{"error": "Could not save enrollment"})
		return
	}
	if err := f.Close(); err != nil {
		writeJSONStatus(w, 500, map[string]string{"error": "Could not save enrollment"})
		return
	}
	if err := os.Rename(f.Name(), filepath.Join(s.monitoringDir(), "enrollments.json")); err != nil {
		writeJSONStatus(w, 500, map[string]string{"error": "Could not save enrollment"})
		return
	}
	writeJSONStatus(w, 201, input)
}

func (s *Server) handleMonitoringConnection(w http.ResponseWriter, r *http.Request) {
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	cfg, err := s.readMonitoringConfig()
	if err != nil {
		writeJSONStatus(w, 500, map[string]string{"error": "Could not read monitoring configuration"})
		return
	}
	if r.Method == http.MethodGet {
		writeJSONStatus(w, 200, map[string]any{"manager_url": cfg.ManagerURL, "indexer_url": cfg.IndexerURL, "manager_user": cfg.ManagerUser, "indexer_user": cfg.IndexerUser, "agent_host": cfg.AgentHost, "has_manager_password": cfg.ManagerPass != "", "has_indexer_password": cfg.IndexerPass != "", "has_ca": cfg.CAPEM != "", "allowed_commands": cfg.AllowedCommands})
		return
	}
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !authConfigured(s.cfg) {
		writeJSONStatus(w, 403, map[string]string{"error": "Configure dashboard authentication before managing Wazuh"})
		return
	}
	limitJSONBody(w, r)
	var input monitoringConfig
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeJSONStatus(w, 400, map[string]string{"error": "Invalid configuration"})
		return
	}
	if !validMonitoringURL(input.ManagerURL) || !validMonitoringURL(input.IndexerURL) || input.ManagerUser == "" || input.IndexerUser == "" || input.AgentHost == "" {
		writeJSONStatus(w, 400, map[string]string{"error": "HTTPS manager and indexer URLs, usernames, and agent host are required"})
		return
	}
	if strings.ContainsAny(input.AgentHost, "/:@?# ") {
		writeJSONStatus(w, 400, map[string]string{"error": "Agent host must be a hostname or IP"})
		return
	}
	if input.ManagerPass == "" {
		input.ManagerPass = cfg.ManagerPass
	}
	if input.IndexerPass == "" {
		input.IndexerPass = cfg.IndexerPass
	}
	if input.CAPEM == "" {
		input.CAPEM = cfg.CAPEM
	}
	if input.ManagerPass == "" || input.IndexerPass == "" {
		writeJSONStatus(w, 400, map[string]string{"error": "Both API passwords are required"})
		return
	}
	seen := map[string]bool{}
	for _, command := range input.AllowedCommands {
		if !monitoringCommand.MatchString(command) || seen[command] {
			writeJSONStatus(w, 400, map[string]string{"error": "Invalid or duplicate allowed command"})
			return
		}
		seen[command] = true
	}
	if _, err := monitoringHTTPClient(input); err != nil {
		writeJSONStatus(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if err := s.saveMonitoringConfig(input); err != nil {
		writeJSONStatus(w, 500, map[string]string{"error": "Could not save monitoring configuration"})
		return
	}
	writeJSONStatus(w, 200, map[string]string{"status": "saved"})
}

func (s *Server) loadMonitoring(w http.ResponseWriter) (monitoringConfig, *http.Client, bool) {
	cfg, err := s.readMonitoringConfig()
	if err != nil {
		writeJSONStatus(w, 500, map[string]string{"error": "Could not read monitoring configuration"})
		return cfg, nil, false
	}
	if cfg.ManagerURL == "" {
		writeJSONStatus(w, 503, map[string]string{"error": "Wazuh is not configured"})
		return cfg, nil, false
	}
	client, err := monitoringHTTPClient(cfg)
	if err != nil {
		writeJSONStatus(w, 503, map[string]string{"error": err.Error()})
		return cfg, nil, false
	}
	return cfg, client, true
}

func (s *Server) handleMonitoringHealth(w http.ResponseWriter, r *http.Request) {
	cfg, client, ok := s.loadMonitoring(w)
	if !ok {
		return
	}
	status := map[string]any{"manager": false, "indexer": false, "agent_host": cfg.AgentHost}
	if token, err := managerToken(r.Context(), client, cfg); err == nil {
		_, err = monitoringRequest(r.Context(), client, "GET", cfg.ManagerURL, "/manager/info", "", "", token, nil)
		status["manager"] = err == nil
	}
	_, err := monitoringRequest(r.Context(), client, "GET", cfg.IndexerURL, "/", cfg.IndexerUser, cfg.IndexerPass, "", nil)
	status["indexer"] = err == nil
	writeJSONStatus(w, 200, status)
}

func pagination(r *http.Request) (int, int, error) {
	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if r.URL.Query().Get("page") == "" {
		page = 1
		err = nil
	}
	if err != nil || page < 1 {
		return 0, 0, errors.New("invalid page")
	}
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if r.URL.Query().Get("limit") == "" {
		limit = 25
		err = nil
	}
	if err != nil || limit < 1 || limit > 100 || page > 10000 {
		return 0, 0, errors.New("invalid limit or page")
	}
	return page, limit, nil
}

func (s *Server) monitoringProxy(w http.ResponseWriter, r *http.Request, path string, extra url.Values) {
	page, limit, err := pagination(r)
	if err != nil {
		writeJSONStatus(w, 400, map[string]string{"error": err.Error()})
		return
	}
	cfg, client, ok := s.loadMonitoring(w)
	if !ok {
		return
	}
	q := url.Values{"offset": {strconv.Itoa((page - 1) * limit)}, "limit": {strconv.Itoa(limit)}}
	if search := strings.TrimSpace(r.URL.Query().Get("q")); search != "" {
		if len(search) > 120 {
			writeJSONStatus(w, 400, map[string]string{"error": "Search is too long"})
			return
		}
		q.Set("search", search)
	}
	for key, values := range extra {
		q[key] = values
	}
	token, err := managerToken(r.Context(), client, cfg)
	if err != nil {
		writeJSONStatus(w, 502, map[string]string{"error": err.Error()})
		return
	}
	raw, err := monitoringRequest(r.Context(), client, "GET", cfg.ManagerURL, path+"?"+q.Encode(), "", "", token, nil)
	if err != nil {
		writeJSONStatus(w, 502, map[string]string{"error": err.Error()})
		return
	}
	var envelope struct {
		Error int `json:"error"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.Error != 0 {
		writeJSONStatus(w, 502, map[string]string{"error": "Wazuh manager could not return this data"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

func (s *Server) handleMonitoringAgent(w http.ResponseWriter, r *http.Request, tail string) {
	parts := strings.Split(tail, "/")
	if len(parts) < 1 || !monitoringAgentID.MatchString(parts[0]) {
		writeJSONStatus(w, 400, map[string]string{"error": "Invalid agent ID"})
		return
	}
	id := parts[0]
	if len(parts) == 1 && r.Method == http.MethodGet {
		s.monitoringProxy(w, r, "/agents", url.Values{"agents_list": {id}})
		return
	}
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	switch parts[1] {
	case "fim":
		if r.Method == "GET" {
			s.monitoringProxy(w, r, "/syscheck/"+id, nil)
			return
		}
	case "sca":
		if r.Method == "GET" {
			s.monitoringProxy(w, r, "/sca/"+id, nil)
			return
		}
	case "alerts":
		if r.Method == "GET" {
			s.monitoringSearch(w, r, "wazuh-alerts-*", id)
			return
		}
	case "vulnerabilities":
		if r.Method == "GET" {
			s.monitoringSearch(w, r, "wazuh-states-vulnerabilities-*", id)
			return
		}
	case "active-response":
		if r.Method == "POST" {
			s.handleMonitoringResponse(w, r, id)
			return
		}
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func (s *Server) monitoringSearch(w http.ResponseWriter, r *http.Request, index, agentID string) {
	page, limit, err := pagination(r)
	if err != nil {
		writeJSONStatus(w, 400, map[string]string{"error": err.Error()})
		return
	}
	cfg, client, ok := s.loadMonitoring(w)
	if !ok {
		return
	}
	filters := []any{}
	if agentID != "" {
		filters = append(filters, map[string]any{"term": map[string]string{"agent.id": agentID}})
	}
	if q := strings.TrimSpace(r.URL.Query().Get("q")); q != "" {
		if len(q) > 120 {
			writeJSONStatus(w, 400, map[string]string{"error": "Search is too long"})
			return
		}
		filters = append(filters, map[string]any{"multi_match": map[string]any{"query": q, "fields": []string{"rule.description", "agent.name", "data.*", "vulnerability.id"}}})
	}
	query := map[string]any{"from": (page - 1) * limit, "size": limit, "sort": []any{map[string]any{"@timestamp": map[string]string{"order": "desc", "unmapped_type": "date"}}}, "query": map[string]any{"bool": map[string]any{"filter": filters}}}
	raw, err := monitoringRequest(r.Context(), client, "POST", cfg.IndexerURL, "/"+index+"/_search", cfg.IndexerUser, cfg.IndexerPass, "", query)
	if err != nil {
		writeJSONStatus(w, 502, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

func (s *Server) handleMonitoringResponse(w http.ResponseWriter, r *http.Request, agentID string) {
	if !authConfigured(s.cfg) {
		writeJSONStatus(w, 403, map[string]string{"error": "Dashboard authentication is required"})
		return
	}
	limitJSONBody(w, r)
	var req struct {
		Command      string `json:"command"`
		ConfirmAgent string `json:"confirm_agent"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.ConfirmAgent != agentID {
		writeJSONStatus(w, 400, map[string]string{"error": "Confirm the selected agent ID"})
		return
	}
	cfg, client, ok := s.loadMonitoring(w)
	if !ok {
		return
	}
	allowed := false
	for _, cmd := range cfg.AllowedCommands {
		if cmd == req.Command {
			allowed = true
			break
		}
	}
	if !allowed || !monitoringCommand.MatchString(req.Command) {
		writeJSONStatus(w, 403, map[string]string{"error": "Command is not allowlisted"})
		return
	}
	action := monitoringAction{Time: time.Now().UTC(), Actor: s.cfg.Username, AgentID: agentID, Command: req.Command, Status: "requested"}
	if auditErr := s.appendMonitoringAudit(action); auditErr != nil {
		writeJSONStatus(w, 500, map[string]string{"error": "Could not audit response request; no command was sent"})
		return
	}
	token, err := managerToken(r.Context(), client, cfg)
	if err != nil {
		action.Status = "failed"
		action.Result = err.Error()
		_ = s.appendMonitoringAudit(action)
		writeJSONStatus(w, 502, map[string]string{"error": err.Error()})
		return
	}
	// Wazuh's active-response API accepts only a single agent ID here. Never
	// forward arbitrary request fields or a group/all selector.
	raw, err := monitoringRequest(r.Context(), client, "PUT", cfg.ManagerURL, "/active-response?agents_list="+agentID, "", "", token, map[string]any{"command": req.Command, "custom": false})
	if err == nil {
		var result struct {
			Error int `json:"error"`
			Data  struct {
				AffectedItems []string          `json:"affected_items"`
				FailedItems   []json.RawMessage `json:"failed_items"`
			} `json:"data"`
		}
		if json.Unmarshal(raw, &result) != nil || result.Error != 0 || len(result.Data.FailedItems) != 0 || len(result.Data.AffectedItems) != 1 || result.Data.AffectedItems[0] != agentID {
			err = errors.New("Wazuh did not confirm response submission for the selected agent")
		}
	}
	if err != nil {
		action.Status = "failed"
		action.Result = err.Error()
	} else {
		action.Status = "submitted"
		action.Result = "Wazuh accepted the request; confirm execution in agent logs"
	}
	if auditErr := s.appendMonitoringAudit(action); auditErr != nil {
		writeJSONStatus(w, 500, map[string]string{"error": "Response was submitted but audit logging failed; inspect Wazuh before retrying"})
		return
	}
	if err != nil {
		writeJSONStatus(w, 502, map[string]string{"error": err.Error()})
		return
	}
	writeJSONStatus(w, 200, action)
}

func (s *Server) appendMonitoringAudit(action monitoringAction) error {
	monitoringAuditMu.Lock()
	defer monitoringAuditMu.Unlock()
	if err := os.MkdirAll(s.monitoringDir(), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(s.monitoringDir(), "active-response-audit.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(action); err != nil {
		return err
	}
	return f.Sync()
}

func (s *Server) handleMonitoringAudit(w http.ResponseWriter, r *http.Request) {
	page, limit, err := pagination(r)
	if err != nil {
		writeJSONStatus(w, 400, map[string]string{"error": err.Error()})
		return
	}
	f, err := os.Open(filepath.Join(s.monitoringDir(), "active-response-audit.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		writeJSONStatus(w, 200, []monitoringAction{})
		return
	}
	if err != nil {
		writeJSONStatus(w, 500, map[string]string{"error": "Could not read audit history"})
		return
	}
	defer f.Close()
	// Keep the most recent 1,000 entries, with a bounded line size. Wazuh
	// remains the authoritative execution/event store.
	all := make([]monitoringAction, 0, 1000)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 64<<10)
	for scanner.Scan() {
		var action monitoringAction
		if json.Unmarshal(scanner.Bytes(), &action) == nil {
			if len(all) == 1000 {
				copy(all, all[1:])
				all = all[:999]
			}
			all = append(all, action)
		}
	}
	if err := scanner.Err(); err != nil {
		writeJSONStatus(w, 500, map[string]string{"error": "Could not read audit history"})
		return
	}
	start := (page - 1) * limit
	if start >= len(all) {
		writeJSONStatus(w, 200, []monitoringAction{})
		return
	}
	end := start + limit
	if end > len(all) {
		end = len(all)
	}
	actions := make([]monitoringAction, 0, end-start)
	for i := len(all) - 1 - start; i >= len(all)-end; i-- {
		actions = append(actions, all[i])
	}
	if actions == nil {
		actions = []monitoringAction{}
	}
	writeJSONStatus(w, 200, actions)
}
