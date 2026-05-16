package web

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/agent"
	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/llm"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

func newTestServer(t *testing.T, cfg *config.Config) *Server {
	t.Helper()
	if cfg == nil {
		cfg = &config.Config{RateLimitRequests: 60, RateLimitWindow: 60}
	}
	if cfg.RateLimitRequests == 0 {
		cfg.RateLimitRequests = 60
	}
	if cfg.RateLimitWindow == 0 {
		cfg.RateLimitWindow = 60
	}
	s := NewServer(cfg, 0)
	s.dataDir = t.TempDir()
	t.Cleanup(func() {
		if s.rateLimiter != nil {
			defer func() { _ = recover() }()
			s.rateLimiter.Stop()
		}
	})
	return s
}

func resetAuthSessionsForTest() {
	authSessionsMu.Lock()
	defer authSessionsMu.Unlock()
	authSessions = make(map[string]time.Time)
}

func TestGenerateReportResolvesUploadedLogoPath(t *testing.T) {
	s := newTestServer(t, nil)
	logosDir := filepath.Join(s.dataDir, "logos")
	if err := os.MkdirAll(logosDir, 0755); err != nil {
		t.Fatal(err)
	}
	logoPath := filepath.Join(logosDir, "acme.png")
	writeTestPNG(t, logoPath)

	scanDir := filepath.Join(s.dataDir, "acme.example", "2026-05-14", "scan-logo")
	if err := os.MkdirAll(scanDir, 0755); err != nil {
		t.Fatal(err)
	}
	rec := &ScanRecord{
		ID:          "scan-logo",
		Name:        "Acme Security Review",
		Target:      "https://acme.example",
		StartedAt:   time.Now().Add(-15 * time.Minute).Format(time.RFC3339),
		FinishedAt:  time.Now().Format(time.RFC3339),
		Status:      "finished",
		CompanyName: "Acme",
		LogoPath:    "/uploads/logos/acme.png",
		Vulns: []VulnSummary{{
			Title:       "SQL Injection in Search",
			Severity:    "critical",
			Endpoint:    "/search",
			CVSS:        9.1,
			Description: "Search input is injectable.",
			PoCScript:   strings.Repeat("curl -X POST https://acme.example/search -d 'q=test'\n", 80),
			Remediation: "Use parameterized queries.",
		}},
		Events: []WSEvent{{Type: "message", Content: "Tech stack detected: nginx"}},
	}

	resolved, ok := s.resolveReportLogoPath(rec.LogoPath)
	if !ok || resolved != logoPath {
		t.Fatalf("resolveReportLogoPath() = %q, %v; want %q, true", resolved, ok, logoPath)
	}
	reportPath, err := s.generateReportAt(rec, scanDir)
	if err != nil {
		t.Fatalf("generateReportAt() error = %v", err)
	}
	info, err := os.Stat(reportPath)
	if err != nil {
		t.Fatalf("generated report missing: %v", err)
	}
	if info.Size() < 1000 {
		t.Fatalf("generated report is unexpectedly small: %d bytes", info.Size())
	}
}

func writeTestPNG(t *testing.T, path string) {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			img.Set(x, y, color.RGBA{R: 16, G: 185, B: 129, A: 255})
		}
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := png.Encode(file, img); err != nil {
		t.Fatal(err)
	}
}

func TestBroadcastToInstanceReachesDashboardAndSubscribedClients(t *testing.T) {
	s := newTestServer(t, nil)
	inst := &ScanInstance{ID: "inst-1", Targets: "https://example.com", Status: "running"}
	s.instancesMu.Lock()
	s.instances[inst.ID] = inst
	s.instancesMu.Unlock()

	dashboard := &wsClient{send: make(chan []byte, 1)}
	subscribed := &wsClient{send: make(chan []byte, 1), instanceID: inst.ID}
	other := &wsClient{send: make(chan []byte, 1), instanceID: "other"}
	s.mu.Lock()
	s.clients[dashboard] = true
	s.clients[subscribed] = true
	s.clients[other] = true
	s.mu.Unlock()

	s.broadcastToInstance(inst.ID, WSEvent{Type: "message", Content: "hello"})

	for name, ch := range map[string]<-chan []byte{
		"dashboard":  dashboard.send,
		"subscribed": subscribed.send,
	} {
		select {
		case raw := <-ch:
			var evt WSEvent
			if err := json.Unmarshal(raw, &evt); err != nil {
				t.Fatalf("%s received invalid event: %v", name, err)
			}
			if evt.InstanceID != inst.ID {
				t.Fatalf("%s event instance_id = %q, want %q", name, evt.InstanceID, inst.ID)
			}
			if evt.Content != "hello" {
				t.Fatalf("%s event content = %q, want hello", name, evt.Content)
			}
		default:
			t.Fatalf("%s client did not receive instance event", name)
		}
	}
	select {
	case <-other.send:
		t.Fatal("unrelated instance client received event")
	default:
	}

	inst.mu.RLock()
	defer inst.mu.RUnlock()
	if len(inst.events) != 1 {
		t.Fatalf("buffered events = %d, want 1", len(inst.events))
	}
}

func TestRateLimitMiddleware_EnforcesLimitAndBypassesStaticAndWS(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute)
	defer rl.Stop()

	calls := 0
	handler := rateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/chat", nil)
	req.RemoteAddr = "127.0.0.1:1111"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("first request status = %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/chat", nil)
	req.RemoteAddr = "127.0.0.1:2222"
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429", rr.Code)
	}

	staticBypassPaths := []string{
		"/ws",
		"/static/app.js",
		"/assets/logo.png",
		"/app.js",
		"/style.css",
		"/logo.png",
		"/chunks/app-123.js",
		"/api/auth/status",
		"/api/status",
		"/api/version",
		"/api/scans",
		"/api/scans/scan-1",
		"/api/instances",
		"/api/instances/scan-1",
		"/api/instances/scan-1/events",
		"/api/queue/status",
	}
	for _, path := range staticBypassPaths {
		req = httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "127.0.0.1:3333"
		rr = httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s bypass status = %d, want 200", path, rr.Code)
		}
	}
	if want := 1 + len(staticBypassPaths); calls != want {
		t.Fatalf("inner handler calls = %d, want %d", calls, want)
	}
}

func TestAuthMiddleware_AllowsReactShellAndAssetsBeforeSession(t *testing.T) {
	resetAuthSessionsForTest()
	mw := authMiddleware(&config.Config{Username: "admin", Password: "secret"})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	publicPaths := []string{
		"/",
		"/login",
		"/scans",
		"/app.js",
		"/style.css",
		"/logo.png",
		"/chunks/app-123.js",
		"/api/auth/status",
	}
	for _, path := range publicPaths {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("%s status = %d, want %d", path, rr.Code, http.StatusNoContent)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("protected API status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestIsStaticWebAssetPath_DoesNotClassifyDottedScanRoutes(t *testing.T) {
	staticPaths := []string{"/app.js", "/style.css", "/chunks/app-123.js", "/assets/logo.png", "/static/app.js"}
	for _, path := range staticPaths {
		if !isStaticWebAssetPath(path) {
			t.Fatalf("%s was not classified as a static asset", path)
		}
	}

	appRoutes := []string{"/scans/pentest-ground.com_4280_9286f18f", "/api/scans/pentest-ground.com_4280_9286f18f", "/ws"}
	for _, path := range appRoutes {
		if isStaticWebAssetPath(path) {
			t.Fatalf("%s was incorrectly classified as a static asset", path)
		}
	}
}

func TestIsDashboardReadPath_OnlyBypassesSafePollingReads(t *testing.T) {
	readPaths := []string{
		"/api/auth/status",
		"/api/status",
		"/api/version",
		"/api/scans",
		"/api/scans/scan-1",
		"/api/instances",
		"/api/instances/scan-1",
		"/api/instances/scan-1/events",
		"/api/queue/status",
	}
	for _, path := range readPaths {
		if !isDashboardReadPath(http.MethodGet, path) {
			t.Fatalf("%s was not classified as a dashboard read", path)
		}
	}

	writePaths := []string{
		"/api/scan",
		"/api/stop",
		"/api/chat",
		"/api/auth/login",
		"/api/instances/scan-1/stop",
	}
	for _, path := range writePaths {
		if isDashboardReadPath(http.MethodPost, path) {
			t.Fatalf("POST %s was incorrectly classified as a dashboard read", path)
		}
	}
}

func TestCanStartInstanceStatus(t *testing.T) {
	for _, status := range []string{"saved", "stopped", "failed", "finished", " Finished "} {
		if !canStartInstanceStatus(status) {
			t.Fatalf("%q should be startable", status)
		}
	}
	for _, status := range []string{"running", "pending", "paused", "", "unknown"} {
		if canStartInstanceStatus(status) {
			t.Fatalf("%q should not be startable", status)
		}
	}
}

func TestAuthHandlers_LoginStatusLogout(t *testing.T) {
	resetAuthSessionsForTest()
	s := newTestServer(t, &config.Config{
		Username:          "admin",
		Password:          "secret",
		RateLimitRequests: 60,
		RateLimitWindow:   60,
	})

	rr := httptest.NewRecorder()
	s.handleAuthStatus(rr, httptest.NewRequest(http.MethodGet, "/api/auth/status", nil))
	if !strings.Contains(rr.Body.String(), `"auth_enabled":true`) || !strings.Contains(rr.Body.String(), `"authenticated":false`) {
		t.Fatalf("unexpected unauthenticated status body: %s", rr.Body.String())
	}

	rr = httptest.NewRecorder()
	loginBody := strings.NewReader(`{"username":"admin","password":"secret"}`)
	s.handleLogin(rr, httptest.NewRequest(http.MethodPost, "/api/auth/login", loginBody))
	if rr.Code != http.StatusOK {
		t.Fatalf("login status = %d body=%q", rr.Code, rr.Body.String())
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("login cookies = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != sessionCookieName || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge <= 0 {
		t.Fatalf("unexpected session cookie: %#v", cookie)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
	req.AddCookie(cookie)
	rr = httptest.NewRecorder()
	s.handleAuthStatus(rr, req)
	if !strings.Contains(rr.Body.String(), `"authenticated":true`) {
		t.Fatalf("authenticated status body: %s", rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.AddCookie(cookie)
	rr = httptest.NewRecorder()
	s.handleLogout(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("logout status = %d", rr.Code)
	}
	if isValidSession(cookie.Value) {
		t.Fatal("session remained valid after logout")
	}
}

func TestScanRequest_InternalFieldsIgnoredFromJSON(t *testing.T) {
	var req ScanRequest
	if err := json.Unmarshal([]byte(`{
		"targets":["https://example.test"],
		"instruction":"run",
		"instance_id":"spoofed",
		"is_resume":true
	}`), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.InstanceID != "" || req.IsResume {
		t.Fatalf("internal fields were set from JSON: %#v", req)
	}
}

func TestPhaseRestriction_ReconReportOnlyIsStrict(t *testing.T) {
	instruction := buildPhaseFilterInstruction([]int{1, 22})
	for _, want := range []string{
		"RECONNAISSANCE-ONLY SCOPE",
		"Do NOT run vulnerability scanners",
		"DNS records",
		"Open ports",
		"do not call report_vulnerability",
	} {
		if !strings.Contains(instruction, want) {
			t.Fatalf("phase restriction missing %q:\n%s", want, instruction)
		}
	}
	if !isReconReportOnlyPhaseSelection([]int{1, 22}) {
		t.Fatal("recon/report-only phase selection was not detected")
	}
	if isReconReportOnlyPhaseSelection([]int{1, 6, 22}) {
		t.Fatal("vulnerability phase selection was incorrectly treated as recon-only")
	}
}

func TestInferCurrentPhase_DoesNotTreatSessionFinishedAsFinalReport(t *testing.T) {
	allowed := []int{1, 8, 22}

	if got := inferCurrentPhase(WSEvent{Type: "finished", Content: "Agent session complete"}, allowed); got != 0 {
		t.Fatalf("session finished inferred phase %d, want 0", got)
	}
	if got := inferCurrentPhase(WSEvent{Type: "tool_call", ToolName: "finish"}, allowed); got != 0 {
		t.Fatalf("finish tool inferred phase %d, want 0", got)
	}
	if got := inferCurrentPhase(WSEvent{Type: "tool_call", ToolName: "report_vulnerability"}, allowed); got != 0 {
		t.Fatalf("report_vulnerability inferred phase %d, want 0", got)
	}
	if got := inferCurrentPhase(WSEvent{Type: "queue_finished", Content: "Scan queue ended"}, allowed); got != 22 {
		t.Fatalf("queue_finished inferred phase %d, want 22", got)
	}
	if got := inferCurrentPhase(WSEvent{
		Type:     "tool_call",
		ToolName: "terminal_execute",
		ToolArgs: map[string]string{
			"cmd": "test IDOR authorization bypass on account endpoint",
		},
	}, allowed); got != 8 {
		t.Fatalf("IDOR tool call inferred phase %d, want 8", got)
	}
}

func TestHandleGetScan_ReturnsLiveInstanceMetadata(t *testing.T) {
	s := newTestServer(t, nil)
	inst := &ScanInstance{
		ID:             "inst-meta",
		Name:           "Recon pass",
		Targets:        "https://meta.test",
		Status:         "running",
		StartedAt:      "2026-05-10T10:00:00Z",
		ScanMode:       "single",
		Instruction:    "recon only",
		SeverityFilter: []string{"high"},
		Phases:         []int{1, 22},
		CurrentPhase:   1,
		CompanyName:    "ACME",
		events: []WSEvent{{
			Type:         "target_started",
			Content:      "Scanning target",
			CurrentPhase: 1,
		}},
	}
	s.instancesMu.Lock()
	s.instances[inst.ID] = inst
	s.instancesMu.Unlock()

	rr := httptest.NewRecorder()
	s.handleGetScan(rr, httptest.NewRequest(http.MethodGet, "/api/scans/inst-meta", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("get scan code = %d body=%s", rr.Code, rr.Body.String())
	}

	var rec ScanRecord
	if err := json.Unmarshal(rr.Body.Bytes(), &rec); err != nil {
		t.Fatalf("decode scan record: %v", err)
	}
	if rec.Name != "Recon pass" || rec.Instruction != "recon only" || rec.CurrentPhase != 1 || len(rec.Phases) != 2 {
		t.Fatalf("live instance metadata not preserved: %#v", rec)
	}
}

func TestHandleChat_RoutesRunningInstanceByInstanceID(t *testing.T) {
	s := newTestServer(t, nil)
	events := make(chan agent.Event, 4)
	sctx := scanctx.New("chat-running", t.TempDir())
	agnt := agent.NewAgent(s.cfg, "test-agent", events, sctx)
	inst := &ScanInstance{
		ID:      "inst-running",
		Targets: "https://running.test",
		Status:  "running",
		agent:   agnt,
	}
	s.instancesMu.Lock()
	s.instances[inst.ID] = inst
	s.instancesMu.Unlock()
	t.Cleanup(func() {
		agnt.Stop()
		sctx.Close()
	})

	rr := httptest.NewRecorder()
	body := strings.NewReader(`{"instance_id":"inst-running","message":"continue checking auth"}`)
	s.handleChat(rr, httptest.NewRequest(http.MethodPost, "/api/chat", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("chat status = %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "next iteration") {
		t.Fatalf("unexpected running chat response: %s", rr.Body.String())
	}
}

func TestHandleChat_AllowsFinishedInstancePostScanChat(t *testing.T) {
	s := newTestServer(t, &config.Config{RateLimitRequests: 60, RateLimitWindow: 60})
	var gotMessages []string
	s.postScanChatFn = func(_ *config.Config, messages []llm.Message) (string, error) {
		for _, msg := range messages {
			gotMessages = append(gotMessages, msg.Content)
		}
		return "The scan found one high severity issue.", nil
	}
	inst := &ScanInstance{
		ID:          "inst-finished",
		Targets:     "https://done.test",
		Status:      "finished",
		StartedAt:   "2026-05-10T10:00:00Z",
		FinishedAt:  "2026-05-10T10:30:00Z",
		ScanMode:    "single",
		Iterations:  2,
		ToolCalls:   3,
		VulnCount:   1,
		TotalTokens: 100,
		Vulns: []VulnSummary{{
			ID:          "v1",
			Title:       "SQL injection",
			Severity:    "high",
			Endpoint:    "/login",
			Description: "Authentication endpoint reflected SQL errors.",
		}},
		events: []WSEvent{
			{Type: "target_started", Target: "https://done.test", Content: "Scanning https://done.test"},
			{Type: "finished", Content: "Completed with one finding"},
		},
	}
	s.instancesMu.Lock()
	s.instances[inst.ID] = inst
	s.instancesMu.Unlock()

	rr := httptest.NewRecorder()
	body := strings.NewReader(`{"instance_id":"inst-finished","message":"what did we find?"}`)
	s.handleChat(rr, httptest.NewRequest(http.MethodPost, "/api/chat", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("chat status = %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "one high severity issue") {
		t.Fatalf("unexpected post-scan chat response: %s", rr.Body.String())
	}
	joinedMessages := strings.Join(gotMessages, "\n")
	if !strings.Contains(joinedMessages, "post-scan chat mode") ||
		!strings.Contains(joinedMessages, "SQL injection") ||
		!strings.Contains(joinedMessages, "what did we find?") {
		t.Fatalf("LLM prompt missing completed scan context or user message: %s", joinedMessages)
	}
}

func TestHandleChat_WithoutInstanceIDUsesLatestCompletedInstance(t *testing.T) {
	s := newTestServer(t, &config.Config{RateLimitRequests: 60, RateLimitWindow: 60})
	s.postScanChatFn = func(_ *config.Config, messages []llm.Message) (string, error) {
		if got := messages[len(messages)-1].Content; got != "test for any api endpoint" {
			t.Fatalf("chat message = %q", got)
		}
		return "The scan is complete; here are the API-related findings from the completed scan.", nil
	}
	inst := &ScanInstance{
		ID:         "inst-latest-finished",
		Targets:    "https://done.test",
		Status:     "finished",
		StartedAt:  "2026-05-10T10:00:00Z",
		FinishedAt: "2026-05-10T10:30:00Z",
		ScanMode:   "single",
		events: []WSEvent{
			{Type: "queue_finished", Content: "Scan queue ended"},
		},
	}
	s.instancesMu.Lock()
	s.instances[inst.ID] = inst
	s.instancesMu.Unlock()

	rr := httptest.NewRecorder()
	body := strings.NewReader(`{"message":"test for any api endpoint"}`)
	s.handleChat(rr, httptest.NewRequest(http.MethodPost, "/api/chat", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("chat status = %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "API-related findings") {
		t.Fatalf("unexpected no-instance post-scan chat response: %s", rr.Body.String())
	}
}

func TestHandleChat_WithoutInstanceIDIgnoresStaleFinishedAgent(t *testing.T) {
	s := newTestServer(t, &config.Config{RateLimitRequests: 60, RateLimitWindow: 60})
	events := make(chan agent.Event, 4)
	sctx := scanctx.New("stale-agent", t.TempDir())
	agnt := agent.NewAgent(s.cfg, "stale-agent", events, sctx)
	t.Cleanup(func() {
		agnt.Stop()
		sctx.Close()
	})

	s.mu.Lock()
	s.currentScanID = "stale-scan"
	s.currentAgents["stale-scan"] = agnt
	s.mu.Unlock()
	s.running.Store(false)

	s.postScanChatFn = func(_ *config.Config, _ []llm.Message) (string, error) {
		return "Post-scan context answer.", nil
	}
	inst := &ScanInstance{
		ID:         "inst-finished-after-stale-agent",
		Targets:    "https://done.test",
		Status:     "finished",
		StartedAt:  "2026-05-10T10:00:00Z",
		FinishedAt: "2026-05-10T10:30:00Z",
	}
	s.instancesMu.Lock()
	s.instances[inst.ID] = inst
	s.instancesMu.Unlock()

	rr := httptest.NewRecorder()
	body := strings.NewReader(`{"message":"what did we find?"}`)
	s.handleChat(rr, httptest.NewRequest(http.MethodPost, "/api/chat", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("chat status = %d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "next iteration") {
		t.Fatalf("stale agent handled post-scan chat: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "Post-scan context answer") {
		t.Fatalf("unexpected post-scan response: %s", rr.Body.String())
	}
}

func TestUploadHandlers_ParseTargetsAndInstructions(t *testing.T) {
	s := newTestServer(t, nil)

	body, contentType := multipartBody(t, "file", "targets.txt", "https://a.test\n# ignored\n\nhttps://b.test\n")
	req := httptest.NewRequest(http.MethodPost, "/api/upload-targets", body)
	req.Header.Set("Content-Type", contentType)
	rr := httptest.NewRecorder()
	s.handleUploadTargets(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("upload targets status = %d body=%q", rr.Code, rr.Body.String())
	}
	var targetsResp struct {
		Targets []string `json:"targets"`
		Count   int      `json:"count"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &targetsResp); err != nil {
		t.Fatalf("decode targets response: %v", err)
	}
	if targetsResp.Count != 2 || strings.Join(targetsResp.Targets, ",") != "https://a.test,https://b.test" {
		t.Fatalf("unexpected targets response: %#v", targetsResp)
	}

	body, contentType = multipartBody(t, "file", "instructions.txt", "focus on auth flows")
	req = httptest.NewRequest(http.MethodPost, "/api/upload-instructions", body)
	req.Header.Set("Content-Type", contentType)
	rr = httptest.NewRecorder()
	s.handleUploadInstructions(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("upload instructions status = %d body=%q", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "focus on auth flows") {
		t.Fatalf("unexpected instructions response: %s", rr.Body.String())
	}
}

func multipartBody(t *testing.T, field, name, content string) (*bytes.Buffer, string) {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	f, err := w.CreateFormFile(field, name)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := f.Write([]byte(content)); err != nil {
		t.Fatalf("write multipart: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close multipart: %v", err)
	}
	return &body, w.FormDataContentType()
}

func TestQueueStateHandlers_StatusAndClear(t *testing.T) {
	s := newTestServer(t, nil)
	s.saveQueueState(1, ScanRequest{Targets: []string{"https://a.test", "https://b.test"}, Instruction: "notes", ScanMode: "dast"})

	rr := httptest.NewRecorder()
	s.handleQueueStatus(rr, httptest.NewRequest(http.MethodGet, "/api/queue/status", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("queue status code = %d", rr.Code)
	}
	var status map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode queue status: %v", err)
	}
	if status["available"] != true || status["remaining"].(float64) != 1 || status["scan_mode"] != "dast" {
		t.Fatalf("unexpected queue status: %#v", status)
	}

	rr = httptest.NewRecorder()
	s.handleQueueClear(rr, httptest.NewRequest(http.MethodPost, "/api/queue/clear", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("queue clear code = %d", rr.Code)
	}
	if state := s.loadQueueState(); state != nil {
		t.Fatalf("queue state still exists after clear: %#v", state)
	}
}

func TestQueueStateHandlers_ClearInvalidAndCompletedState(t *testing.T) {
	cases := []struct {
		name  string
		write func(*testing.T, *Server)
	}{
		{
			name: "corrupt JSON",
			write: func(t *testing.T, s *Server) {
				t.Helper()
				if err := os.WriteFile(s.queueStatePath(), []byte("{not-json"), 0o644); err != nil {
					t.Fatalf("write corrupt queue: %v", err)
				}
			},
		},
		{
			name: "negative index",
			write: func(t *testing.T, s *Server) {
				t.Helper()
				s.saveQueueState(-1, ScanRequest{Targets: []string{"https://a.test"}, ScanMode: "single"})
			},
		},
		{
			name: "completed index",
			write: func(t *testing.T, s *Server) {
				t.Helper()
				s.saveQueueState(1, ScanRequest{Targets: []string{"https://a.test"}, ScanMode: "single"})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t, nil)
			tc.write(t, s)

			rr := httptest.NewRecorder()
			s.handleQueueStatus(rr, httptest.NewRequest(http.MethodGet, "/api/queue/status", nil))
			if rr.Code != http.StatusOK {
				t.Fatalf("queue status code = %d", rr.Code)
			}
			var status map[string]any
			if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil {
				t.Fatalf("decode queue status: %v", err)
			}
			if status["available"] != false {
				t.Fatalf("queue should be unavailable for invalid state: %#v", status)
			}
			if state := s.loadQueueState(); state != nil {
				t.Fatalf("invalid queue state was not cleared: %#v", state)
			}

			rr = httptest.NewRecorder()
			s.handleQueueResume(rr, httptest.NewRequest(http.MethodPost, "/api/queue/resume", nil))
			if !strings.Contains(rr.Body.String(), "No interrupted queue found") {
				t.Fatalf("unexpected resume response: %s", rr.Body.String())
			}
		})
	}
}

func TestQueueState_PreservesAllConfig(t *testing.T) {
	s := newTestServer(t, nil)
	req := ScanRequest{
		Targets:        []string{"https://a.test", "https://b.test"},
		Instruction:    "deep scan with custom rules",
		ScanMode:       "wildcard",
		Name:           "My Pentest",
		SeverityFilter: []string{"critical", "high"},
		Phases:         []int{1, 6, 8, 22},
		CompanyName:    "ACME Corp",
		LogoPath:       "/uploads/logos/acme.png",
		DiscordWebhook: "https://discord.example/hook/abc123",
	}
	s.saveQueueState(0, req)

	state := s.loadQueueState()
	if state == nil {
		t.Fatal("queue state not loaded")
	}
	if state.Name != "My Pentest" {
		t.Errorf("Name = %q, want %q", state.Name, "My Pentest")
	}
	if state.Instruction != "deep scan with custom rules" {
		t.Errorf("Instruction = %q", state.Instruction)
	}
	if state.ScanMode != "wildcard" {
		t.Errorf("ScanMode = %q, want wildcard", state.ScanMode)
	}
	if len(state.SeverityFilter) != 2 || state.SeverityFilter[0] != "critical" {
		t.Errorf("SeverityFilter = %v, want [critical high]", state.SeverityFilter)
	}
	if len(state.Phases) != 4 || state.Phases[0] != 1 || state.Phases[3] != 22 {
		t.Errorf("Phases = %v, want [1 6 8 22]", state.Phases)
	}
	if state.CompanyName != "ACME Corp" {
		t.Errorf("CompanyName = %q, want %q", state.CompanyName, "ACME Corp")
	}
	if state.LogoPath != "/uploads/logos/acme.png" {
		t.Errorf("LogoPath = %q", state.LogoPath)
	}
	if state.DiscordWebhook != "https://discord.example/hook/abc123" {
		t.Errorf("DiscordWebhook = %q", state.DiscordWebhook)
	}
	if len(state.Targets) != 2 || state.Targets[0] != "https://a.test" {
		t.Errorf("Targets = %v", state.Targets)
	}
	if state.CurrentIdx != 0 {
		t.Errorf("CurrentIdx = %d, want 0", state.CurrentIdx)
	}
	if !state.Active {
		t.Error("Active should be true")
	}
}

func TestQueueState_OldFileWithoutNewFields(t *testing.T) {
	// Simulate an old queue_state.json that only has the original fields.
	// New fields should deserialize as zero values.
	s := newTestServer(t, nil)
	oldJSON := `{
		"targets": ["https://old.test"],
		"current_idx": 0,
		"instruction": "old instruction",
		"scan_mode": "single",
		"started_at": "2026-01-01T00:00:00Z",
		"active": true
	}`
	if err := os.WriteFile(s.queueStatePath(), []byte(oldJSON), 0o644); err != nil {
		t.Fatalf("write old queue state: %v", err)
	}

	state := s.loadQueueState()
	if state == nil {
		t.Fatal("old queue state not loaded")
	}
	if len(state.Targets) != 1 || state.Targets[0] != "https://old.test" {
		t.Errorf("Targets = %v", state.Targets)
	}
	if state.Instruction != "old instruction" {
		t.Errorf("Instruction = %q", state.Instruction)
	}
	// New fields should be zero values
	if state.Name != "" {
		t.Errorf("Name should be empty for old file, got %q", state.Name)
	}
	if len(state.SeverityFilter) != 0 {
		t.Errorf("SeverityFilter should be empty for old file, got %v", state.SeverityFilter)
	}
	if len(state.Phases) != 0 {
		t.Errorf("Phases should be empty for old file, got %v", state.Phases)
	}
	if state.CompanyName != "" {
		t.Errorf("CompanyName should be empty for old file, got %q", state.CompanyName)
	}
}

func TestQueueStatus_ReturnsNewFields(t *testing.T) {
	s := newTestServer(t, nil)
	s.saveQueueState(0, ScanRequest{
		Targets:        []string{"https://a.test"},
		ScanMode:       "dast",
		Name:           "Status Test",
		SeverityFilter: []string{"high"},
		Phases:         []int{1, 22},
		CompanyName:    "TestCo",
		LogoPath:       "/logos/test.png",
	})

	rr := httptest.NewRecorder()
	s.handleQueueStatus(rr, httptest.NewRequest(http.MethodGet, "/api/queue/status", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d", rr.Code)
	}
	var status map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if status["name"] != "Status Test" {
		t.Errorf("name = %v", status["name"])
	}
	if status["company_name"] != "TestCo" {
		t.Errorf("company_name = %v", status["company_name"])
	}
	if status["logo_path"] != "/logos/test.png" {
		t.Errorf("logo_path = %v", status["logo_path"])
	}
	// DiscordWebhook should NOT be exposed via the API
	if _, ok := status["discord_webhook"]; ok {
		t.Error("discord_webhook should not be exposed in queue status API")
	}
}

func TestScanPersistence_ListLatestDeleteAndRebuild(t *testing.T) {
	s := newTestServer(t, nil)
	writeScanRecord(t, s.dataDir, "target-a/2026-05-01/scan-a", ScanRecord{
		ID:        "scan-a",
		Target:    "https://a.test",
		StartedAt: "2026-05-01T10:00:00Z",
		Status:    "finished",
		Vulns:     []VulnSummary{{ID: "v1", Severity: "high"}},
	})
	writeScanRecord(t, s.dataDir, "target-b/2026-05-02/scan-b", ScanRecord{
		ID:               "scan-b",
		Target:           "https://b.test",
		StartedAt:        "2026-05-02T10:00:00Z",
		Status:           "running",
		ScanMode:         "wildcard",
		SubScanTotal:     2,
		SubScanRemaining: 2,
		SubScans: []SubScanSummary{
			{Target: "https://sub.b.test", Status: "pending"},
			{Target: "https://later.b.test", Status: "pending"},
		},
	})
	writeScanRecord(t, s.dataDir, "target-b/2026-05-02/subdomain", ScanRecord{
		ID:           "subdomain",
		Target:       "https://sub.b.test",
		ParentTarget: "https://b.test",
		StartedAt:    "2026-05-02T11:00:00Z",
		Status:       "running",
		Vulns:        []VulnSummary{{ID: "v2", Severity: "medium"}},
	})

	rr := httptest.NewRecorder()
	s.handleListScans(rr, httptest.NewRequest(http.MethodGet, "/api/scans", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"id":"scan-b"`) {
		t.Fatalf("list scans response: code=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), `"id":"subdomain"`) {
		t.Fatalf("subdomain scan leaked into top-level list: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"sub_scan_total":2`) ||
		!strings.Contains(rr.Body.String(), `"sub_scan_remaining":1`) {
		t.Fatalf("parent scan missing subdomain count: %s", rr.Body.String())
	}

	rr = httptest.NewRecorder()
	s.handleGetScan(rr, httptest.NewRequest(http.MethodGet, "/api/scans/latest", nil))
	var latest ScanRecord
	if err := json.Unmarshal(rr.Body.Bytes(), &latest); err != nil {
		t.Fatalf("decode latest scan: %v body=%s", err, rr.Body.String())
	}
	if latest.ID != "scan-b" {
		t.Fatalf("latest scan should return newest top-level parent: %#v", latest)
	}

	rr = httptest.NewRecorder()
	s.handleGetScan(rr, httptest.NewRequest(http.MethodGet, "/api/scans/scan-b", nil))
	if !strings.Contains(rr.Body.String(), `"sub_scans"`) ||
		!strings.Contains(rr.Body.String(), `"target":"https://sub.b.test"`) ||
		!strings.Contains(rr.Body.String(), `"target":"https://later.b.test"`) ||
		!strings.Contains(rr.Body.String(), `"id":"v2"`) {
		t.Fatalf("parent scan did not include child subdomain detail: %s", rr.Body.String())
	}

	s.rebuildInstancesFromDisk()
	if _, ok := s.instances["subdomain"]; ok {
		t.Fatal("subdomain scan should not be rebuilt as a top-level instance")
	}
	inst := s.instances["scan-b"]
	if inst == nil || inst.Status != "stopped" || inst.StopReason != "server_restart" {
		t.Fatalf("running scan was not marked stopped on rebuild: %#v", inst)
	}
	_, rebuilt := s.findScanByID("scan-b")
	if rebuilt == nil || rebuilt.Status != "stopped" || rebuilt.StopReason != "server_restart" || rebuilt.FinishedAt == "" {
		t.Fatalf("rebuilt scan was not persisted as stopped: %#v", rebuilt)
	}
	_, rebuiltSub := s.findScanByID("subdomain")
	if rebuiltSub == nil || rebuiltSub.Status != "stopped" || rebuiltSub.StopReason != "server_restart" {
		t.Fatalf("subdomain running scan was not persisted as stopped: %#v", rebuiltSub)
	}

	rr = httptest.NewRecorder()
	s.handleListScans(rr, httptest.NewRequest(http.MethodGet, "/api/scans", nil))
	var listed []struct {
		ID         string `json:"id"`
		Status     string `json:"status"`
		FinishedAt string `json:"finished_at"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode list scans after rebuild: %v body=%s", err, rr.Body.String())
	}
	for _, got := range listed {
		if got.ID == "subdomain" {
			t.Fatalf("subdomain scan leaked into rebuilt list: %#v", got)
		}
		if got.ID == "scan-b" && got.Status != "stopped" {
			t.Fatalf("list scans still returned stale status for %s: %#v", got.ID, got)
		}
	}

	rr = httptest.NewRecorder()
	s.handleGetScan(rr, httptest.NewRequest(http.MethodDelete, "/api/scans/scan-a", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("delete scan code = %d body=%s", rr.Code, rr.Body.String())
	}
	if _, rec := s.findScanByID("scan-a"); rec != nil {
		t.Fatal("scan-a still found after delete")
	}
}

func TestFindScanByID_ResolvesParentInstanceAlias(t *testing.T) {
	s := newTestServer(t, nil)
	writeScanRecord(t, s.dataDir, "target-a/2026-05-01/scan-a", ScanRecord{
		ID:         "scan-a",
		InstanceID: "queue-1234",
		Target:     "https://a.test",
		StartedAt:  "2026-05-01T10:00:00Z",
		Status:     "finished",
	})

	dir, rec := s.findScanByID("queue-1234")
	if dir == "" || rec == nil || rec.ID != "scan-a" {
		t.Fatalf("alias did not resolve to persisted scan: dir=%q rec=%#v", dir, rec)
	}
}

func TestHandleGetScan_FallsBackFromRecentShortInstanceRoute(t *testing.T) {
	s := newTestServer(t, nil)
	writeScanRecord(t, s.dataDir, "target-a/2026-05-01/scan-a", ScanRecord{
		ID:        "scan-a",
		Target:    "https://a.test",
		StartedAt: time.Now().Add(-5 * time.Minute).Format(time.RFC3339Nano),
		Status:    "finished",
	})

	rr := httptest.NewRecorder()
	s.handleGetScan(rr, httptest.NewRequest(http.MethodGet, "/api/scans/deadbeef", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"id":"scan-a"`) {
		t.Fatalf("recent short route did not resolve to latest scan: code=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleGetScan_MarksGlobalDiscordWebhookConfigured(t *testing.T) {
	s := newTestServer(t, &config.Config{
		DiscordWebhook:    "https://discord.example/webhook",
		RateLimitRequests: 60,
		RateLimitWindow:   60,
	})
	writeScanRecord(t, s.dataDir, "target-a/2026-05-01/scan-a", ScanRecord{
		ID:        "scan-a",
		Target:    "https://a.test",
		StartedAt: "2026-05-01T10:00:00Z",
		Status:    "finished",
	})

	rr := httptest.NewRecorder()
	s.handleGetScan(rr, httptest.NewRequest(http.MethodGet, "/api/scans/scan-a", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("get scan code = %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"discord_webhook_configured":true`) {
		t.Fatalf("global webhook was not marked configured: %s", rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "discord.example") {
		t.Fatalf("webhook URL leaked in response: %s", rr.Body.String())
	}
}

func writeScanRecord(t *testing.T, baseDir, rel string, rec ScanRecord) {
	t.Helper()
	dir := filepath.Join(baseDir, filepath.FromSlash(rel))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir scan dir: %v", err)
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		t.Fatalf("marshal scan record: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scan.json"), data, 0o644); err != nil {
		t.Fatalf("write scan.json: %v", err)
	}
}

func TestHandleRateLimitSettings_ClampsAndReplacesLimiter(t *testing.T) {
	s := newTestServer(t, &config.Config{RateLimitRequests: 5, RateLimitWindow: 30})

	rr := httptest.NewRecorder()
	s.handleRateLimit(rr, httptest.NewRequest(http.MethodPost, "/api/settings/rate-limit", strings.NewReader(`{"requests":2000,"window":1}`)))
	if rr.Code != http.StatusOK {
		t.Fatalf("rate limit update code = %d body=%s", rr.Code, rr.Body.String())
	}
	if s.cfg.RateLimitRequests != 1000 || s.cfg.RateLimitWindow != 10 {
		t.Fatalf("config was not clamped: requests=%d window=%d", s.cfg.RateLimitRequests, s.cfg.RateLimitWindow)
	}
	if s.rateLimiter == nil {
		t.Fatal("rate limiter was not replaced")
	}
}

func TestAgentMailSettings_MasksAndPreservesExistingKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	envFile := filepath.Join(home, ".xalgorix.env")
	oldKey := "old-secret-12345678"
	if err := os.WriteFile(envFile, []byte("XALGORIX_LLM=test\nAGENTMAIL_POD=oldpod\nAGENTMAIL_API_KEY="+oldKey+"\n"), 0o644); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	s := newTestServer(t, &config.Config{
		AgentMailPod:      "oldpod",
		AgentMailAPIKey:   oldKey,
		RateLimitRequests: 60,
		RateLimitWindow:   60,
	})

	rr := httptest.NewRecorder()
	s.handleAgentMailSettings(rr, httptest.NewRequest(http.MethodGet, "/api/settings/agentmail", nil))
	var getResp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	if getResp["apiKey"] != "****12345678" || getResp["hasApiKey"] != true {
		t.Fatalf("unexpected masked GET response: %#v", getResp)
	}

	rr = httptest.NewRecorder()
	body := strings.NewReader(`{"pod":"newpod","apiKey":"****12345678"}`)
	s.handleAgentMailSettings(rr, httptest.NewRequest(http.MethodPost, "/api/settings/agentmail", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("preserve POST code = %d body=%s", rr.Code, rr.Body.String())
	}
	if s.cfg.AgentMailAPIKey != oldKey {
		t.Fatalf("masked POST overwrote key: %q", s.cfg.AgentMailAPIKey)
	}
	data, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read env file: %v", err)
	}
	if !strings.Contains(string(data), "AGENTMAIL_API_KEY="+oldKey) || !strings.Contains(string(data), "AGENTMAIL_POD=newpod") {
		t.Fatalf("env file did not preserve old key and update pod:\n%s", string(data))
	}
	if info, err := os.Stat(envFile); err != nil {
		t.Fatalf("stat env file: %v", err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("env file mode = %#o, want 0600", info.Mode().Perm())
	}

	rr = httptest.NewRecorder()
	body = strings.NewReader(`{"pod":"newpod","apiKey":"new-secret-abcdef12"}`)
	s.handleAgentMailSettings(rr, httptest.NewRequest(http.MethodPost, "/api/settings/agentmail", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("new key POST code = %d body=%s", rr.Code, rr.Body.String())
	}
	if s.cfg.AgentMailAPIKey != "new-secret-abcdef12" {
		t.Fatalf("new POST did not update config key: %q", s.cfg.AgentMailAPIKey)
	}
	data, err = os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read env file after new key: %v", err)
	}
	if !strings.Contains(string(data), "AGENTMAIL_API_KEY=new-secret-abcdef12") {
		t.Fatalf("env file did not contain new key:\n%s", string(data))
	}
}

func TestLLMSettings_MasksPreservesAndPersists(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	envFile := filepath.Join(home, ".xalgorix.env")
	oldAPIKey := "old-llm-secret-12345678"
	oldGeminiKey := "old-gemini-secret-87654321"
	if err := os.WriteFile(envFile, []byte("XALGORIX_LLM=old/model\nXALGORIX_API_KEY="+oldAPIKey+"\nGEMINI_API_KEY="+oldGeminiKey+"\n"), 0o644); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	s := newTestServer(t, &config.Config{
		LLM:               "old/model",
		APIBase:           "https://old.example/v1",
		APIKey:            oldAPIKey,
		ReasoningEffort:   "high",
		LLMMaxRetries:     5,
		MemCompTimeout:    30,
		MaxIterations:     0,
		GeminiAPIKey:      oldGeminiKey,
		RateLimitRequests: 60,
		RateLimitWindow:   60,
	})

	rr := httptest.NewRecorder()
	s.handleLLMSettings(rr, httptest.NewRequest(http.MethodGet, "/api/settings/llm", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET code = %d body=%s", rr.Code, rr.Body.String())
	}
	var getResp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	if getResp["apiKey"] != "****12345678" || getResp["geminiApiKey"] != "****87654321" {
		t.Fatalf("unexpected masked GET response: %#v", getResp)
	}

	rr = httptest.NewRecorder()
	body := strings.NewReader(`{"model":"openai/gpt-5.4","apiBase":"https://api.openai.com/v1","apiKey":"****12345678","reasoningEffort":"medium","llmMaxRetries":7,"memoryCompressorTimeout":45,"maxIterations":9,"geminiApiKey":"****87654321"}`)
	s.handleLLMSettings(rr, httptest.NewRequest(http.MethodPost, "/api/settings/llm", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("POST code = %d body=%s", rr.Code, rr.Body.String())
	}
	if s.cfg.LLM != "openai/gpt-5.4" || s.cfg.APIBase != "https://api.openai.com/v1" {
		t.Fatalf("LLM settings not applied: llm=%q apiBase=%q", s.cfg.LLM, s.cfg.APIBase)
	}
	if s.cfg.APIKey != oldAPIKey || s.cfg.GeminiAPIKey != oldGeminiKey {
		t.Fatalf("masked POST did not preserve secrets: api=%q gemini=%q", s.cfg.APIKey, s.cfg.GeminiAPIKey)
	}
	if s.cfg.ReasoningEffort != "medium" || s.cfg.LLMMaxRetries != 7 || s.cfg.MemCompTimeout != 45 || s.cfg.MaxIterations != 9 {
		t.Fatalf("numeric settings not applied: %#v", s.cfg)
	}
	data, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read env file: %v", err)
	}
	env := string(data)
	for _, want := range []string{
		"XALGORIX_LLM=openai/gpt-5.4",
		"XALGORIX_API_BASE=https://api.openai.com/v1",
		"XALGORIX_API_KEY=" + oldAPIKey,
		"GEMINI_API_KEY=" + oldGeminiKey,
		"XALGORIX_REASONING_EFFORT=medium",
	} {
		if !strings.Contains(env, want) {
			t.Fatalf("env file missing %q:\n%s", want, env)
		}
	}
}

func TestEnvironmentSettings_RejectsUnknownAndUpdatesRuntime(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	s := newTestServer(t, &config.Config{RateLimitRequests: 60, RateLimitWindow: 60})

	rr := httptest.NewRecorder()
	s.handleEnvironmentSettings(rr, httptest.NewRequest(http.MethodPost, "/api/settings/environment", strings.NewReader(`{"values":{"UNSUPPORTED_ENV":"x"}}`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unsupported env code = %d, want 400", rr.Code)
	}

	rr = httptest.NewRecorder()
	body := strings.NewReader(`{"values":{"XALGORIX_RATE_LIMIT_REQUESTS":"2000","XALGORIX_RATE_LIMIT_WINDOW":"1","XALGORIX_DISCORD_WEBHOOK":"https://discord.example/webhook","XALGORIX_BIND":"0.0.0.0"}}`)
	s.handleEnvironmentSettings(rr, httptest.NewRequest(http.MethodPost, "/api/settings/environment", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("environment POST code = %d body=%s", rr.Code, rr.Body.String())
	}
	if s.cfg.RateLimitRequests != 1000 || s.cfg.RateLimitWindow != 10 {
		t.Fatalf("rate limits not clamped/applied: %d/%d", s.cfg.RateLimitRequests, s.cfg.RateLimitWindow)
	}
	if s.cfg.DiscordWebhook != "https://discord.example/webhook" || s.discordWebhook != "https://discord.example/webhook" {
		t.Fatalf("discord webhook not applied: cfg=%q runtime=%q", s.cfg.DiscordWebhook, s.discordWebhook)
	}
	if s.cfg.BindAddr != "0.0.0.0" {
		t.Fatalf("bind address not applied: %q", s.cfg.BindAddr)
	}
	var resp environmentSettingsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.RestartRequired {
		t.Fatal("expected restartRequired for bind change")
	}
	data, err := os.ReadFile(filepath.Join(home, ".xalgorix.env"))
	if err != nil {
		t.Fatalf("read env file: %v", err)
	}
	env := string(data)
	for _, want := range []string{
		"XALGORIX_RATE_LIMIT_REQUESTS=1000",
		"XALGORIX_RATE_LIMIT_WINDOW=10",
		"XALGORIX_DISCORD_WEBHOOK=https://discord.example/webhook",
		"XALGORIX_BIND=0.0.0.0",
	} {
		if !strings.Contains(env, want) {
			t.Fatalf("env file missing %q:\n%s", want, env)
		}
	}
}

func TestInstanceAction_GetAndStopSpecificInstance(t *testing.T) {
	s := newTestServer(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.instances["inst-1"] = &ScanInstance{
		ID:        "inst-1",
		Targets:   "https://a.test",
		Status:    "running",
		StartedAt: "2026-05-02T10:00:00Z",
		cancel:    cancel,
	}

	rr := httptest.NewRecorder()
	s.handleInstanceAction(rr, httptest.NewRequest(http.MethodGet, "/api/instances/inst-1", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"id":"inst-1"`) {
		t.Fatalf("get instance response: code=%d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	s.handleInstanceAction(rr, httptest.NewRequest(http.MethodPost, "/api/instances/inst-1/stop", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("stop instance code = %d body=%s", rr.Code, rr.Body.String())
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("instance cancel function was not called")
	}
	if got := s.instances["inst-1"].Status; got != "stopped" {
		t.Fatalf("instance status = %q, want stopped", got)
	}
}
