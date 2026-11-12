package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/credentials"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

func fixtureJWT(serial int64, exp time.Time) string {
	enc := base64.RawURLEncoding
	payload, _ := json.Marshal(map[string]any{"sub": "qa-user", "jti": serial, "exp": exp.Unix()})
	return enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc.EncodeToString(payload) + ".c2lnbmF0dXJl"
}

// tokenLab is a disposable microservice fixture: an auth service issuing
// JWTs and services accepting only currently valid tokens.
type tokenLab struct {
	mu       sync.Mutex
	valid    map[string]bool
	logins   atomic.Int64
	lifetime time.Duration
	strayHit atomic.Int64
	auth     *httptest.Server
	orders   *httptest.Server
	reports  *httptest.Server
	stray    *httptest.Server
}

func (l *tokenLab) authorized(r *http.Request) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.valid[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
}

func (l *tokenLab) revokeAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.valid = map[string]bool{}
}

func newTokenLab(t *testing.T) *tokenLab {
	t.Helper()
	lab := &tokenLab{valid: map[string]bool{}, lifetime: time.Hour}
	lab.auth = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			var body map[string]string
			if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&body) != nil || body["email"] != "qa@example.test" || body["password"] != "correct horse" || body["client"] != "xalgorix" {
				http.Error(w, `{"error":"invalid login"}`, http.StatusUnauthorized)
				return
			}
			serial := lab.logins.Add(1)
			token := fixtureJWT(serial, time.Now().Add(lab.lifetime))
			lab.mu.Lock()
			lab.valid[token] = true
			lab.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"data":{"accessToken":%q,"user":{"id":1}}}`, token)
		case "/api/auth/me":
			if !lab.authorized(r) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"email":"qa@example.test"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	protected := func(path string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != path {
				http.NotFound(w, r) // identical for anonymous and authenticated callers
				return
			}
			if !lab.authorized(r) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"items":[]}`))
		})
	}
	lab.orders = httptest.NewServer(protected("/api/orders"))
	lab.reports = httptest.NewServer(protected("/api/reports"))
	lab.stray = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lab.strayHit.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Errorf("token reached an unbound service")
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(func() { lab.auth.Close(); lab.orders.Close(); lab.reports.Close(); lab.stray.Close() })
	return lab
}

func tokenTestVault(t *testing.T, s *Server) *credentials.Vault {
	t.Helper()
	keyPath := t.TempDir() + "/credential.key"
	if err := os.WriteFile(keyPath, []byte("01234567890123456789012345678901"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XALGORIX_CREDENTIAL_KEY_FILE", keyPath)
	vault, err := s.credentialVault()
	if err != nil {
		t.Fatal(err)
	}
	return vault
}

func tokenLoginValues(loginURL string) map[string]string {
	return map[string]string{"login_url": loginURL, "username": "qa@example.test", "password": "correct horse", "username_field": "email", "extra_fields": `{"client":"xalgorix"}`}
}

// microservicePlan binds one token credential to auth (protected path),
// orders (protected path) and reports (no protected path). stray is a target
// of the assessment but is not bound to the credential.
func microservicePlan(lab *tokenLab, credentialID string) *scanner.AssessmentPlan {
	targets := []assessment.Target{
		{ID: "svc-auth", Kind: assessment.KindURL, Value: lab.auth.URL},
		{ID: "svc-orders", Kind: assessment.KindURL, Value: lab.orders.URL},
		{ID: "svc-reports", Kind: assessment.KindURL, Value: lab.reports.URL},
		{ID: "svc-stray", Kind: assessment.KindURL, Value: lab.stray.URL},
	}
	cfg := assessment.AssessmentConfig{
		Mode: assessment.ModeGrayBox, Types: []assessment.Type{assessment.TypeAPI}, Targets: targets,
		Access: []assessment.AccessBinding{
			{Kind: assessment.AccessTokenLogin, CredentialID: credentialID, TargetIDs: []string{"svc-auth"}, VerifyURL: lab.auth.URL + "/api/auth/me"},
			{Kind: assessment.AccessTokenLogin, CredentialID: credentialID, TargetIDs: []string{"svc-orders"}, VerifyURL: lab.orders.URL + "/api/orders"},
			{Kind: assessment.AccessTokenLogin, CredentialID: credentialID, TargetIDs: []string{"svc-reports"}},
		},
	}
	plan := &scanner.AssessmentPlan{Config: cfg, Capabilities: assessment.DeriveCapabilities(cfg)}
	for _, target := range targets {
		plan.Jobs = append(plan.Jobs, scanner.PlanJob{ID: "zap:" + target.ID, Scanner: "zap", TargetID: target.ID, Target: target.Value, State: scanner.PlanSelected, ExecutionMode: "unauthenticated"})
	}
	return plan
}

func capabilityState(plan *scanner.AssessmentPlan, targetID string) (assessment.EvidenceState, string) {
	for _, c := range plan.Capabilities {
		if c.Capability == assessment.CapAuthWeb && c.TargetID == targetID {
			return c.State, c.Reason
		}
	}
	return "", ""
}

func jobMode(plan *scanner.AssessmentPlan, targetID string) string {
	for _, job := range plan.Jobs {
		if job.TargetID == targetID {
			return job.ExecutionMode
		}
	}
	return ""
}

func TestTokenLoginLogsInOnceAndAppliesTokenToBoundServices(t *testing.T) {
	lab := newTokenLab(t)
	s := newTestServer(t, nil)
	vault := tokenTestVault(t, s)
	meta, err := vault.Create(credentials.Record{Name: "shared login", Kind: assessment.AccessTokenLogin, TargetIDs: []string{"svc-auth", "svc-orders", "svc-reports"}, Values: tokenLoginValues(lab.auth.URL + "/api/auth/login")})
	if err != nil {
		t.Fatal(err)
	}
	plan := microservicePlan(lab, meta.ID)
	headers, err := s.prepareAssessmentAuthentication(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if got := lab.logins.Load(); got != 1 {
		t.Fatalf("expected one login for three services, got %d", got)
	}
	line := headers["svc-auth"]
	if len(line) != 1 || !strings.HasPrefix(line[0], "Authorization: Bearer ") {
		t.Fatalf("auth service has no bearer header: %v", headers)
	}
	for _, id := range []string{"svc-orders", "svc-reports"} {
		if len(headers[id]) != 1 || headers[id][0] != line[0] {
			t.Fatalf("%s did not receive the shared token: %v", id, headers[id])
		}
	}
	if len(headers["svc-stray"]) != 0 {
		t.Fatal("unbound service received the token")
	}
	for _, id := range []string{"svc-auth", "svc-orders"} {
		if state, reason := capabilityState(plan, id); state != assessment.StateVerified {
			t.Fatalf("%s not verified: %s %s", id, state, reason)
		}
	}
	if state, reason := capabilityState(plan, "svc-reports"); state != assessment.StateAvailable || !strings.Contains(reason, "not verified") {
		t.Fatalf("service without protected path must be available-but-unverified, got %s %q", state, reason)
	}
	for _, id := range []string{"svc-auth", "svc-orders", "svc-reports"} {
		if jobMode(plan, id) != "authenticated" {
			t.Fatalf("%s ZAP job is not authenticated", id)
		}
	}
	if jobMode(plan, "svc-stray") == "authenticated" {
		t.Fatal("unbound service job marked authenticated")
	}
	token := strings.TrimPrefix(line[0], "Authorization: Bearer ")
	encoded, _ := json.Marshal(plan)
	if strings.Contains(string(encoded), token) || strings.Contains(string(encoded), "correct horse") {
		t.Fatal("token or password copied into the plan")
	}
	if lab.strayHit.Load() != 0 {
		t.Fatal("unbound service was contacted during authentication")
	}
}

func TestTokenLoginRenewalIsSharedAcrossServices(t *testing.T) {
	lab := newTokenLab(t)
	s := newTestServer(t, nil)
	vault := tokenTestVault(t, s)
	meta, err := vault.Create(credentials.Record{Name: "shared login", Kind: assessment.AccessTokenLogin, TargetIDs: []string{"svc-auth", "svc-orders", "svc-reports"}, Values: tokenLoginValues(lab.auth.URL + "/api/auth/login")})
	if err != nil {
		t.Fatal(err)
	}
	plan := microservicePlan(lab, meta.ID)
	headers, err := s.prepareAssessmentAuthentication(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	refreshers, err := s.assessmentAuthRefreshers(plan, headers)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"svc-auth", "svc-orders", "svc-reports"} {
		if refreshers[id] == nil {
			t.Fatalf("%s has no session refresher", id)
		}
	}
	// A valid session is kept without logging in again.
	same, err := refreshers["svc-orders"](context.Background(), headers["svc-orders"])
	if err != nil || same[0] != headers["svc-orders"][0] || lab.logins.Load() != 1 {
		t.Fatalf("valid session was not kept: %v %v logins=%d", same, err, lab.logins.Load())
	}
	lab.revokeAll()
	renewed, err := refreshers["svc-orders"](context.Background(), headers["svc-orders"])
	if err != nil {
		t.Fatalf("renewal failed: %v", err)
	}
	if renewed[0] == headers["svc-orders"][0] || lab.logins.Load() != 2 {
		t.Fatalf("expired token was not renewed once: logins=%d", lab.logins.Load())
	}
	// Another service still holding the old token picks up the renewed one
	// without a second login.
	picked, err := refreshers["svc-auth"](context.Background(), headers["svc-auth"])
	if err != nil || picked[0] != renewed[0] || lab.logins.Load() != 2 {
		t.Fatalf("renewal not shared: %v %v logins=%d", picked, err, lab.logins.Load())
	}
	unverified, err := refreshers["svc-reports"](context.Background(), headers["svc-reports"])
	if err != nil || unverified[0] != renewed[0] || lab.logins.Load() != 2 {
		t.Fatalf("unverified service did not pick up the shared token: %v %v", unverified, err)
	}
}

func TestTokenSessionRenewsBeforeJWTExpiry(t *testing.T) {
	lab := newTokenLab(t)
	cfg, err := parseTokenLoginConfig(tokenLoginValues(lab.auth.URL + "/api/auth/login"))
	if err != nil {
		t.Fatal(err)
	}
	session, err := newTokenSession(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if session.expiry.IsZero() {
		t.Fatal("JWT expiry not decoded")
	}
	first := session.headerLine()
	if line, changed, err := session.current(context.Background(), first); err != nil || changed || line != first {
		t.Fatal("fresh token renewed early")
	}
	session.mu.Lock()
	session.issued, session.expiry = time.Now().Add(-time.Hour), time.Now().Add(30*time.Second)
	session.mu.Unlock()
	line, changed, err := session.current(context.Background(), first)
	if err != nil || !changed || line == first || lab.logins.Load() != 2 {
		t.Fatalf("near-expiry token not renewed: changed=%v err=%v logins=%d", changed, err, lab.logins.Load())
	}
	if session.renewals != 0 {
		t.Fatal("expiry-driven renewal counted against the failure limit")
	}
}

func TestTokenLoginRefusesLoginURLOutsideAssessmentTargets(t *testing.T) {
	lab := newTokenLab(t)
	var outsideHits atomic.Int64
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outsideHits.Add(1)
		http.Error(w, "nope", http.StatusTeapot)
	}))
	defer outside.Close()
	s := newTestServer(t, nil)
	vault := tokenTestVault(t, s)
	meta, err := vault.Create(credentials.Record{Name: "shared login", Kind: assessment.AccessTokenLogin, TargetIDs: []string{"svc-auth", "svc-orders", "svc-reports"}, Values: tokenLoginValues(outside.URL + "/login")})
	if err != nil {
		t.Fatal(err)
	}
	plan := microservicePlan(lab, meta.ID)
	headers, err := s.prepareAssessmentAuthentication(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(headers) != 0 || outsideHits.Load() != 0 {
		t.Fatalf("password sent outside the assessment: headers=%v hits=%d", headers, outsideHits.Load())
	}
	if state, reason := capabilityState(plan, "svc-orders"); state != assessment.StateUnavailable || !strings.Contains(reason, "outside every application target") {
		t.Fatalf("unexpected state %s %q", state, reason)
	}
	for _, job := range plan.Jobs[:3] {
		if job.State != scanner.PlanSkipped {
			t.Fatalf("authenticated job not skipped: %+v", job)
		}
	}
}

func TestTokenLoginRejectedLoginFailsEveryBoundService(t *testing.T) {
	lab := newTokenLab(t)
	s := newTestServer(t, nil)
	vault := tokenTestVault(t, s)
	values := tokenLoginValues(lab.auth.URL + "/api/auth/login")
	values["password"] = "wrong"
	meta, err := vault.Create(credentials.Record{Name: "shared login", Kind: assessment.AccessTokenLogin, TargetIDs: []string{"svc-auth", "svc-orders", "svc-reports"}, Values: values})
	if err != nil {
		t.Fatal(err)
	}
	plan := microservicePlan(lab, meta.ID)
	if _, err := s.prepareAssessmentAuthentication(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"svc-auth", "svc-orders", "svc-reports"} {
		state, reason := capabilityState(plan, id)
		if state != assessment.StateFailed || !strings.Contains(reason, "HTTP 401") || strings.Contains(reason, "wrong") {
			t.Fatalf("%s: %s %q", id, state, reason)
		}
	}
	if lab.logins.Load() != 0 {
		t.Fatal("rejected login counted as issued")
	}
}

func TestTokenLoginFormBodyAndExplicitTokenPath(t *testing.T) {
	var gotForm string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.PostForm.Encode()
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			http.Error(w, "bad type", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"result":{"tokens":[{"value":"opaque-token-1"}]}}`))
	}))
	defer server.Close()
	values := map[string]string{"login_url": server.URL + "/realms/app/token", "username": "qa", "password": "pw", "body_format": "form", "extra_fields": `{"grant_type":"password","client_id":"web"}`, "token_path": "result.tokens.0.value", "header_name": "X-Auth-Token", "header_prefix": ""}
	cfg, err := parseTokenLoginConfig(values)
	if err != nil {
		t.Fatal(err)
	}
	session, err := newTokenSession(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if session.headerLine() != "X-Auth-Token: opaque-token-1" || !session.expiry.IsZero() {
		t.Fatalf("unexpected header %q", session.headerLine())
	}
	for _, want := range []string{"grant_type=password", "client_id=web", "username=qa", "password=pw"} {
		if !strings.Contains(gotForm, want) {
			t.Fatalf("form body missing %s: %s", want, gotForm)
		}
	}
}

func TestExtractTokenAndConfigValidation(t *testing.T) {
	cases := map[string]string{
		`{"access_token":"a"}`:             "a",
		`{"accessToken":"b"}`:              "b",
		`{"token":"c"}`:                    "c",
		`{"data":{"token":"d"}}`:           "d",
		`{"data":{"access_token":"e"}}`:    "e",
		`{"jwt":"f","access_token":"pri"}`: "pri",
	}
	for body, want := range cases {
		if got, err := extractToken([]byte(body), ""); err != nil || got != want {
			t.Errorf("%s: got %q err %v", body, got, err)
		}
	}
	for _, body := range []string{`{"user":{}}`, `not json`, `{"token":42}`, `{"token":""}`} {
		if _, err := extractToken([]byte(body), ""); err == nil {
			t.Errorf("%s: expected error", body)
		}
	}
	if _, err := extractToken([]byte(`{"a":{"b":"x"}}`), "a.c"); err == nil {
		t.Error("missing explicit path accepted")
	}
	bad := []map[string]string{
		{"login_url": "", "username": "u", "password": "p"},
		{"login_url": "ftp://x/login", "username": "u", "password": "p"},
		{"login_url": "https://user:pw@x/login", "username": "u", "password": "p"},
		{"login_url": "https://x/login", "username": "u", "password": "p", "body_format": "xml"},
		{"login_url": "https://x/login", "username": "u", "password": "p", "extra_fields": `{"password":"override"}`},
		{"login_url": "https://x/login", "username": "u", "password": "p", "header_name": "Bad Header"},
	}
	for _, values := range bad {
		if _, err := parseTokenLoginConfig(values); err == nil {
			t.Errorf("invalid config accepted: %v", values)
		}
	}
	if exp := jwtExpiry(fixtureJWT(1, time.Unix(2000000000, 0))); exp.Unix() != 2000000000 {
		t.Fatalf("exp decoded as %v", exp)
	}
	if !jwtExpiry("opaque").IsZero() {
		t.Fatal("opaque token given an expiry")
	}
}

func TestCredentialTestEndpointTokenLogin(t *testing.T) {
	lab := newTokenLab(t)
	s := newTestServer(t, nil)
	s.cfg.AllowLocalTargets = true
	vault := tokenTestVault(t, s)
	meta, err := vault.Create(credentials.Record{Name: "shared login", Kind: assessment.AccessTokenLogin, TargetIDs: []string{"svc-orders", "svc-reports"}, Values: tokenLoginValues(lab.auth.URL + "/api/auth/login")})
	if err != nil {
		t.Fatal(err)
	}
	invoke := func(body string) string {
		rr := httptest.NewRecorder()
		s.handleCredentialDetail(rr, httptest.NewRequest(http.MethodPost, "/api/credentials/"+meta.ID+"/test", strings.NewReader(body)))
		if strings.Contains(rr.Body.String(), "correct horse") || strings.Contains(rr.Body.String(), "eyJ") {
			t.Fatalf("test response leaked a secret: %s", rr.Body.String())
		}
		return rr.Body.String()
	}
	verified := invoke(fmt.Sprintf(`{"target_id":"svc-orders","target_url":%q,"verify_url":%q,"login_targets":[%q]}`, lab.orders.URL, lab.orders.URL+"/api/orders", lab.auth.URL))
	if !strings.Contains(verified, `"state":"verified"`) {
		t.Fatalf("protected path not verified: %s", verified)
	}
	available := invoke(fmt.Sprintf(`{"target_id":"svc-reports","target_url":%q,"login_targets":[%q]}`, lab.reports.URL, lab.auth.URL))
	if !strings.Contains(available, `"state":"available"`) || strings.Contains(available, `"verified":true`) {
		t.Fatalf("unverified service reported as verified: %s", available)
	}
	before := lab.logins.Load()
	refused := invoke(fmt.Sprintf(`{"target_id":"svc-orders","target_url":%q}`, lab.orders.URL))
	if !strings.Contains(refused, "must be inside") || lab.logins.Load() != before {
		t.Fatalf("login outside listed targets was attempted: %s", refused)
	}
}

func TestPastedHeaderTokenUnreachableHostFailsClearly(t *testing.T) {
	s := newTestServer(t, nil)
	vault := tokenTestVault(t, s)
	meta, err := vault.Create(credentials.Record{Name: "pasted", Kind: assessment.AccessApplicationHeaders, TargetIDs: []string{"portal"}, Values: map[string]string{"Authorization": "Bearer pasted-token"}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := assessment.AssessmentConfig{Targets: []assessment.Target{{ID: "portal", Kind: assessment.KindURL, Value: "https://portal.invalid"}}, Access: []assessment.AccessBinding{{Kind: assessment.AccessApplicationHeaders, CredentialID: meta.ID, TargetIDs: []string{"portal"}}}}
	plan := &scanner.AssessmentPlan{Config: cfg, Capabilities: assessment.DeriveCapabilities(cfg)}
	headers, err := s.prepareAssessmentAuthentication(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	state, reason := capabilityState(plan, "portal")
	if len(headers["portal"]) != 0 || state != assessment.StateFailed || !strings.Contains(reason, "could not resolve portal.invalid") {
		t.Fatalf("unreachable host: headers=%v state=%s reason=%q", headers, state, reason)
	}
}

func TestPastedHeaderTokenAppliedUnverifiedAndExpiryStopsIt(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })) // a NestJS root: 404 with or without a token
	defer api.Close()
	s := newTestServer(t, nil)
	vault := tokenTestVault(t, s)
	token := fixtureJWT(7, time.Now().Add(time.Hour))
	meta, err := vault.Create(credentials.Record{Name: "pasted", Kind: assessment.AccessApplicationHeaders, TargetIDs: []string{"api"}, Values: map[string]string{"Authorization": "Bearer " + token}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := assessment.AssessmentConfig{Targets: []assessment.Target{{ID: "api", Kind: assessment.KindURL, Value: api.URL}}, Access: []assessment.AccessBinding{{Kind: assessment.AccessApplicationHeaders, CredentialID: meta.ID, TargetIDs: []string{"api"}}}}
	plan := &scanner.AssessmentPlan{Config: cfg, Capabilities: assessment.DeriveCapabilities(cfg), Jobs: []scanner.PlanJob{{Scanner: "zap", TargetID: "api", State: scanner.PlanSelected}}}
	headers, err := s.prepareAssessmentAuthentication(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	state, reason := capabilityState(plan, "api")
	if len(headers["api"]) != 1 || state != assessment.StateAvailable || !strings.Contains(reason, "not verified") || plan.Jobs[0].ExecutionMode != "authenticated" {
		t.Fatalf("pasted token on an API root was not applied as unverified: headers=%v state=%s reason=%q", headers, state, reason)
	}
	refreshers, err := s.assessmentAuthRefreshers(plan, headers)
	if err != nil {
		t.Fatal(err)
	}
	if next, err := refreshers["api"](context.Background(), headers["api"]); err != nil || next[0] != headers["api"][0] {
		t.Fatalf("unverified credential not kept by the session check: %v %v", next, err)
	}
	expired := []string{"Authorization: Bearer " + fixtureJWT(8, time.Now().Add(-time.Minute))}
	if _, err := refreshers["api"](context.Background(), expired); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired pasted token was not stopped: %v", err)
	}
	// An already-expired token is refused at scan start with that reason.
	stale, _ := vault.Create(credentials.Record{Name: "stale", Kind: assessment.AccessApplicationHeaders, TargetIDs: []string{"api"}, Values: map[string]string{"Authorization": "Bearer " + fixtureJWT(9, time.Now().Add(-time.Hour))}})
	cfg.Access[0].CredentialID = stale.ID
	plan = &scanner.AssessmentPlan{Config: cfg, Capabilities: assessment.DeriveCapabilities(cfg)}
	if headers, _ := s.prepareAssessmentAuthentication(context.Background(), plan); len(headers["api"]) != 0 {
		t.Fatal("expired pasted token applied at scan start")
	}
	if state, reason := capabilityState(plan, "api"); state != assessment.StateFailed || !strings.Contains(reason, "expired") {
		t.Fatalf("expired token: state=%s reason=%q", state, reason)
	}
}
