package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

// Token login logs in once against an explicit login API, reads the bearer
// token from its response, and applies it to every target explicitly bound to
// the same credential. The password is only ever sent to the login URL, whose
// origin must be inside one of the assessment's own application targets. The
// token lives in memory only.

const (
	maxTokenBytes          = 16 << 10
	maxTokenLoginResponse  = 1 << 20
	tokenRenewMargin       = 2 * time.Minute
	maxProactiveRenewals   = 1000
	tokenLoginClientTimout = 15 * time.Second
)

// defaultTokenPaths are tried in order when no explicit token path is given.
var defaultTokenPaths = []string{"access_token", "accessToken", "token", "jwt", "id_token", "data.token", "data.accessToken", "data.access_token", "result.token", "result.accessToken"}

// tokenConfigError marks a configuration problem (nothing was sent), as
// opposed to a login the server rejected.
type tokenConfigError string

func (e tokenConfigError) Error() string { return string(e) }

type tokenLoginConfig struct {
	loginURL      string
	username      string
	password      string
	usernameField string
	passwordField string
	bodyFormat    string
	tokenPath     string
	headerName    string
	headerPrefix  string
	extra         map[string]string
}

func parseTokenLoginConfig(values map[string]string) (tokenLoginConfig, error) {
	cfg := tokenLoginConfig{
		loginURL:      strings.TrimSpace(values["login_url"]),
		username:      values["username"],
		password:      values["password"],
		usernameField: strings.TrimSpace(values["username_field"]),
		passwordField: strings.TrimSpace(values["password_field"]),
		bodyFormat:    strings.ToLower(strings.TrimSpace(values["body_format"])),
		tokenPath:     strings.TrimSpace(values["token_path"]),
		headerName:    strings.TrimSpace(values["header_name"]),
		headerPrefix:  values["header_prefix"],
	}
	if cfg.usernameField == "" {
		cfg.usernameField = "username"
	}
	if cfg.passwordField == "" {
		cfg.passwordField = "password"
	}
	if cfg.bodyFormat == "" {
		cfg.bodyFormat = "json"
	}
	if cfg.headerName == "" {
		cfg.headerName = "Authorization"
	}
	if _, set := values["header_prefix"]; !set {
		cfg.headerPrefix = "Bearer "
	}
	if cfg.loginURL == "" || cfg.username == "" || cfg.password == "" {
		return cfg, tokenConfigError("token login requires a login URL, username and password")
	}
	if cfg.bodyFormat != "json" && cfg.bodyFormat != "form" {
		return cfg, tokenConfigError("token login body format must be json or form")
	}
	if !validHTTPHeaderName(cfg.headerName) || hasUnsafeHeaderValue(cfg.headerPrefix) || len(cfg.headerPrefix) > 64 {
		return cfg, tokenConfigError("token login header name or prefix is invalid")
	}
	if len(cfg.usernameField) > 128 || len(cfg.passwordField) > 128 || len(cfg.tokenPath) > 256 || strings.ContainsAny(cfg.usernameField+cfg.passwordField+cfg.tokenPath, "\r\n\x00") {
		return cfg, tokenConfigError("token login field names are invalid")
	}
	if raw := strings.TrimSpace(values["extra_fields"]); raw != "" {
		if err := json.Unmarshal([]byte(raw), &cfg.extra); err != nil || len(cfg.extra) > 32 {
			return cfg, tokenConfigError("token login extra fields must be a JSON object of up to 32 string values")
		}
		for key := range cfg.extra {
			if key == "" || key == cfg.usernameField || key == cfg.passwordField || len(key) > 128 {
				return cfg, tokenConfigError("token login extra fields cannot replace the username or password fields")
			}
		}
	}
	parsed, err := url.Parse(cfg.loginURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return cfg, tokenConfigError("token login URL must be an absolute HTTP(S) URL without credentials or fragments")
	}
	return cfg, nil
}

// tokenLoginAllowed reports whether the login URL is inside one of the given
// application scopes. The password must never leave the assessment's targets.
func tokenLoginAllowed(loginURL string, scopes []assessment.AppScope) bool {
	for _, scope := range scopes {
		if urlWithinScope(scope, loginURL) {
			return true
		}
	}
	return false
}

// obtainLoginToken performs one login and returns the token and its JWT
// expiry (zero when the token is not a JWT with an exp claim). Errors are
// fixed phrases that never contain credential or token values.
func obtainLoginToken(ctx context.Context, cfg tokenLoginConfig) (string, time.Time, error) {
	var body []byte
	contentType := "application/json"
	if cfg.bodyFormat == "form" {
		form := url.Values{}
		for key, value := range cfg.extra {
			form.Set(key, value)
		}
		form.Set(cfg.usernameField, cfg.username)
		form.Set(cfg.passwordField, cfg.password)
		body, contentType = []byte(form.Encode()), "application/x-www-form-urlencoded"
	} else {
		payload := map[string]string{}
		for key, value := range cfg.extra {
			payload[key] = value
		}
		payload[cfg.usernameField], payload[cfg.passwordField] = cfg.username, cfg.password
		encoded, err := json.Marshal(payload)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("token login body could not be encoded")
		}
		body = encoded
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.loginURL, bytes.NewReader(body))
	if err != nil {
		return "", time.Time{}, tokenConfigError("invalid token login URL")
	}
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Accept", "application/json")
	// Redirects are never followed: a login API answers directly, and
	// following one could carry the request to another origin.
	client := &http.Client{Timeout: tokenLoginClientTimout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("token login request failed")
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maxTokenLoginResponse))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", time.Time{}, fmt.Errorf("token login was rejected (HTTP %d)", response.StatusCode)
	}
	if readErr != nil {
		return "", time.Time{}, fmt.Errorf("token login response could not be read")
	}
	token, err := extractToken(raw, cfg.tokenPath)
	if err != nil {
		// Some APIs return the token in a response header instead of the body.
		if header := strings.TrimSpace(response.Header.Get("Authorization")); cfg.tokenPath == "" && header != "" {
			token = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(header, "Bearer "), "bearer "))
			err = nil
		}
	}
	if err != nil {
		return "", time.Time{}, err
	}
	if token == "" || len(token) > maxTokenBytes || hasUnsafeHeaderValue(token) || strings.ContainsAny(token, " \t") {
		return "", time.Time{}, fmt.Errorf("token login returned an unusable token")
	}
	return token, jwtExpiry(token), nil
}

// extractToken reads a string token from a JSON response, using path (dot
// separated, numeric segments index arrays) or the common default locations.
func extractToken(body []byte, path string) (string, error) {
	var document any
	if err := json.Unmarshal(body, &document); err != nil {
		return "", fmt.Errorf("token login response is not JSON")
	}
	paths := defaultTokenPaths
	if path != "" {
		paths = []string{path}
	}
	for _, candidate := range paths {
		if value, ok := lookupJSONPath(document, candidate); ok {
			if token, isString := value.(string); isString && strings.TrimSpace(token) != "" {
				return strings.TrimSpace(token), nil
			}
		}
	}
	if path != "" {
		return "", fmt.Errorf("token login response has no string token at the configured token path")
	}
	return "", fmt.Errorf("token login response has no token at a known location; set a token path")
}

func lookupJSONPath(document any, path string) (any, bool) {
	current := document
	for _, segment := range strings.Split(path, ".") {
		switch node := current.(type) {
		case map[string]any:
			next, ok := node[segment]
			if !ok {
				return nil, false
			}
			current = next
		case []any:
			index, err := strconv.Atoi(segment)
			if err != nil || index < 0 || index >= len(node) {
				return nil, false
			}
			current = node[index]
		default:
			return nil, false
		}
	}
	return current, true
}

// jwtExpiry decodes the exp claim of a JWT for renewal timing only. The
// signature is not checked; the value never grants anything.
func jwtExpiry(token string) time.Time {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return time.Time{}
	}
	var claims struct {
		Exp json.Number `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return time.Time{}
	}
	seconds, err := claims.Exp.Float64()
	if err != nil || seconds <= 0 {
		return time.Time{}
	}
	return time.Unix(int64(seconds), 0)
}

// tokenSession is one logged-in token shared by every target bound to the
// same credential. Renewal is serialized, so many targets noticing expiry at
// once cause a single login.
type tokenSession struct {
	mu         sync.Mutex
	cfg        tokenLoginConfig
	line       string
	issued     time.Time
	expiry     time.Time
	renewals   int // renewals after a failed check (bounded by maxSessionRenewals)
	proactive  int // expiry-driven renewals (bounded by maxProactiveRenewals)
	loginCount int
}

func newTokenSession(ctx context.Context, cfg tokenLoginConfig) (*tokenSession, error) {
	session := &tokenSession{cfg: cfg}
	if err := session.login(ctx); err != nil {
		return nil, err
	}
	return session, nil
}

func (t *tokenSession) login(ctx context.Context) error {
	token, expiry, err := obtainLoginToken(ctx, t.cfg)
	if err != nil {
		return err
	}
	t.line = t.cfg.headerName + ": " + t.cfg.headerPrefix + token
	t.issued, t.expiry = time.Now(), expiry
	t.loginCount++
	return nil
}

// headerLine returns the current header line ("Authorization: Bearer ...").
func (t *tokenSession) headerLine() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.line
}

func (t *tokenSession) token() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return strings.TrimPrefix(strings.TrimPrefix(t.line, t.cfg.headerName+": "), t.cfg.headerPrefix)
}

func (t *tokenSession) nearExpiryLocked(now time.Time) bool {
	if t.expiry.IsZero() {
		return false
	}
	margin := tokenRenewMargin
	if lifetime := t.expiry.Sub(t.issued); lifetime > 0 && lifetime/2 < margin {
		margin = lifetime / 2
	}
	return !now.Before(t.expiry.Add(-margin))
}

// current returns the session's line when another caller already renewed it
// (stale differs), or renews proactively when the token is near expiry.
func (t *tokenSession) current(ctx context.Context, stale string) (string, bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.line != stale {
		return t.line, true, nil
	}
	if !t.nearExpiryLocked(time.Now()) {
		return t.line, false, nil
	}
	if t.proactive >= maxProactiveRenewals {
		return "", false, fmt.Errorf("token renewal limit reached")
	}
	t.proactive++
	if err := t.login(ctx); err != nil {
		return "", false, fmt.Errorf("token renewal failed")
	}
	return t.line, true, nil
}

// renewAfterFailure logs in again after a verification failure, unless
// another caller already did so.
func (t *tokenSession) renewAfterFailure(ctx context.Context, stale string) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.line != stale {
		return t.line, nil
	}
	if t.renewals >= maxSessionRenewals {
		return "", fmt.Errorf("authenticated session expired again after %d renewals; renewal limit reached", maxSessionRenewals)
	}
	t.renewals++
	if err := t.login(ctx); err != nil {
		return "", fmt.Errorf("authenticated session renewal failed")
	}
	return t.line, nil
}

// replaceHeaderLine swaps the token header in a header set, keeping others.
func replaceHeaderLine(lines []string, headerName, next string) ([]string, bool) {
	out := append([]string(nil), lines...)
	prefix := strings.ToLower(headerName) + ":"
	for i, line := range out {
		if strings.HasPrefix(strings.ToLower(line), prefix) {
			out[i] = next
			return out, true
		}
	}
	return out, false
}

func headerLineFor(lines []string, headerName string) string {
	prefix := strings.ToLower(headerName) + ":"
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), prefix) {
			return line
		}
	}
	return ""
}

// tokenTargetRefresher returns the session refresher for a target bound to a
// shared token login, or nil when the target has none. Renewal is shared: when
// one target renews, the others pick up the new token without logging in.
func tokenTargetRefresher(plan *scanner.AssessmentPlan, target assessment.Target, sessions map[string]*tokenSession) func(context.Context, []string) ([]string, error) {
	var session *tokenSession
	var verifyURL, marker string
	for _, binding := range plan.Config.Access {
		if binding.Kind != assessment.AccessTokenLogin || sessions[binding.CredentialID] == nil {
			continue
		}
		for _, id := range binding.TargetIDs {
			if id == target.ID {
				session, verifyURL, marker = sessions[binding.CredentialID], binding.VerifyURL, binding.VerifyMarker
			}
		}
	}
	if session == nil {
		return nil
	}
	verified := false
	for _, capability := range plan.Capabilities {
		if capability.Capability == assessment.CapAuthWeb && capability.TargetID == target.ID && capability.State == assessment.StateVerified {
			verified = true
		}
	}
	appURL := target.Value
	if verifyURL == "" {
		verifyURL = appURL
	}
	headerName := session.cfg.headerName
	check := func(ctx context.Context, lines []string) error {
		if marker != "" {
			return verifyHeaderSession(ctx, verifyURL, marker, lines, appURL)
		}
		positive, err := probeHeaderSession(ctx, verifyURL, "", lines, appURL)
		if err == nil {
			err = verifyAnonymousContrast(ctx, applicationScope(appURL), verifyURL, positive)
		}
		return err
	}
	return func(ctx context.Context, current []string) ([]string, error) {
		stale := headerLineFor(current, headerName)
		if stale == "" {
			return nil, fmt.Errorf("authenticated session token is missing")
		}
		line, changed, err := session.current(ctx, stale)
		if err != nil {
			return nil, err
		}
		if changed {
			next, _ := replaceHeaderLine(current, headerName, line)
			return next, nil
		}
		if !verified {
			// Access was never verified for this target, so there is no check
			// to repeat; expiry-driven renewal above still applies.
			return current, nil
		}
		if check(ctx, current) == nil {
			return current, nil
		}
		line, err = session.renewAfterFailure(ctx, stale)
		if err != nil {
			return nil, err
		}
		next, _ := replaceHeaderLine(current, headerName, line)
		if check(ctx, next) != nil {
			return nil, fmt.Errorf("authenticated session renewal could not be verified")
		}
		return next, nil
	}
}
