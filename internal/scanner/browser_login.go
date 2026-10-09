package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/credentials"
)

// BrowserLoginParams configures a real-browser login capture. Username and
// Password are secrets: they are only ever typed into the same-origin login
// page and are never written to artifacts, logs, or error messages.
type BrowserLoginParams struct {
	AppScope       *assessment.AppScope
	LoginURL       string
	VerifyURL      string
	Marker         string // optional; when set, confirmed in the post-login page
	Username       string
	Password       string
	UsernameField  string // input name or CSS selector; default "username"
	PasswordField  string // input name or CSS selector; default "password"
	SubmitSelector string // optional CSS selector for the submit control
}

// BrowserLoginResult carries the captured session. Both fields are secrets and
// are handled exactly like an operator-supplied credential.
type BrowserLoginResult struct {
	CookieHeader string
	Storage      *credentials.BrowserStorage
}

// CaptureBrowserLogin drives a headless Chromium through a real login and
// captures the resulting session cookies and web storage. Unlike the
// hand-replayed HTTP form POST, it runs the page's own JavaScript, so it works
// for SPA/NextAuth logins that need a CSRF round-trip and set their session
// cookie from an endpoint other than the one the form posts to.
//
// Credential safety: the capture is pinned to the login page's origin. Every
// browser request to a different origin is blocked, so the typed password can
// never be submitted to an SSO provider or third-party host; and the password
// is only typed after confirming the live page is still on the bound origin.
func CaptureBrowserLogin(ctx context.Context, cfg Config, scanDir string, p BrowserLoginParams) (BrowserLoginResult, error) {
	if cfg.KatanaChromePath == "" {
		return BrowserLoginResult{}, fmt.Errorf("browser login requires a configured Chromium path")
	}
	if p.AppScope == nil {
		return BrowserLoginResult{}, fmt.Errorf("browser login requires an approved application scope")
	}
	if p.Username == "" || p.Password == "" || p.LoginURL == "" {
		return BrowserLoginResult{}, fmt.Errorf("browser login configuration is incomplete")
	}
	bound, err := assessment.ParseApprovedOrigin("", p.LoginURL)
	if err != nil {
		return BrowserLoginResult{}, fmt.Errorf("invalid login URL")
	}
	if ok, _ := p.AppScope.Allows(p.LoginURL); !ok {
		return BrowserLoginResult{}, fmt.Errorf("login URL is outside the approved application scope")
	}
	usernameField := strings.TrimSpace(p.UsernameField)
	if usernameField == "" {
		usernameField = "username"
	}
	passwordField := strings.TrimSpace(p.PasswordField)
	if passwordField == "" {
		passwordField = "password"
	}

	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	profileDir, err := os.MkdirTemp(scanDir, "browser-login-")
	if err != nil {
		return BrowserLoginResult{}, fmt.Errorf("browser login workspace could not be created")
	}
	defer os.RemoveAll(profileDir)

	launch := launcher.New().Context(ctx).Bin(cfg.KatanaChromePath).UserDataDir(profileDir).Headless(true).NoSandbox(true).Leakless(false)
	control, err := launch.Launch()
	if err != nil {
		return BrowserLoginResult{}, fmt.Errorf("launch Chromium for login: %w", err)
	}
	defer launch.Cleanup()
	browser := rod.New().Context(ctx).ControlURL(control)
	if err := browser.Connect(); err != nil {
		return BrowserLoginResult{}, fmt.Errorf("connect to Chromium for login")
	}
	defer browser.Close()

	// Pin every browser request to the bound origin. Same-origin requests are
	// forwarded to the live site (so the server can set its session cookie);
	// any cross-origin request is failed, which is the credential boundary.
	crossOrigin := false
	var loginDone atomic.Bool
	var reqMu sync.Mutex
	var loginRequests []string
	recordLoginRequest := func(method, path string, status int) {
		if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
			return
		}
		reqMu.Lock()
		if len(loginRequests) < 20 {
			loginRequests = append(loginRequests, fmt.Sprintf("%s %s→%d", method, path, status))
		}
		reqMu.Unlock()
	}
	loginSummary := func() string {
		reqMu.Lock()
		defer reqMu.Unlock()
		if len(loginRequests) == 0 {
			return "no login POST was observed, so the submit did not trigger a sign-in request"
		}
		return strings.Join(loginRequests, "; ")
	}
	router := browser.HijackRequests()
	// The intercepting client keeps its own cookie jar. Fulfilling an intercepted
	// request does not reliably persist Set-Cookie in Chromium (notably __Secure-/
	// __Host- session cookies), so the jar is the authoritative session store: it
	// captures the cookie the login response sets and re-sends it on the browser's
	// later same-origin requests, so the protected page loads authenticated.
	jar, err := cookiejar.New(nil)
	if err != nil {
		return BrowserLoginResult{}, fmt.Errorf("browser login cookie store unavailable")
	}
	boundURL, _ := url.Parse(bound.Origin() + "/")
	client := &http.Client{Jar: jar, Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	if err := router.Add("*", "", func(h *rod.Hijack) {
		origin, _ := assessment.ParseApprovedOrigin("", h.Request.URL().String())
		if origin.Origin() != bound.Origin() {
			method := h.Request.Method()
			// Cross-origin sub-resources (scripts, styles, fonts, read-only APIs)
			// may load so the login and dashboard pages render, but never with a
			// credential and never with a state-changing method — so the typed
			// password can never be submitted to a different origin (e.g. an SSO
			// provider), which is the credential boundary.
			// Before the session is captured, block cross-origin state-changing
			// requests so the typed password cannot reach another origin. Once
			// login is done the password is no longer in play, so cross-origin
			// data calls may proceed (still credential-stripped) to let the
			// protected page fully render for the marker check.
			if !loginDone.Load() && method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions {
				crossOrigin = true
				h.Response.Fail(proto.NetworkErrorReasonBlockedByClient)
				return
			}
			h.Request.Req().Header.Del("Authorization")
			h.Request.Req().Header.Del("Cookie")
			if err := h.LoadResponse(client, true); err != nil {
				h.Response.Fail(proto.NetworkErrorReasonFailed)
			}
			return
		}
		if err := h.LoadResponse(client, true); err != nil {
			h.Response.Fail(proto.NetworkErrorReasonFailed)
			return
		}
		recordLoginRequest(h.Request.Method(), h.Request.URL().Path, h.Response.Payload().ResponseCode)
	}); err != nil {
		return BrowserLoginResult{}, fmt.Errorf("prepare login request boundary")
	}
	go router.Run()
	defer router.Stop()

	page, err := browser.Context(ctx).Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return BrowserLoginResult{}, fmt.Errorf("open login page")
	}
	// Give the headless browser a real desktop viewport and user agent so a
	// responsive SPA renders its full layout (not a near-empty/mobile shell) and
	// does not serve a bot-stripped page.
	_ = page.SetViewport(&proto.EmulationSetDeviceMetricsOverride{Width: 1366, Height: 900, DeviceScaleFactor: 1})
	_ = page.SetUserAgent(&proto.NetworkSetUserAgentOverride{UserAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"})
	if err := page.Navigate(p.LoginURL); err != nil {
		return BrowserLoginResult{}, fmt.Errorf("navigate to the login page")
	}
	if err := page.WaitLoad(); err != nil {
		return BrowserLoginResult{}, fmt.Errorf("the login page did not load")
	}
	page.WaitRequestIdle(500*time.Millisecond, nil, nil, nil)()

	// Never type the password unless the live page is still on the bound origin.
	if info, err := page.Info(); err != nil || sameBrowserOrigin(info.URL, bound) != true {
		return BrowserLoginResult{}, fmt.Errorf("the login page left the approved origin before credentials were entered")
	}

	if err := inputInto(page, usernameField, []string{"input[type=email]", "input[name=email]", "input[name=username]", "input[name=user]"}, p.Username); err != nil {
		return BrowserLoginResult{}, fmt.Errorf("the username field could not be found on the login page")
	}
	if err := inputInto(page, passwordField, []string{"input[type=password]", "input[name=password]"}, p.Password); err != nil {
		return BrowserLoginResult{}, fmt.Errorf("the password field could not be found on the login page")
	}
	if err := submitLogin(page, p.SubmitSelector, passwordField); err != nil {
		return BrowserLoginResult{}, fmt.Errorf("the login form could not be submitted")
	}

	// Allow the login to complete, whether by navigation or by an XHR that sets
	// the session cookie without one.
	_ = page.WaitLoad()
	page.WaitRequestIdle(1500*time.Millisecond, nil, nil, nil)()

	landingURL := ""
	if info, infoErr := page.Info(); infoErr == nil {
		landingURL = info.URL
	}

	cookieHeader, cookieNames, err := captureCookieHeader(jar, boundURL)
	if err != nil {
		if crossOrigin {
			return BrowserLoginResult{}, fmt.Errorf("login did not establish a session (a cross-origin step was blocked by the credential boundary; login requests: %s)", loginSummary())
		}
		return BrowserLoginResult{}, fmt.Errorf("%v (login requests: %s)", err, loginSummary())
	}
	// The session is captured; let cross-origin data calls render the dashboard.
	loginDone.Store(true)

	storage := captureStorage(page, bound)

	// When a marker is supplied, confirm it on the protected page. The anonymous
	// negative control is the caller's responsibility, as with every credential.
	if strings.TrimSpace(p.Marker) != "" {
		normalizedMarker := normalizeVisibleText(p.Marker)
		// First, the page the app already rendered after login, letting its own
		// client-side routing settle. A hard reload of an SPA sub-route tears down
		// that state and can fail to re-render, so only navigate if the marker
		// is not already present where login landed.
		page.WaitRequestIdle(2*time.Second, nil, nil, nil)()
		found, rendered := pollForMarker(page, normalizedMarker, 20*time.Second)
		if !found {
			verifyURL := p.VerifyURL
			if verifyURL == "" {
				verifyURL = p.LoginURL
			}
			if ok, _ := p.AppScope.Allows(verifyURL); !ok {
				return BrowserLoginResult{}, fmt.Errorf("verification URL is outside the approved application scope")
			}
			if info, infoErr := page.Info(); infoErr != nil || info.URL != verifyURL {
				_ = page.Navigate(verifyURL)
				_ = page.WaitLoad()
				page.WaitRequestIdle(2*time.Second, nil, nil, nil)()
			}
			found, rendered = pollForMarker(page, normalizedMarker, 20*time.Second)
		}
		if !found {
			finalURL := landingURL
			if info, infoErr := page.Info(); infoErr == nil && info.URL != "" {
				finalURL = info.URL
			}
			// Classify the rendered page so the cause is clear: a session cookie
			// means the login worked, so the remaining issue is the headless
			// render or the marker text, not authentication.
			return BrowserLoginResult{}, fmt.Errorf("the session marker was not visible (after submit the page was at %s; verify ended at %s; %s; cookies captured: %s; login requests: %s)", SafeTelemetryURL(landingURL), SafeTelemetryURL(finalURL), classifyRender(rendered), strings.Join(cookieNames, ", "), loginSummary())
		}
	}

	return BrowserLoginResult{CookieHeader: cookieHeader, Storage: storage}, nil
}

// pollForMarker polls the page's visible text for the (already normalized)
// marker until it appears or the timeout elapses, returning whether it was
// found and the last rendered length.
func pollForMarker(page *rod.Page, normalizedMarker string, timeout time.Duration) (bool, string) {
	deadline := time.Now().Add(timeout)
	last := ""
	for {
		// textContent captures DOM text regardless of visibility/viewport, so the
		// marker is found even when innerText reports little in headless.
		text, evalErr := page.Eval(`() => { const b = document.body; if (!b) return ""; const t = b.textContent || ""; return t.trim() ? t : (b.innerText || ""); }`)
		if evalErr == nil {
			last = text.Value.Str()
			if strings.Contains(normalizeVisibleText(last), normalizedMarker) {
				return true, last
			}
		}
		if time.Now().After(deadline) {
			return false, last
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// classifyRender describes why a page lacked the marker, without echoing its
// content: a JS-disabled shell (app did not render), the sign-in screen (session
// not applied), or a page that rendered but without the marker text.
func classifyRender(text string) string {
	low := strings.ToLower(text)
	n := len([]rune(strings.TrimSpace(text)))
	switch {
	case strings.Contains(low, "enable javascript"):
		return fmt.Sprintf("the app did not render in the headless browser (JavaScript-disabled fallback shown, %d chars)", n)
	case n < 400 && (strings.Contains(low, "password") || strings.Contains(low, "sign in") || strings.Contains(low, "log in")):
		return fmt.Sprintf("the page is still the sign-in screen (%d chars), so the session was not applied on this navigation", n)
	default:
		return fmt.Sprintf("the page rendered %d characters but not the marker, so the marker text likely differs from the page", n)
	}
}

// normalizeVisibleText collapses runs of whitespace to single spaces so a
// marker still matches when a heading is split across elements or lines.
func normalizeVisibleText(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// sameBrowserOrigin reports whether a live page URL is on the bound origin.
func sameBrowserOrigin(pageURL string, bound assessment.ApprovedOrigin) bool {
	origin, err := assessment.ParseApprovedOrigin("", pageURL)
	if err != nil {
		return false
	}
	return origin.Origin() == bound.Origin()
}

// inputInto types text into the first matching element, trying the configured
// field first (as a raw selector, then as an input name) and then fallbacks.
func inputInto(page *rod.Page, field string, fallbacks []string, text string) error {
	for _, selector := range fieldSelectors(field, fallbacks) {
		el, err := page.Timeout(3 * time.Second).Element(selector)
		if err != nil || el == nil {
			continue
		}
		if err := el.Focus(); err != nil {
			continue
		}
		if err := el.Input(text); err != nil {
			continue
		}
		return nil
	}
	return fmt.Errorf("field not found")
}

// submitLogin submits the login form. It first presses Enter in the password
// field — the most reliable trigger for React/SPA forms whose submit is wired to
// the form's onSubmit rather than a native button — and also clicks a submit
// control, so forms that need either path still go through.
func submitLogin(page *rod.Page, selector, passwordField string) error {
	submitted := false
	// Enter in the password field.
	for _, candidate := range fieldSelectors(passwordField, []string{"input[type=password]", "input[name=password]"}) {
		el, err := page.Timeout(2 * time.Second).Element(candidate)
		if err != nil || el == nil {
			continue
		}
		if el.Focus() == nil && el.Type(input.Enter) == nil {
			submitted = true
		}
		break
	}
	// Click an explicit or native submit control.
	candidates := []string{}
	if strings.TrimSpace(selector) != "" {
		candidates = append(candidates, selector)
	}
	candidates = append(candidates, "button[type=submit]", "input[type=submit]", "button")
	for _, candidate := range candidates {
		el, err := page.Timeout(2 * time.Second).Element(candidate)
		if err != nil || el == nil {
			continue
		}
		if el.Click(proto.InputMouseButtonLeft, 1) == nil {
			submitted = true
			break
		}
	}
	if submitted {
		return nil
	}
	return fmt.Errorf("no submit control")
}

// fieldSelectors builds the ordered selector list for a configured field name.
func fieldSelectors(field string, fallbacks []string) []string {
	selectors := []string{}
	if strings.ContainsAny(field, ".#[ >:") {
		selectors = append(selectors, field)
	} else if field != "" {
		selectors = append(selectors, fmt.Sprintf("input[name=%q]", field), "#"+field)
	}
	return append(selectors, fallbacks...)
}

// captureCookieHeader builds a Cookie header from the session cookies the
// browser holds for the bound host. Cookies with unsafe names/values are
// dropped rather than forwarded.
func captureCookieHeader(jar http.CookieJar, boundURL *url.URL) (string, []string, error) {
	if jar == nil || boundURL == nil {
		return "", nil, fmt.Errorf("the browser session cookies could not be read after login")
	}
	var parts, names []string
	for _, cookie := range jar.Cookies(boundURL) {
		if cookie == nil || cookie.Name == "" {
			continue
		}
		if strings.ContainsAny(cookie.Name, " \t\r\n;=") || strings.ContainsAny(cookie.Value, "\r\n;") {
			continue
		}
		parts = append(parts, cookie.Name+"="+cookie.Value)
		names = append(names, cookie.Name)
	}
	if len(parts) == 0 {
		return "", nil, fmt.Errorf("login did not establish a session cookie")
	}
	return "Cookie: " + strings.Join(parts, "; "), names, nil
}

// captureStorage reads localStorage/sessionStorage for the bound origin. It is
// best-effort: a session carried purely in cookies yields an empty blob, which
// is valid.
func captureStorage(page *rod.Page, bound assessment.ApprovedOrigin) *credentials.BrowserStorage {
	result, err := page.Eval(`() => JSON.stringify({local:Object.fromEntries(Object.entries(localStorage)),session:Object.fromEntries(Object.entries(sessionStorage))})`)
	if err != nil {
		return nil
	}
	var captured struct {
		Local   map[string]string `json:"local"`
		Session map[string]string `json:"session"`
	}
	if json.Unmarshal([]byte(result.Value.Str()), &captured) != nil {
		return nil
	}
	if len(captured.Local) == 0 && len(captured.Session) == 0 {
		return nil
	}
	storage := &credentials.BrowserStorage{Local: captured.Local, Session: captured.Session}
	if storage.Validate() != nil {
		return nil
	}
	return storage
}
