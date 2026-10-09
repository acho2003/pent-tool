package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
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
	router := browser.HijackRequests()
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	if err := router.Add("*", "", func(h *rod.Hijack) {
		origin, _ := assessment.ParseApprovedOrigin("", h.Request.URL().String())
		if origin.Origin() != bound.Origin() {
			method := h.Request.Method()
			// Cross-origin sub-resources (scripts, styles, fonts, read-only APIs)
			// may load so the login and dashboard pages render, but never with a
			// credential and never with a state-changing method — so the typed
			// password can never be submitted to a different origin (e.g. an SSO
			// provider), which is the credential boundary.
			if method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions {
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
		}
	}); err != nil {
		return BrowserLoginResult{}, fmt.Errorf("prepare login request boundary")
	}
	go router.Run()
	defer router.Stop()

	page, err := browser.Context(ctx).Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return BrowserLoginResult{}, fmt.Errorf("open login page")
	}
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
	if err := submitLogin(page, p.SubmitSelector); err != nil {
		return BrowserLoginResult{}, fmt.Errorf("the login form could not be submitted")
	}

	// Allow the login to complete, whether by navigation or by an XHR that sets
	// the session cookie without one.
	_ = page.WaitLoad()
	page.WaitRequestIdle(1500*time.Millisecond, nil, nil, nil)()

	cookieHeader, err := captureCookieHeader(page, bound)
	if err != nil {
		if crossOrigin {
			return BrowserLoginResult{}, fmt.Errorf("login did not establish a session (a cross-origin step was blocked by the credential boundary)")
		}
		return BrowserLoginResult{}, err
	}

	storage := captureStorage(page, bound)

	// When a marker is supplied, confirm it on the protected page. The anonymous
	// negative control is the caller's responsibility, as with every credential.
	if strings.TrimSpace(p.Marker) != "" {
		verifyURL := p.VerifyURL
		if verifyURL == "" {
			verifyURL = p.LoginURL
		}
		if ok, _ := p.AppScope.Allows(verifyURL); !ok {
			return BrowserLoginResult{}, fmt.Errorf("verification URL is outside the approved application scope")
		}
		// A single-page app often satisfies this navigation with client-side
		// routing, which surfaces as a benign ERR_ABORTED from Navigate/WaitLoad;
		// the authoritative signal is whether the marker renders, so poll for it
		// rather than treating those errors as fatal.
		_ = page.Navigate(verifyURL)
		_ = page.WaitLoad()
		page.WaitRequestIdle(2*time.Second, nil, nil, nil)()
		normalizedMarker := normalizeVisibleText(p.Marker)
		found := false
		lastLen := 0
		deadline := time.Now().Add(25 * time.Second)
		for {
			text, evalErr := page.Eval(`() => document.body ? document.body.innerText : ""`)
			if evalErr == nil {
				rendered := text.Value.Str()
				lastLen = len([]rune(rendered))
				// Whitespace-tolerant match: a heading split across elements comes
				// back with newlines/extra spaces between the words.
				if strings.Contains(normalizeVisibleText(rendered), normalizedMarker) {
					found = true
					break
				}
			}
			if time.Now().After(deadline) {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if !found {
			finalURL := verifyURL
			if info, infoErr := page.Info(); infoErr == nil && info.URL != "" {
				finalURL = info.URL
			}
			return BrowserLoginResult{}, fmt.Errorf("logged in, but the response marker was not visible on the protected page (ended at %s, %d characters rendered)", SafeTelemetryURL(finalURL), lastLen)
		}
	}

	return BrowserLoginResult{CookieHeader: cookieHeader, Storage: storage}, nil
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
	selectors := []string{}
	if strings.ContainsAny(field, ".#[ >:") {
		selectors = append(selectors, field)
	} else if field != "" {
		selectors = append(selectors, fmt.Sprintf("input[name=%q]", field), "#"+field)
	}
	selectors = append(selectors, fallbacks...)
	for _, selector := range selectors {
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

// submitLogin clicks the submit control, or presses Enter as a fallback so a
// form without an explicit button still submits.
func submitLogin(page *rod.Page, selector string) error {
	candidates := []string{}
	if strings.TrimSpace(selector) != "" {
		candidates = append(candidates, selector)
	}
	candidates = append(candidates, "button[type=submit]", "input[type=submit]", "button")
	for _, candidate := range candidates {
		el, err := page.Timeout(3 * time.Second).Element(candidate)
		if err != nil || el == nil {
			continue
		}
		if err := el.Click(proto.InputMouseButtonLeft, 1); err != nil {
			continue
		}
		return nil
	}
	if page.Keyboard != nil {
		return page.Keyboard.Press(input.Enter)
	}
	return fmt.Errorf("no submit control")
}

// captureCookieHeader builds a Cookie header from the session cookies the
// browser holds for the bound host. Cookies with unsafe names/values are
// dropped rather than forwarded.
func captureCookieHeader(page *rod.Page, bound assessment.ApprovedOrigin) (string, error) {
	cookies, err := page.Cookies([]string{bound.Origin() + "/"})
	if err != nil {
		return "", fmt.Errorf("the browser session cookies could not be read after login")
	}
	var parts []string
	for _, cookie := range cookies {
		if cookie == nil || cookie.Name == "" {
			continue
		}
		if strings.ContainsAny(cookie.Name, " \t\r\n;=") || strings.ContainsAny(cookie.Value, "\r\n;") {
			continue
		}
		parts = append(parts, cookie.Name+"="+cookie.Value)
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("login did not establish a session cookie")
	}
	return "Cookie: " + strings.Join(parts, "; "), nil
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
