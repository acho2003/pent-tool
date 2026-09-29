package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// verifyFormSession logs into one explicitly scoped application and returns
// only the session cookie header. The encrypted username/password never enter
// a scan artifact, ZAP command, event, or assessment plan.
func verifyFormSession(ctx context.Context, appURL, verifyURL, marker string, values map[string]string) (string, error) {
	loginURL := strings.TrimSpace(values["login_url"])
	username := values["username"]
	password := values["password"]
	usernameField := strings.TrimSpace(values["username_field"])
	passwordField := strings.TrimSpace(values["password_field"])
	csrfField := strings.TrimSpace(values["csrf_field"])
	if usernameField == "" {
		usernameField = "username"
	}
	if passwordField == "" {
		passwordField = "password"
	}
	if loginURL == "" || username == "" || password == "" || marker == "" || len(marker) > 256 || strings.ContainsAny(marker, "\r\n\x00") || !validHTTPHeaderName(usernameField) || !validHTTPHeaderName(passwordField) || (csrfField != "" && !validHTTPHeaderName(csrfField)) {
		return "", fmt.Errorf("form login configuration is incomplete or invalid")
	}
	if !urlWithinApplication(appURL, loginURL) || !urlWithinApplication(appURL, verifyURL) {
		return "", fmt.Errorf("form login or verification URL is outside the application boundary")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", fmt.Errorf("create isolated login cookie jar")
	}
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || !urlWithinApplication(appURL, req.URL.String()) {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	loginRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, loginURL, nil)
	if err != nil {
		return "", fmt.Errorf("invalid form login URL")
	}
	loginResponse, err := client.Do(loginRequest)
	if err != nil {
		return "", fmt.Errorf("form login page request failed")
	}
	page, readErr := io.ReadAll(io.LimitReader(loginResponse.Body, 1<<20))
	loginResponse.Body.Close()
	if readErr != nil || loginResponse.StatusCode < 200 || loginResponse.StatusCode >= 300 {
		return "", fmt.Errorf("form login page could not be read")
	}
	action, fields, err := loginForm(page, loginURL, appURL, usernameField, passwordField, csrfField)
	if err != nil {
		return "", err
	}
	fields.Set(usernameField, username)
	fields.Set(passwordField, password)
	postRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, action, strings.NewReader(fields.Encode()))
	if err != nil {
		return "", fmt.Errorf("invalid form action")
	}
	postRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postResponse, err := client.Do(postRequest)
	if err != nil {
		return "", fmt.Errorf("form login request failed")
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(postResponse.Body, 1<<20))
	postResponse.Body.Close()
	if postResponse.StatusCode < 200 || postResponse.StatusCode >= 300 {
		return "", fmt.Errorf("form login was rejected")
	}
	verifyRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, verifyURL, nil)
	if err != nil {
		return "", fmt.Errorf("invalid verification URL")
	}
	verifyResponse, err := client.Do(verifyRequest)
	if err != nil {
		return "", fmt.Errorf("form session verification failed")
	}
	verificationBody, readErr := io.ReadAll(io.LimitReader(verifyResponse.Body, 1<<20))
	verifyResponse.Body.Close()
	if readErr != nil || verifyResponse.StatusCode < 200 || verifyResponse.StatusCode >= 300 || !strings.Contains(string(verificationBody), marker) {
		return "", fmt.Errorf("form session verification marker was not found")
	}
	verifyParsed, _ := url.Parse(verifyURL)
	cookies := jar.Cookies(verifyParsed)
	if len(cookies) == 0 {
		return "", fmt.Errorf("form login produced no usable session cookie")
	}
	parts := make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		if !validHTTPHeaderName(cookie.Name) || hasUnsafeHeaderValue(cookie.Value) {
			return "", fmt.Errorf("form login produced an invalid session cookie")
		}
		parts = append(parts, cookie.Name+"="+cookie.Value)
	}
	return "Cookie: " + strings.Join(parts, "; "), nil
}

func loginForm(page []byte, loginURL, appURL, usernameField, passwordField, csrfField string) (string, url.Values, error) {
	doc, err := html.Parse(strings.NewReader(string(page)))
	if err != nil {
		return "", nil, fmt.Errorf("login page HTML could not be parsed")
	}
	base, _ := url.Parse(loginURL)
	var walk func(*html.Node) (string, url.Values, bool)
	walk = func(node *html.Node) (string, url.Values, bool) {
		if node.Type == html.ElementNode && node.Data == "form" {
			method := strings.ToLower(nodeAttr(node, "method"))
			if method == "" || method == "post" {
				action := nodeAttr(node, "action")
				if action == "" {
					action = loginURL
				} else if parsed, parseErr := url.Parse(action); parseErr == nil {
					action = base.ResolveReference(parsed).String()
				}
				if !urlWithinApplication(appURL, action) {
					return "", nil, false
				}
				fields := url.Values{}
				foundUser, foundPassword, foundCSRF := false, false, csrfField == ""
				var collect func(*html.Node)
				collect = func(child *html.Node) {
					if child.Type == html.ElementNode && child.Data == "input" {
						name := nodeAttr(child, "name")
						typ := strings.ToLower(nodeAttr(child, "type"))
						if name == usernameField {
							foundUser = true
						}
						if name == passwordField {
							foundPassword = true
						}
						if name == csrfField && typ == "hidden" {
							foundCSRF = true
						}
						if typ == "hidden" && len(fields) < 32 {
							fields.Set(name, nodeAttr(child, "value"))
						}
					}
					for next := child.FirstChild; next != nil; next = next.NextSibling {
						collect(next)
					}
				}
				collect(node)
				if foundUser && foundPassword && foundCSRF && len(fields.Encode()) <= 4096 {
					return action, fields, true
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			if action, fields, ok := walk(child); ok {
				return action, fields, true
			}
		}
		return "", nil, false
	}
	if action, fields, ok := walk(doc); ok {
		return action, fields, nil
	}
	return "", nil, fmt.Errorf("no in-scope login form with required fields was found")
}

func nodeAttr(node *html.Node, key string) string {
	for _, attribute := range node.Attr {
		if attribute.Key == key {
			return attribute.Val
		}
	}
	return ""
}
