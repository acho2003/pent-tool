// Package httpclient provides a structured HTTP client tool for the agent.
// Unlike raw terminal curl, this tool returns structured output (status code,
// headers, body) that the LLM can reason about precisely. It respects the
// global proxy and TLS-skip-verify configuration.
package httpclient

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/proxy"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

const maxBodyBytes = 50 * 1024 // 50 KB — keep context window manageable

// Register adds the http_request tool to the registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name: "http_request",
		Description: "Make a structured HTTP request. Use this instead of terminal curl/wget for any HTTP call — it returns status code, response headers, and body in a clean format the agent can reason about. Perfect for: API testing, auth bypass attempts, JWT manipulation, SSRF probing, parameter fuzzing, cookie inspection, redirect chain analysis, and any HTTP-based recon.",
		Parameters: []tools.Parameter{
			{Name: "url", Description: "Target URL (include protocol, e.g. https://example.com/api/users)", Required: true},
			{Name: "method", Description: "HTTP method: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS (default: GET)", Required: false},
			{Name: "headers", Description: `JSON object of request headers, e.g. {"Authorization":"Bearer eyJ...","Content-Type":"application/json"}`, Required: false},
			{Name: "body", Description: "Request body (for POST/PUT/PATCH). Pass the raw string to send.", Required: false},
			{Name: "follow_redirects", Description: "Follow HTTP redirects (default: true). Set to false to inspect 3xx responses directly — useful for open redirect and SSRF testing.", Required: false},
			{Name: "timeout", Description: "Request timeout in seconds (default: 30, max: 60)", Required: false},
		},
		Execute: execute,
	})
}

func execute(args map[string]string) (tools.Result, error) {
	targetURL := strings.TrimSpace(args["url"])
	if targetURL == "" {
		return tools.Result{}, fmt.Errorf("url is required")
	}
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	method := strings.ToUpper(strings.TrimSpace(args["method"]))
	if method == "" {
		method = "GET"
	}
	if !validMethod(method) {
		return tools.Result{}, fmt.Errorf("invalid HTTP method: %s", method)
	}

	timeout := 30
	if s := strings.TrimSpace(args["timeout"]); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			timeout = n
			if timeout > 60 {
				timeout = 60
			}
		}
	}

	followRedirects := true
	if s := strings.TrimSpace(args["follow_redirects"]); s != "" {
		switch strings.ToLower(s) {
		case "false", "0", "no", "off":
			followRedirects = false
		}
	}

	var bodyReader io.Reader
	if body := strings.TrimSpace(args["body"]); body != "" {
		bodyReader = strings.NewReader(body)
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return tools.Result{}, fmt.Errorf("invalid URL %q: %w", targetURL, err)
	}
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "https"
	}

	req, err := http.NewRequest(method, parsedURL.String(), bodyReader)
	if err != nil {
		return tools.Result{}, fmt.Errorf("failed to create request: %w", err)
	}

	// Parse and set custom headers.
	headersStr := strings.TrimSpace(args["headers"])
	if headersStr != "" {
		var hdrs map[string]string
		if err := json.Unmarshal([]byte(headersStr), &hdrs); err != nil {
			return tools.Result{}, fmt.Errorf("invalid headers JSON: %w", err)
		}
		for k, v := range hdrs {
			req.Header.Set(k, v)
		}
	}

	// Set default User-Agent if caller didn't provide one.
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	}

	client := buildClient(timeout, followRedirects)

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return tools.Result{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	elapsed := time.Since(start)

	var out strings.Builder
	out.WriteString(fmt.Sprintf("%s %s\n", resp.Proto, resp.Status))
	out.WriteString(fmt.Sprintf("Request-Time: %.0fms\n\n", float64(elapsed.Microseconds())/1000))

	// Print response headers in a readable format.
	out.WriteString("--- Response Headers ---\n")
	for k, vals := range resp.Header {
		for _, v := range vals {
			out.WriteString(fmt.Sprintf("%s: %s\n", k, v))
		}
	}

	// Read body (capped).
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return tools.Result{}, fmt.Errorf("failed to read response body: %w", err)
	}
	truncated := len(bodyBytes) > maxBodyBytes
	if truncated {
		bodyBytes = bodyBytes[:maxBodyBytes]
	}

	contentType := resp.Header.Get("Content-Type")
	isBinary := isBinaryContentType(contentType)

	out.WriteString(fmt.Sprintf("\n--- Response Body%s ---\n", map[bool]string{true: " (text)", false: ""}[!isBinary]))
	if isBinary {
		out.WriteString(fmt.Sprintf("[binary content: %s, %d bytes]\n", contentType, len(bodyBytes)))
	} else {
		out.WriteString(string(bodyBytes))
		if truncated {
			out.WriteString("\n\n[Body truncated at 50 KB]")
		}
	}

	return tools.Result{Output: out.String()}, nil
}

func validMethod(m string) bool {
	switch m {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
		return true
	}
	return false
}

func isBinaryContentType(ct string) bool {
	ct = strings.ToLower(ct)
	binaryPrefixes := []string{
		"image/", "audio/", "video/", "application/octet-stream",
		"application/zip", "application/gzip", "application/pdf",
		"application/vnd.", "font/",
	}
	for _, p := range binaryPrefixes {
		if strings.HasPrefix(ct, p) {
			return true
		}
	}
	return false
}

func buildClient(timeoutSec int, followRedirects bool) *http.Client {
	cfg := config.Get()

	tr := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.TLSSkipVerify {
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{} //nolint:gosec
		} else {
			tr.TLSClientConfig = tr.TLSClientConfig.Clone()
		}
		tr.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec
	}

	// Apply proxy when enabled.
	if proxy.Enabled() {
		if p := proxy.GetProxy(); p != nil {
			if proxyURL, err := p.URL(); err == nil {
				tr.Proxy = http.ProxyURL(proxyURL)
			}
		}
	}

	c := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(timeoutSec) * time.Second,
	}

	if !followRedirects {
		c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return c
}
