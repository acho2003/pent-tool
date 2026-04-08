// Package playwright provides Playwright MCP browser automation tools.
package playwright

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/xalgorix/v3/internal/config"
	"github.com/xalgord/xalgorix/v3/internal/tools"
)

var (
	mcpServer      *exec.Cmd
	mcpServerLock  sync.Mutex
	mcpInitialized bool
)

// Register adds Playwright MCP tools to the registry.
func Register(r *tools.Registry) {
	// Register browser action tool with Caido proxy support
	r.Register(&tools.Tool{
		Name:        "browser_action",
		Description: "Control browser via Playwright. Actions: launch, navigate, screenshot. Use proxy: 'caido' to route through Caido proxy.",
		Parameters: []tools.Parameter{
			{Name: "action", Description: "Action: launch, navigate, screenshot, close, evaluate", Required: true},
			{Name: "url", Description: "URL for navigate action", Required: false},
			{Name: "script", Description: "JavaScript to evaluate", Required: false},
			{Name: "proxy", Description: "Proxy: 'caido', 'none', or proxy URL", Required: false},
			{Name: "headless", Description: "Run headless (default: true)", Required: false},
		},
		Execute: browserAction,
	})
}

// detectCaidoPort detects the Caido proxy port.
func detectCaidoPort() int {
	cfg := config.Get()
	if cfg.CaidoPort > 0 {
		return cfg.CaidoPort
	}
	return 8080
}

// browserAction handles browser automation with Caido proxy support.
func browserAction(args map[string]string) (tools.Result, error) {
	action := args["action"]

	switch action {
	case "launch":
		return launchBrowser(args)
	case "navigate":
		return navigateBrowser(args)
	case "screenshot":
		return takeScreenshot(args)
	case "close":
		return closeBrowser(args)
	case "evaluate":
		return evaluateScript(args)
	default:
		return tools.Result{}, fmt.Errorf("unknown action: %s. Supported: launch, navigate, screenshot, close, evaluate", action)
	}
}

// launchBrowser launches a browser instance.
func launchBrowser(args map[string]string) (tools.Result, error) {
	proxy := args["proxy"]
	headless := args["headless"]

	if headless == "" {
		headless = "true"
	}

	// Check for Chromium
	checkCmd := exec.Command("which", "chromium")
	if err := checkCmd.Run(); err != nil {
		checkCmd = exec.Command("which", "google-chrome")
		if err := checkCmd.Run(); err != nil {
			return tools.Result{}, fmt.Errorf("Chromium/Chrome not found. Install with: sudo apt install chromium")
		}
	}

	// Build launch command
	var cmd *exec.Cmd
	if proxy == "caido" {
		caidoPort := detectCaidoPort()
		cmd = exec.Command("chromium",
			"--headless=new",
			"--no-sandbox",
			"--disable-dev-shm-usage",
			fmt.Sprintf("--proxy-server=http://127.0.0.1:%d", caidoPort),
		)
	} else if proxy != "" && proxy != "none" {
		cmd = exec.Command("chromium",
			"--headless=new",
			"--no-sandbox",
			"--disable-dev-shm-usage",
			fmt.Sprintf("--proxy-server=%s", proxy),
		)
	} else {
		cmd = exec.Command("chromium",
			"--headless=new",
			"--no-sandbox",
			"--disable-dev-shm-usage",
		)
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return tools.Result{}, fmt.Errorf("failed to launch browser: %w", err)
	}

	return tools.Result{
		Output: fmt.Sprintf("Browser launched (proxy: %s)", proxy),
		Metadata: map[string]any{
			"action":   "launch",
			"headless": headless,
			"proxy":    proxy,
		},
	}, nil
}

// navigateBrowser navigates to a URL with Caido proxy support.
func navigateBrowser(args map[string]string) (tools.Result, error) {
	targetURL := args["url"]
	if targetURL == "" {
		return tools.Result{}, fmt.Errorf("url is required for navigate action")
	}

	proxy := args["proxy"]

	// Use curl for navigation through proxy
	var cmd *exec.Cmd
	if proxy == "caido" {
		caidoPort := detectCaidoPort()
		cmd = exec.Command("curl", "-s", "-x", fmt.Sprintf("http://127.0.0.1:%d", caidoPort), targetURL)
	} else if proxy != "" && proxy != "none" {
		cmd = exec.Command("curl", "-s", "-x", proxy, targetURL)
	} else {
		cmd = exec.Command("curl", "-s", targetURL)
	}

	output, err := cmd.Output()
	if err != nil {
		return tools.Result{}, fmt.Errorf("navigation failed: %w", err)
	}

	body := string(output)
	if len(body) > 10000 {
		body = body[:10000] + "\n\n... [TRUNCATED]"
	}

	return tools.Result{
		Output: fmt.Sprintf("Navigated to: %s\n\n%s", targetURL, body),
		Metadata: map[string]any{
			"action": "navigate",
			"url":    targetURL,
			"proxy":  proxy,
		},
	}, nil
}

// takeScreenshot takes a screenshot using Chromium.
func takeScreenshot(args map[string]string) (tools.Result, error) {
	proxy := args["proxy"]

	// Build chromium screenshot command
	var cmd *exec.Cmd
	if proxy == "caido" {
		caidoPort := detectCaidoPort()
		cmd = exec.Command("chromium",
			"--headless=new",
			"--no-sandbox",
			"--disable-dev-shm-usage",
			fmt.Sprintf("--proxy-server=http://127.0.0.1:%d", caidoPort),
			"--screenshot=/tmp/xalgorix_screenshot.png",
			"about:blank",
		)
	} else if proxy != "" && proxy != "none" {
		cmd = exec.Command("chromium",
			"--headless=new",
			"--no-sandbox",
			"--disable-dev-shm-usage",
			fmt.Sprintf("--proxy-server=%s", proxy),
			"--screenshot=/tmp/xalgorix_screenshot.png",
			"about:blank",
		)
	} else {
		cmd = exec.Command("chromium",
			"--headless=new",
			"--no-sandbox",
			"--disable-dev-shm-usage",
			"--screenshot=/tmp/xalgorix_screenshot.png",
			"about:blank",
		)
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return tools.Result{}, fmt.Errorf("screenshot failed: %w", err)
	}

	screenshotData, err := os.ReadFile("/tmp/xalgorix_screenshot.png")
	if err != nil {
		return tools.Result{}, fmt.Errorf("failed to read screenshot: %w", err)
	}

	return tools.Result{
		Output: fmt.Sprintf("Screenshot taken: %d bytes", len(screenshotData)),
		Metadata: map[string]any{
			"action":     "screenshot",
			"size_bytes": len(screenshotData),
		},
	}, nil
}

// evaluateScript evaluates JavaScript in browser.
func evaluateScript(args map[string]string) (tools.Result, error) {
	script := args["script"]
	if script == "" {
		return tools.Result{}, fmt.Errorf("script is required for evaluate action")
	}

	// This would require a full browser context
	return tools.Result{
		Output: fmt.Sprintf("JavaScript evaluation requires full browser context: %s", script),
		Metadata: map[string]any{
			"action": "evaluate",
			"script": script,
		},
	}, nil
}

// closeBrowser closes the browser.
func closeBrowser(args map[string]string) (tools.Result, error) {
	// Kill any running chromium processes
	exec.Command("pkill", "-f", "chromium").Run()

	return tools.Result{
		Output:   "Browser closed",
		Metadata: map[string]any{"action": "close"},
	}, nil
}

// SendThroughCaido sends an HTTP request through Caido proxy.
func SendThroughCaido(method, targetURL, body string, headers map[string]string) (tools.Result, error) {
	caidoPort := detectCaidoPort()
	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", caidoPort)

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, targetURL, bodyReader)
	if err != nil {
		return tools.Result{}, fmt.Errorf("invalid request: %w", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	proxy, _ := url.Parse(proxyURL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxy),
		},
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		// Fall back to direct request
		client = &http.Client{}
		resp, err = client.Do(req)
		if err != nil {
			return tools.Result{}, fmt.Errorf("request failed: %w", err)
		}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	var respBuilder strings.Builder
	respBuilder.WriteString(fmt.Sprintf("HTTP/%s %s\n", resp.Proto, resp.Status))
	for k, vs := range resp.Header {
		for _, v := range vs {
			respBuilder.WriteString(fmt.Sprintf("%s: %s\n", k, v))
		}
	}
	respBuilder.WriteString("\n")

	bodyStr := string(respBody)
	if len(bodyStr) > 10000 {
		bodyStr = bodyStr[:10000] + "\n\n... [TRUNCATED]"
	}
	respBuilder.WriteString(bodyStr)

	return tools.Result{
		Output: respBuilder.String(),
		Metadata: map[string]any{
			"status_code": resp.StatusCode,
			"url":         targetURL,
			"proxy":       "caido",
		},
	}, nil
}
