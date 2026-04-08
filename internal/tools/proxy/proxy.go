// Package proxy provides Caido proxy integration tools.
package proxy

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v3/internal/config"
	"github.com/xalgord/xalgorix/v3/internal/tools"
)

// Register adds proxy tools to the registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name:        "send_request",
		Description: "Send an HTTP request through the Caido proxy. Falls back to direct request if Caido is unavailable.",
		Parameters: []tools.Parameter{
			{Name: "method", Description: "HTTP method (GET, POST, PUT, DELETE, etc.)", Required: true},
			{Name: "url", Description: "Target URL", Required: true},
			{Name: "headers", Description: "Request headers as JSON object", Required: false},
			{Name: "body", Description: "Request body", Required: false},
		},
		Execute: sendRequest,
	})

	r.Register(&tools.Tool{
		Name:        "list_requests",
		Description: "List HTTP requests captured by Caido proxy.",
		Parameters: []tools.Parameter{
			{Name: "count", Description: "Number of requests to list (default: 20)", Required: false},
			{Name: "filter", Description: "Filter by URL substring", Required: false},
		},
		Execute: listRequests,
	})
}

func detectCaidoPort() int {
	cfg := config.Get()
	if cfg.CaidoPort > 0 {
		return cfg.CaidoPort
	}

	// Check if Caido is running by looking for its process
	out, err := exec.Command("ss", "-tlnp").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			// Only match lines that explicitly contain "caido" in the process name
			if strings.Contains(strings.ToLower(line), "caido") {
				parts := strings.Fields(line)
				for _, p := range parts {
					if strings.Contains(p, ":") {
						addr := strings.Split(p, ":")
						if port, err := strconv.Atoi(addr[len(addr)-1]); err == nil && port > 0 {
							return port
						}
					}
				}
			}
		}
	}

	// Try common Caido ports with a short timeout
	checkClient := &http.Client{Timeout: 2 * time.Second}
	for _, port := range []int{8080, 8081, 9090} {
		resp, err := checkClient.Get(fmt.Sprintf("http://127.0.0.1:%d", port))
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return port
			}
		}
	}

	return 8080
}


func getCaidoGraphQLURL() string {
	port := detectCaidoPort()
	return fmt.Sprintf("http://127.0.0.1:%d/graphql", port)
}

func sendRequest(args map[string]string) (tools.Result, error) {
	method := strings.ToUpper(args["method"])
	targetURL := args["url"]

	var bodyReader io.Reader
	if body := args["body"]; body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, targetURL, bodyReader)
	if err != nil {
		return tools.Result{}, fmt.Errorf("invalid request: %w", err)
	}

	if headersJSON := args["headers"]; headersJSON != "" {
		var headers map[string]string
		if err := json.Unmarshal([]byte(headersJSON), &headers); err == nil {
			for k, v := range headers {
				req.Header.Set(k, v)
			}
		}
	}

	caidoPort := detectCaidoPort()
	usedProxy := false

	// Check if Caido is accessible with a short timeout
	checkClient := &http.Client{Timeout: 3 * time.Second}
	checkResp, checkErr := checkClient.Get(fmt.Sprintf("http://127.0.0.1:%d", caidoPort))
	if checkResp != nil {
		checkResp.Body.Close()
	}

	var client *http.Client
	if checkErr == nil && checkResp != nil && checkResp.StatusCode < 500 {
		// Caido is running — route through proxy
		proxyURLStr := fmt.Sprintf("http://127.0.0.1:%d", caidoPort)
		proxyURL, err := url.Parse(proxyURLStr)
		if err != nil {
			log.Printf("Warning: failed to parse proxy URL %s: %v", proxyURLStr, err)
			// Fall through to direct connection
		} else {
		client = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				Proxy:           http.ProxyURL(proxyURL),
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
		usedProxy = true
		}
	} else {
		// Caido not available — use direct connection
		client = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	}

	resp, err := client.Do(req)
	if err != nil && usedProxy {
		// Proxy failed — fall back to direct request
		client = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
		resp, err = client.Do(req)
		usedProxy = false
	}
	if err != nil {
		return tools.Result{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return tools.Result{}, fmt.Errorf("failed to read response body: %w", err)
	}

	var b strings.Builder
	if usedProxy {
		b.WriteString(fmt.Sprintf("[via Caido proxy :%d]\n", caidoPort))
	} else {
		b.WriteString("[direct request — Caido not available]\n")
	}
	b.WriteString(fmt.Sprintf("HTTP/%s %s\n", resp.Proto, resp.Status))
	for k, vs := range resp.Header {
		for _, v := range vs {
			b.WriteString(fmt.Sprintf("%s: %s\n", k, v))
		}
	}
	b.WriteString("\n")

	bodyStr := string(respBody)
	if len(bodyStr) > 10000 {
		bodyStr = bodyStr[:10000] + "\n\n... [TRUNCATED]"
	}
	b.WriteString(bodyStr)

	return tools.Result{
		Output: b.String(),
		Metadata: map[string]any{
			"status_code": resp.StatusCode,
			"url":         targetURL,
			"via_proxy":   usedProxy,
		},
	}, nil
}

func listRequests(args map[string]string) (tools.Result, error) {
	cfg := config.Get()
	if cfg.CaidoAPIToken == "" {
		return tools.Result{Output: "Caido API token not configured. Set CAIDO_API_TOKEN in ~/.xalgorix.env"}, nil
	}

	count := 20
	if c := args["count"]; c != "" {
		fmt.Sscanf(c, "%d", &count)
	}

	query := `query { requests(first: ` + strconv.Itoa(count) + `) { edges { node { id method url response { statusCode } } } } }`

	gqlReq := map[string]any{"query": query}
	body, err := json.Marshal(gqlReq)
	if err != nil {
		return tools.Result{Error: fmt.Sprintf("Failed to marshal GraphQL query: %v", err)}, nil
	}

	gqlURL := getCaidoGraphQLURL()
	req, err := http.NewRequest(http.MethodPost, gqlURL, bytes.NewReader(body))
	if err != nil {
		return tools.Result{Error: fmt.Sprintf("Failed to create GraphQL request: %v", err)}, nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.CaidoAPIToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return tools.Result{Output: fmt.Sprintf("Failed to query Caido GraphQL API at %s: %v\nMake sure Caido is running and accessible.", gqlURL, err)}, nil
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return tools.Result{Error: fmt.Sprintf("Failed to read Caido response: %v", err)}, nil
	}
	return tools.Result{Output: string(respBody)}, nil
}
