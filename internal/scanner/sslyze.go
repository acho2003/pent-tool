package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type sslyzeRunner struct{}

func (sslyzeRunner) Name() string { return "sslyze" }
func (sslyzeRunner) Descriptor() Descriptor {
	return Descriptor{Name: "sslyze", Summary: "Optional TLS protocol assessment per approved service", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightLight, Applies: appliesToHost}
}
func (sslyzeRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	spec := buildSSLyze(req, cfg)
	if spec.notApp == "" {
		if err := cfg.Budget.Wait(ctx); err != nil {
			spec = commandSpec{notApp: "assessment budget exhausted before TLS scan: " + err.Error(), timeout: cfg.SSLyzeTimeout}
		}
	}
	return executeSpec(ctx, "sslyze", req, cfg, spec, emit)
}

func buildSSLyze(req Request, cfg Config) commandSpec {
	u, err := url.Parse(strings.TrimSpace(req.Target))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return commandSpec{notApp: "SSLyze requires one approved HTTPS service", timeout: cfg.SSLyzeTimeout}
	}
	if req.AppScope != nil {
		approved := false
		for _, origin := range req.AppScope.Origins() {
			if strings.EqualFold(origin.Origin(), u.Scheme+"://"+u.Host) {
				approved = true
				break
			}
		}
		if !approved {
			return commandSpec{notApp: "TLS service is outside approved origins", timeout: cfg.SSLyzeTimeout}
		}
	}
	if cfg.ScopeGuard != nil {
		if blocked, reason := cfg.ScopeGuard(req.Target, nil); blocked {
			return commandSpec{notApp: "TLS service failed execution-time scope guard: " + reason, timeout: cfg.SSLyzeTimeout}
		}
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	if _, err := strconv.Atoi(port); err != nil {
		return commandSpec{notApp: "TLS service port is invalid", timeout: cfg.SSLyzeTimeout}
	}
	artifact := filepath.Join(req.ScanDir, "scanner-output", "sslyze", "results.json")
	return commandSpec{path: cfg.SSLyzePath, artifact: artifact, timeout: cfg.SSLyzeTimeout,
		args: []string{"--quiet", "--slow_connection", "--tlsv1", "--tlsv1_1", "--json_out=" + artifact, net.JoinHostPort(u.Hostname(), port)}}
}

// parseSSLyze reads the versioned JSON export. A protocol is reported only
// when its scan command completed and explicitly observed support.
func parseSSLyze(path string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var document struct {
		ServerScanResults []struct {
			ServerLocation struct {
				Hostname string `json:"hostname"`
				Port     int    `json:"port"`
			} `json:"server_location"`
			ScanStatus string `json:"scan_status"`
			ScanResult map[string]struct {
				Status string          `json:"status"`
				Result json.RawMessage `json:"result"`
			} `json:"scan_result"`
		} `json:"server_scan_results"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("decode SSLyze JSON: %w", err)
	}
	var findings []Finding
	for _, service := range document.ServerScanResults {
		if service.ScanStatus != "COMPLETED" {
			continue
		}
		for key, version := range map[string]string{"tls_1_0_cipher_suites": "TLS 1.0", "tls_1_1_cipher_suites": "TLS 1.1"} {
			attempt := service.ScanResult[key]
			if attempt.Status != "COMPLETED" {
				continue
			}
			var result struct {
				Supported bool `json:"is_tls_version_supported"`
			}
			if json.Unmarshal(attempt.Result, &result) != nil || !result.Supported {
				continue
			}
			port := strconv.Itoa(service.ServerLocation.Port)
			findings = append(findings, Finding{SourceID: "sslyze:" + service.ServerLocation.Hostname + ":" + port + ":" + key, Scanner: "sslyze", RuleID: key, Title: version + " is enabled", Severity: "MEDIUM", Target: service.ServerLocation.Hostname, Endpoint: service.ServerLocation.Hostname + ":" + port, Port: port, Protocol: version, Description: "The TLS service accepted a deprecated protocol version.", Remediation: "Disable this protocol version and retain TLS 1.2 or newer."})
		}
	}
	return findings, nil
}
