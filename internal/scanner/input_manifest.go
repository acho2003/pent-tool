package scanner

import (
	"encoding/json"
	"github.com/xalgord/xalgorix/v4/internal/storage"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

type ScannerRequestInput struct {
	InventoryScope string `json:"inventory_scope,omitempty"`
	EndpointID     string `json:"endpoint_id"`
	URL            string `json:"url"`
	Method         string `json:"method"`
	ContentType    string `json:"content_type,omitempty"`
	BodyDigest     string `json:"body_digest,omitempty"`
	Selected       bool   `json:"selected"`
	Reason         string `json:"reason,omitempty"`
	Body           string `json:"-"`
}
type EndpointSubmission struct {
	EndpointID  string `json:"endpoint_id"`
	Method      string `json:"method"`
	URL         string `json:"url"`
	Status      string `json:"status"`
	Reason      string `json:"reason,omitempty"`
	At          string `json:"at"`
	EvidenceRef string `json:"evidence_reference,omitempty"`
}
type ScannerInputManifest struct {
	SchemaVersion   int                   `json:"schema_version"`
	Scanner         string                `json:"scanner"`
	AttemptID       string                `json:"attempt_id"`
	PlanFingerprint string                `json:"plan_fingerprint"`
	CreatedAt       string                `json:"created_at"`
	Requests        []ScannerRequestInput `json:"requests"`
}

func SafeTelemetryURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[invalid URL]"
	}
	u.User = nil
	parts := strings.Split(u.RawQuery, "&")
	for i, part := range parts {
		key, _, hasValue := strings.Cut(part, "=")
		name, decodeErr := url.QueryUnescape(key)
		if decodeErr != nil {
			parts[i] = "[invalid parameter omitted]"
			continue
		}
		lower := strings.ToLower(name)
		if strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "session") || strings.Contains(lower, "key") || strings.Contains(lower, "signature") || strings.Contains(lower, "credential") || lower == "sig" || lower == "jwt" || lower == "code" || lower == "authorization" {
			parts[i] = key + "=" + url.QueryEscape("[REDACTED]")
		} else if hasValue {
			if _, err := url.QueryUnescape(part); err != nil {
				parts[i] = key + "=" + url.QueryEscape("[invalid value omitted]")
			}
		}
	}
	u.RawQuery = strings.Join(parts, "&")
	fragment := strings.ToLower(u.Fragment)
	if strings.Contains(fragment, "token=") || strings.Contains(fragment, "secret=") || strings.Contains(fragment, "password=") || strings.Contains(fragment, "session=") {
		u.Fragment = "[REDACTED]"
		u.RawFragment = ""
	}

	return u.String()
}
func BuildScannerInputs(surface *AttackSurface, req Request, scanner string) []ScannerRequestInput {
	selected := map[string]bool{}
	for _, u := range req.EndpointTargets {
		selected[u] = true
	}
	var inputs []ScannerRequestInput
	if surface == nil {
		return inputs
	}
	for _, ep := range surface.Endpoints {
		input := ScannerRequestInput{InventoryScope: surface.Scope, EndpointID: ep.ID, URL: ep.URL, Method: ep.Method, ContentType: ep.RequestContentType, BodyDigest: ep.BodyDigest, Selected: selected[ep.URL]}
		for _, c := range ep.ScannerCoverage {
			if c.Scanner == scanner {
				input.Reason = c.Reason
				if c.Status == "skipped" {
					input.Selected = false
				}
			}
		}
		inputs = append(inputs, input)
	}
	return inputs
}
func SaveScannerInputs(req Request, scanner string) (string, error) {
	manifest := ScannerInputManifest{SchemaVersion: 1, Scanner: scanner, AttemptID: req.AttemptID, PlanFingerprint: req.PlanFingerprint, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), Requests: append([]ScannerRequestInput(nil), req.InputRequests...)}
	for i := range manifest.Requests {
		manifest.Requests[i].URL = SafeTelemetryURL(manifest.Requests[i].URL)
	}
	path := filepath.Join(req.ScanDir, "input-manifest.json")
	if err := storage.EnsureSecureDir(req.ScanDir); err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", err
	}
	return path, storage.WriteAtomic(path, data)
}

func zapFilteredOpenAPI(req Request) ([]byte, error) {
	paths := map[string]any{}
	for _, input := range req.InputRequests {
		if !input.Selected || (input.Method != "GET" && input.Method != "HEAD") {
			continue
		}
		u, err := url.Parse(input.URL)
		if err != nil {
			continue
		}
		path := u.EscapedPath()
		if path == "" {
			path = "/"
		}
		entry, ok := paths[path].(map[string]any)
		if !ok {
			entry = map[string]any{}
			paths[path] = entry
		}
		entry[strings.ToLower(input.Method)] = map[string]any{"responses": map[string]any{"200": map[string]string{"description": "Observed request"}}}
	}
	return json.Marshal(map[string]any{"openapi": "3.0.3", "info": map[string]string{"title": "Approved Xalgorix requests", "version": "1"}, "paths": paths})
}
