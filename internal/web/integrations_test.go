package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

func TestIntegrationsListsEveryRegistryToolAndProvider(t *testing.T) {
	s := newTestServer(t, nil)
	s.cfg.InteractshServer = "https://oast.pro"
	rr := httptest.NewRecorder()
	s.handleIntegrations(rr, httptest.NewRequest(http.MethodGet, "/api/scanners/integrations", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("status %d content-type %q", rr.Code, rr.Header().Get("Content-Type"))
	}
	var body struct {
		Integrations []integrationEntry `json:"integrations"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	byID := map[string]integrationEntry{}
	for _, entry := range body.Integrations {
		byID[entry.ID] = entry
	}
	for _, def := range scanner.ScannerRegistry() {
		if _, ok := byID[def.ID]; !ok {
			t.Errorf("registry tool %s is missing from the integrations page", def.ID)
		}
	}
	for _, id := range []string{"gau", "waybackurls", "chromium", "interactsh", "schemathesis", "authz-matrix"} {
		if _, ok := byID[id]; !ok {
			t.Errorf("%s is missing", id)
		}
	}
	if entry := byID["interactsh"]; entry.Available || !strings.Contains(entry.AvailabilityReason, "public Interactsh") {
		t.Errorf("a public Interactsh server must show as unavailable with its reason: %+v", entry)
	}
	if entry := byID["authz-matrix"]; entry.Integration != "built-in" {
		t.Errorf("native checks must show as built-in: %+v", entry)
	}
	// Built-in checks are compiled into the binary and run via their assessment
	// runner, so they must report as available rather than "no assessment adapter
	// in this build".
	for _, id := range []string{"security-headers", "exposed-files", "nextjs-assets", "vcs-exposure", "actuator"} {
		entry, ok := byID[id]
		if !ok {
			t.Errorf("%s missing", id)
			continue
		}
		if !entry.Available || entry.AvailabilityReason != "" {
			t.Errorf("built-in check %s must show available with no reason: %+v", id, entry)
		}
	}
	for _, entry := range body.Integrations {
		if !entry.Available && entry.AvailabilityReason == "" {
			t.Errorf("unavailable %s needs a reason", entry.ID)
		}
	}
}
