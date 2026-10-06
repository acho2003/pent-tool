package scanner

import (
	"bytes"
	"encoding/json"
	"github.com/xalgord/xalgorix/v4/internal/credentials"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReplayPreservesExactVariantsWithoutPublicSecrets(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	dir := t.TempDir()
	store, err := credentials.NewReplayStore(filepath.Join(dir, "private"), bytes.Repeat([]byte{4}, credentials.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	raw := "https://app.test/a%2Fb/?x=1&token=private-url&x=2"
	body := `{"query":"query {viewer}","variables":{"token":"private-body"}}`
	ep, ok := requestVariantEndpoint("app:1", raw, "POST", "application/json", body, true)
	if !ok {
		t.Fatal("invalid identity")
	}
	ref, err := store.Put("app:1", ep.AuthContextID, credentials.ReplayRequest{EndpointID: ep.ID, URL: raw, Method: ep.Method, ContentType: ep.RequestContentType, Body: body, Headers: map[string]string{"Authorization": "Bearer private-header"}})
	if err != nil {
		t.Fatal(err)
	}
	row := map[string]any{"request": map[string]any{"endpoint": SafeTelemetryURL(raw), "method": "POST", "source": "browser", "request_id": ep.ID, "replay_reference": ref, "read_only": true, "authenticated": true, "body_digest": bodyDigest(body), "parameters": bodyParameters(body, "application/json"), "headers": map[string]string{"content-type": "application/json"}}}
	data, _ := json.Marshal(row)
	artifact := filepath.Join(dir, "browser.jsonl")
	os.WriteFile(artifact, append(data, '\n'), 0600)
	surface, err := ParseKatanaAttackSurface(artifact, "app:1", "https://app.test/", true)
	if err != nil || len(surface.Endpoints) != 1 {
		t.Fatalf("parse %v %+v", err, surface)
	}
	surface.WorkflowVersion = "unified-v1"
	hydrateRequestReplay(surface, store, "app:1")
	actual := surface.Endpoints[0]
	if actual.ID != ep.ID || actual.URL != raw || actual.ReplayBody != body || actual.ReplayHeaders["Authorization"] != "Bearer private-header" {
		t.Fatalf("replay lost: %+v", actual)
	}
	selected := DispatchTargets(surface, "zap", 100)
	if len(selected) != 1 {
		t.Fatalf("readonly body not selected: %+v", surface.Endpoints)
	}
	inputs := BuildScannerInputs(surface, Request{EndpointTargets: selected}, "zap")
	req := Request{ScanDir: filepath.Join(dir, "job"), InputRequests: inputs}
	path, err := SaveScannerInputs(req, "zap")
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveAttackSurface(dir, surface); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{path, attackSurfacePath(dir, "app:1"), artifact} {
		blob, _ := os.ReadFile(file)
		for _, secret := range []string{"private-url", "private-body", "private-header"} {
			if bytes.Contains(blob, []byte(secret)) {
				t.Fatalf("public secret in %s", file)
			}
		}
	}
	public, _ := os.ReadFile(attackSurfacePath(dir, "app:1"))
	var restored AttackSurface
	json.Unmarshal(public, &restored)
	hydrateRequestReplay(&restored, nil, "app:1")
	if restored.Endpoints[0].State != EndpointStateUnmaterialized || len(DispatchTargets(&restored, "zap", 100)) != 0 {
		t.Fatal("missing key did not block request")
	}
	hydrateRequestReplay(&restored, store, "app:1")
	if len(DispatchTargets(&restored, "zap", 100)) != 1 || restored.Endpoints[0].URL != raw {
		t.Fatal("valid restart replay not restored")
	}
	restored.Endpoints[0].State, restored.Endpoints[0].StateReason = EndpointStateExcluded, "policy exclusion"
	hydrateRequestReplay(&restored, store, "app:1")
	if restored.Endpoints[0].State != EndpointStateExcluded {
		t.Fatal("replay overrode exclusion")
	}
	other, _ := requestVariantEndpoint("app:1", raw, "POST", "application/json", body+" ", true)
	if other.ID == ep.ID {
		t.Fatal("body variants collapsed")
	}
	for _, secret := range []string{"private-url", "private-body", "private-header"} {
		if strings.Contains(redact(secret, secretValues(req, Config{})), secret) {
			t.Fatalf("derived secret not redacted: %s", secret)
		}
	}
}
func TestSensitiveSeedsRequireBoundReplay(t *testing.T) {
	raw := "https://app.test/?token=private"
	ep, _ := requestVariantEndpoint("app:a", raw, "GET", "", "", false)
	surface := &AttackSurface{Endpoints: []AttackSurfaceEndpoint{ep}}
	sealInventoryRequests(surface, nil, "app:a")
	if surface.Endpoints[0].State != EndpointStateUnmaterialized {
		t.Fatal("sensitive seed dispatched without replay")
	}
	store, _ := credentials.NewReplayStore(t.TempDir(), bytes.Repeat([]byte{1}, credentials.KeySize))
	surface.Endpoints = []AttackSurfaceEndpoint{ep}
	sealInventoryRequests(surface, store, "app:a")
	hydrateRequestReplay(surface, store, "app:a")
	if surface.Endpoints[0].ReplayRef == "" || surface.Endpoints[0].URL != raw {
		t.Fatal("seed replay lost")
	}
}
func TestUntrustedCrawlerCannotGrantReplayAuthority(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "katana.jsonl")
	os.WriteFile(path, []byte(`{"request":{"endpoint":"https://app.test/graphql","method":"POST","source":"browser","request_id":"123456789012345678901234","read_only":true,"replay_reference":"fake","authenticated":true}}`), 0600)
	surface, err := ParseKatanaAttackSurface(path, "app:a", "https://app.test/", false)
	if err != nil {
		t.Fatal(err)
	}
	ep := surface.Endpoints[0]
	if ep.ReplayRef != "" || ep.ReadOnly || ep.AuthContextID != "" || ep.ID == "123456789012345678901234" {
		t.Fatal("crawler granted capture authority")
	}
}
