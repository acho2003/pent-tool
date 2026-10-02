package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseKatanaAttackSurface_DropsOffHostEndpoints(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "katana.jsonl")
	lines := `{"request":{"endpoint":"http://host.docker.internal:3000/rest/products/search?q=1","method":"GET"}}
{"request":{"endpoint":"https://owasp.org/","method":"GET"}}
{"request":{"endpoint":"https://owasp-juice.shop/","method":"GET"}}
{"request":{"endpoint":"https://fonts.googleapis.com/css","method":"GET"}}
{"request":{"endpoint":"http://host.docker.internal:3000/rest/admin","method":"GET"}}
`
	if err := os.WriteFile(art, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	surface, err := ParseKatanaAttackSurface(art, "host:host.docker.internal", "http://host.docker.internal:3000/", false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, ep := range surface.Endpoints {
		h := hostFromTarget(ep.URL)
		if h != "host.docker.internal" {
			t.Errorf("off-host endpoint leaked into surface: %s (host %s)", ep.URL, h)
		}
	}
	// The two in-scope endpoints must survive.
	if len(surface.Endpoints) < 2 {
		t.Errorf("expected the in-scope endpoints kept, got %d: %+v", len(surface.Endpoints), surface.Endpoints)
	}
}
