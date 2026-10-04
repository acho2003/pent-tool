package scanner

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
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

func writeKatanaFixture(t *testing.T, lines string) string {
	t.Helper()
	art := filepath.Join(t.TempDir(), "katana.jsonl")
	if err := os.WriteFile(art, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	return art
}

func endpointByURL(surface *AttackSurface, rawURL string) *AttackSurfaceEndpoint {
	for i := range surface.Endpoints {
		if surface.Endpoints[i].URL == rawURL {
			return &surface.Endpoints[i]
		}
	}
	return nil
}

func coverageFor(ep *AttackSurfaceEndpoint, scannerName string) EndpointScannerCoverage {
	for _, c := range ep.ScannerCoverage {
		if c.Scanner == scannerName {
			return c
		}
	}
	return EndpointScannerCoverage{}
}

func TestParseKatanaKeepsOutOfScopeRowsWithReason(t *testing.T) {
	art := writeKatanaFixture(t, `{"timestamp":"2026-10-02T00:00:00Z","request":{"endpoint":"http://example.com/app/search?q=1","method":"GET","source":"http://example.com/app/"}}
{"request":{"endpoint":"http://example.com:80/app/default-port","method":"GET"}}
{"request":{"endpoint":"http://example.com:8080/app/other-port","method":"GET"}}
{"request":{"endpoint":"http://example.com/outside","method":"GET"}}
{"request":{"endpoint":"http://example.com/app/admin/users","method":"GET"}}
{"request":{"endpoint":"https://owasp.org/","method":"GET"}}
{"request":{"endpoint":"http://example.com/app/logo.png","method":"GET"}}
`)
	scope := assessment.NewAppScope(
		[]assessment.ApprovedOrigin{{TargetID: "web", Scheme: "http", Host: "example.com", PathPrefix: "/app"}},
		assessment.Exclusion{PathPattern: "/app/admin", Reason: "operator excluded admin"},
	)
	surface, err := ParseKatanaAttackSurfaceScoped(art, "app:web", "http://example.com/app/", true, &scope)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"http://example.com/app/search?q=1":      EndpointStateInScope,
		"http://example.com/app/default-port":    EndpointStateInScope,
		"http://example.com:8080/app/other-port": EndpointStateOutOfScope,
		"http://example.com/outside":             EndpointStateOutOfScope,
		"http://example.com/app/admin/users":     EndpointStateExcluded,
		"https://owasp.org/":                     EndpointStateOutOfScope,
		"http://example.com/app/logo.png":        EndpointStateStatic,
	}
	if len(surface.Endpoints) != len(want) {
		t.Fatalf("endpoints = %d, want %d (out-of-scope rows must be kept): %+v", len(surface.Endpoints), len(want), surface.Endpoints)
	}
	for rawURL, state := range want {
		ep := endpointByURL(surface, rawURL)
		if ep == nil {
			t.Fatalf("missing endpoint %s", rawURL)
		}
		if ep.State != state {
			t.Errorf("%s state = %q, want %q (%s)", rawURL, ep.State, state, ep.StateReason)
		}
		if state != EndpointStateInScope && ep.StateReason == "" {
			t.Errorf("%s has no state reason", rawURL)
		}
		if len(ep.Provenance) == 0 || ep.Provenance[0].Tool != "katana" || !ep.Provenance[0].Authenticated || ep.Provenance[0].Artifact != "katana.jsonl" {
			t.Errorf("%s provenance = %+v", rawURL, ep.Provenance)
		}
	}
	if reason := endpointByURL(surface, "http://example.com/app/admin/users").StateReason; reason != "operator excluded admin" {
		t.Errorf("exclusion reason = %q", reason)
	}
	got := DispatchTargetsScoped(surface, "nuclei", 100, &scope, nil)
	if len(got) != 2 {
		t.Fatalf("nuclei targets = %v, want only the two in-scope endpoints", got)
	}
	for _, rawURL := range []string{"http://example.com:8080/app/other-port", "http://example.com/outside", "http://example.com/app/admin/users", "https://owasp.org/"} {
		c := coverageFor(endpointByURL(surface, rawURL), "nuclei")
		if c.Status != "skipped" || c.Reason == "" {
			t.Errorf("%s coverage = %+v, want skipped with reason", rawURL, c)
		}
	}
}

// The legacy wrapper keeps its host-only boundary: the legacy (non-typed)
// pipeline crawls nmap-discovered web ports, so a link to another port on the
// same host stays in the surface and an off-host link is still dropped.
func TestParseKatanaLegacyWrapperKeepsHostBoundary(t *testing.T) {
	art := writeKatanaFixture(t, `{"request":{"endpoint":"http://example.com:8080/a","method":"GET"}}
{"request":{"endpoint":"http://example.com/b","method":"GET"}}
{"request":{"endpoint":"https://cdn.example.net/c","method":"GET"}}
`)
	surface, err := ParseKatanaAttackSurface(art, "recon:example.com", "http://example.com/", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(surface.Endpoints) != 2 {
		t.Fatalf("endpoints = %+v", surface.Endpoints)
	}
	for _, ep := range surface.Endpoints {
		if ep.State != "" {
			t.Errorf("legacy parse stamped state %q on %s", ep.State, ep.URL)
		}
	}
	if got := DispatchTargets(surface, "nuclei", 100); len(got) != 2 {
		t.Fatalf("legacy nuclei targets = %v", got)
	}
}

func TestInSurfaceScopeNormalizesDefaultPort(t *testing.T) {
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{{Scheme: "https", Host: "example.com", Port: 443}})
	for rawURL, want := range map[string]bool{
		"https://example.com/x":      true,
		"https://example.com:443/x":  true,
		"https://EXAMPLE.com:443/":   true,
		"https://example.com:8443/x": false,
		"http://example.com/x":       false,
	} {
		if got, _ := inSurfaceScope(rawURL, "example.com", &scope); got != want {
			t.Errorf("inSurfaceScope(%s) = %v, want %v", rawURL, got, want)
		}
	}
	if got, _ := inSurfaceScope("http://example.com:8080/x", "example.com", nil); !got {
		t.Error("legacy host scope must keep other ports on the same host")
	}
}

func TestEmptyStateEndpointsStayEligible(t *testing.T) {
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{{Scheme: "https", Host: "example.test"}})
	surface := NewSeedAttackSurface("app:test", "https://example.test/")
	MergeOpenAPIEndpoints(surface, "https://example.test/", []APIEndpoint{{Method: "GET", Path: "/api/items", Source: "openapi"}})
	for _, ep := range surface.Endpoints {
		if ep.State != "" {
			t.Fatalf("seed/OpenAPI endpoint got state %q", ep.State)
		}
	}
	if got := DispatchTargets(surface, "nuclei", 100); len(got) != 2 {
		t.Fatalf("legacy dispatch = %v", got)
	}
	if got := DispatchTargetsScoped(surface, "nuclei", 100, &scope, nil); len(got) != 2 {
		t.Fatalf("scoped dispatch = %v", got)
	}
	// A snapshot written before State existed decodes with an empty State and
	// must still dispatch.
	dir := t.TempDir()
	snapshot := `{"schema_version":1,"classifier_version":` + strconv.Itoa(AttackSurfaceClassifierVersion) + `,"scope":"app:old","target":"https://example.test/","endpoints":[{"id":"abc","url":"https://example.test/search?q=1","canonical_url":"https://example.test/search?q={value}","method":"GET","path":"/search","kind":"web","parameters":[{"name":"q","location":"query"}],"has_parameters":true}]}`
	path := attackSurfacePath(dir, "app:old")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(snapshot), 0o600); err != nil {
		t.Fatal(err)
	}
	resumed, ok := LoadAttackSurface(dir, "app:old", "")
	if !ok {
		t.Fatal("snapshot not loaded")
	}
	if got := DispatchTargetsScoped(resumed, "wapiti", 100, &scope, nil); len(got) != 1 {
		t.Fatalf("resumed snapshot dispatch = %v", got)
	}
}

func TestEndpointEligibleRefusesExcludedMethodPath(t *testing.T) {
	scope := assessment.NewAppScope(
		[]assessment.ApprovedOrigin{{Scheme: "https", Host: "example.test"}},
		assessment.Exclusion{Method: "GET", PathPattern: "/api/delete*", Reason: "destructive GET"},
		assessment.Exclusion{Method: "POST", PathPattern: "/api/search"},
	)
	excluded, ok := normalizeAttackSurfaceEndpoint("https://example.test/api/delete-user?id=1", "GET", "seed", "", 0, "", nil, false, false)
	if !ok {
		t.Fatal("normalize failed")
	}
	if eligible, reason := endpointEligibleInScope(excluded, "nuclei", &scope); eligible || !strings.Contains(reason, "destructive GET") {
		t.Fatalf("excluded GET eligible=%v reason=%q", eligible, reason)
	}
	// A POST-only exclusion does not refuse GET on the same path.
	search, _ := normalizeAttackSurfaceEndpoint("https://example.test/api/search?q=1", "GET", "seed", "", 0, "", nil, false, false)
	if eligible, reason := endpointEligibleInScope(search, "nuclei", &scope); !eligible {
		t.Fatalf("GET refused by POST-only exclusion: %s", reason)
	}
	// A stamped State is refused by the pure gate even without a scope.
	stamped := search
	stamped.State, stamped.StateReason = EndpointStateExcluded, "operator excluded"
	if eligible, reason := endpointEligibleForScanner(stamped, "nuclei"); eligible || !strings.Contains(reason, "operator excluded") {
		t.Fatalf("stamped excluded eligible=%v reason=%q", eligible, reason)
	}
	for _, state := range []string{EndpointStateOutOfScope, EndpointStateStatic, EndpointStateHistoricalUnverified, EndpointStateUnreachable, EndpointStateUnauthorized} {
		ep := search
		ep.State = state
		if eligible, _ := endpointEligibleForScanner(ep, "nuclei"); eligible {
			t.Errorf("state %s was eligible", state)
		}
	}
	ep := search
	ep.State = EndpointStateInScope
	if eligible, reason := endpointEligibleForScanner(ep, "nuclei"); !eligible {
		t.Errorf("in_scope refused: %s", reason)
	}
	// The skip reason is recorded on the endpoint so excluded work stays visible.
	surface := &AttackSurface{Endpoints: []AttackSurfaceEndpoint{excluded}}
	if got := DispatchTargetsScoped(surface, "nuclei", 100, &scope, nil); len(got) != 0 {
		t.Fatalf("excluded endpoint dispatched: %v", got)
	}
	if c := coverageFor(&surface.Endpoints[0], "nuclei"); c.Status != "skipped" || !strings.Contains(c.Reason, "destructive GET") {
		t.Fatalf("coverage = %+v", c)
	}
}

func TestEndpointEligibleRefusesPlaceholderPath(t *testing.T) {
	surface := NewSeedAttackSurface("app:test", "https://example.test/")
	MergeOpenAPIEndpoints(surface, "https://example.test/", []APIEndpoint{{Method: "GET", Path: "/users/{id}", Source: "openapi"}})
	byID := map[string]int{}
	for i := range surface.Endpoints {
		byID[surface.Endpoints[i].ID] = i
	}
	for _, raw := range []string{"https://example.test/orders/%7Bid%7D?x=1", "https://example.test/files/%257Bname%257D"} {
		ep, ok := normalizeAttackSurfaceEndpoint(raw, "GET", "katana", "", 200, "", endpointParameters(raw), false, false)
		if !ok {
			t.Fatalf("normalize %s", raw)
		}
		mergeSurfaceEndpoint(surface, byID, ep)
	}
	for _, scannerName := range []string{"nuclei", "zap", "wapiti", "dalfox"} {
		for _, target := range DispatchTargets(surface, scannerName, 100) {
			lower := strings.ToLower(target)
			if strings.ContainsAny(target, "{}") || strings.Contains(lower, "%7b") || strings.Contains(lower, "%7d") {
				t.Fatalf("%s dispatched placeholder URL %s", scannerName, target)
			}
		}
	}
	for _, ep := range surface.Endpoints {
		if ep.Path == "/" {
			continue
		}
		if c := coverageFor(&ep, "nuclei"); c.Status != "skipped" || !strings.Contains(c.Reason, "placeholder") {
			t.Errorf("%s coverage = %+v", ep.URL, c)
		}
	}
}

func TestScopedOpenAPIMergeKeepsOperationsVisibleWithoutExpandingScope(t *testing.T) {
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{{Scheme: "https", Host: "example.test", PathPrefix: "/app"}})
	surface := NewSeedAttackSurface("app:test", "https://example.test/app/")
	MergeOpenAPIEndpointsScoped(surface, "https://example.test/app/", []APIEndpoint{
		{Method: "GET", Path: "/users/{id}", Source: "openapi", Resolved: false, Reason: "path parameter value was not supplied"},
		{Method: "POST", Path: "/users", Source: "openapi", Resolved: true, Eligible: false, Reason: "operation method is not yet supported"},
		{Method: "GET", Path: "/admin", Origin: "https://other.example.test", Source: "openapi", Resolved: true, Eligible: true},
	}, &scope)
	if len(surface.Endpoints) != 4 { // seed plus each API operation
		t.Fatalf("inventory endpoints=%+v", surface.Endpoints)
	}
	byPath := make(map[string]AttackSurfaceEndpoint)
	for _, endpoint := range surface.Endpoints {
		if endpoint.Sources[0] == "seed" {
			continue
		}
		byPath[endpoint.Path] = endpoint
	}
	placeholder := byPath["/app/users/{id}"]
	if placeholder.State != EndpointStateUnmaterialized || placeholder.StateReason != "path parameter value was not supplied" || len(placeholder.Provenance) == 0 || placeholder.Provenance[0].Tool != "openapi" {
		t.Fatalf("placeholder operation missing review state/provenance: %+v", placeholder)
	}
	for _, target := range DispatchTargetsScoped(surface, "zap", 100, &scope, nil) {
		if strings.Contains(target, "users") || strings.Contains(target, "other.example.test") {
			t.Fatalf("unmaterialized or foreign operation dispatched: %v", target)
		}
	}
	foreign := byPath["/admin"]
	if foreign.State != EndpointStateOutOfScope {
		t.Fatalf("foreign OpenAPI server state=%q reason=%q", foreign.State, foreign.StateReason)
	}
}

func TestDispatchTargetsScopedReservesGlobalEndpointCap(t *testing.T) {
	surface := NewSeedAttackSurface("app:test", "https://example.test/")
	byID := map[string]int{}
	for i := range surface.Endpoints {
		byID[surface.Endpoints[i].ID] = i
	}
	for _, raw := range []string{"https://example.test/a?q=1", "https://example.test/b?q=1", "https://example.test/c?q=1", "https://example.test/d?q=1"} {
		ep, _ := normalizeAttackSurfaceEndpoint(raw, "GET", "katana", "", 200, "", endpointParameters(raw), false, false)
		mergeSurfaceEndpoint(surface, byID, ep)
	}
	budget := NewAssessmentBudget(0, 3, 0)
	nuclei := DispatchTargetsScoped(surface, "nuclei", 100, nil, budget)
	if len(nuclei) != 3 {
		t.Fatalf("nuclei targets = %v, want 3 under the global cap", nuclei)
	}
	if exhausted, gap := budget.Exhausted(); !exhausted || gap != GapBudgetExhausted {
		t.Fatalf("budget exhausted = %v %q", exhausted, gap)
	}
	refused := 0
	for i := range surface.Endpoints {
		if c := coverageFor(&surface.Endpoints[i], "nuclei"); c.Status == "skipped" {
			refused++
			if c.Reason != assessmentEndpointCapReason {
				t.Errorf("refusal reason = %q", c.Reason)
			}
		}
	}
	if refused != 2 {
		t.Fatalf("refused = %d", refused)
	}
	// Another scanner re-uses the already-reserved endpoints at no cost; the
	// endpoint refused before stays refused.
	dalfox := DispatchTargetsScoped(surface, "dalfox", 100, nil, budget)
	if len(dalfox) != 2 {
		t.Fatalf("dalfox targets = %v, want the 2 already-reserved query endpoints", dalfox)
	}
	// A nil budget never caps.
	if got := DispatchTargetsScoped(surface, "nuclei", 100, nil, nil); len(got) != 5 {
		t.Fatalf("nil budget targets = %v", got)
	}
}
