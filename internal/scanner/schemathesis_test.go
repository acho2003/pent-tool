package scanner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func schemathesisTestRequest(t *testing.T, target string, exclusions ...string) Request {
	t.Helper()
	origin, err := assessment.ParseApprovedOrigin("app", target)
	if err != nil {
		t.Fatal(err)
	}
	var excluded []assessment.Exclusion
	for _, path := range exclusions {
		excluded = append(excluded, assessment.Exclusion{PathPattern: path})
	}
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin}, excluded...)
	return Request{Target: target, AppScope: &scope, ScanDir: t.TempDir(), GatewayURL: "http://attempt:secret-gateway@127.0.0.1:9", GatewayCAPath: "/tmp/ca.pem", TypedAssessment: true}
}

func TestSchemathesisDefinitionIncludesOnlyApprovedReadOnlyOperations(t *testing.T) {
	req := schemathesisTestRequest(t, "https://api.example.test/app", "/app/admin")
	req.APIEndpoints = []APIEndpoint{
		{Method: "GET", Path: "/items/{id}", OperationID: "getItem", Source: "openapi", DefinitionID: "d1",
			Parameters: []APIParameter{{Name: "id", Location: "path", Required: true, SchemaType: "integer"}, {Name: "fields", Location: "query", SchemaType: "array"}, {Name: "X-Tenant", Location: "header", Required: true}},
			RequestURL: "https://api.example.test/app/items/42?fields=name"},
		{Method: "HEAD", Path: "/items/{id}", OperationID: "headItem", Source: "openapi"},
		{Method: "GET", Path: "/items/{id}", OperationID: "getItemDuplicate", Source: "openapi"},
		{Method: "POST", Path: "/items", OperationID: "createItem", Source: "openapi"},
		{Method: "GET", Path: "/search", OperationID: "search", Source: "openapi", RequestBodyRequired: true},
		{Method: "GET", Path: "/admin/users", OperationID: "adminUsers", Source: "openapi"},
		{Method: "GET", Path: "/graphql", OperationID: "q", Source: "graphql"},
		{Method: "GET", Path: "/other", OperationID: "other", Source: "openapi", Origin: "https://other.example.test"},
		{Method: "GET", Path: "/../escape", OperationID: "escape", Source: "openapi"},
	}
	document, base, operations, err := schemathesisDefinition(req)
	if err != nil {
		t.Fatal(err)
	}
	if base != "https://api.example.test/app" {
		t.Fatalf("base URL must be the approved application URL, got %s", base)
	}
	reasons := map[string]string{}
	for _, op := range operations {
		reasons[op.OperationID] = op.Status + ": " + op.Reason
	}
	want := map[string]string{
		"getItem":    "included: required header or cookie parameters are not generated: header:X-Tenant",
		"headItem":   "included: ",
		"createItem": "skipped: state-changing method is not fuzzed",
		"search":     "skipped: operation requires a request body",
		"q":          "skipped: GraphQL operations are sent as POST bodies, which the read-only gateway policy does not admit for generated input",
		"other":      "skipped: definition origin differs from the approved application URL",
		"escape":     "skipped: operation path escapes the application boundary",
	}
	for id, expected := range want {
		if reasons[id] != expected {
			t.Errorf("%s: got %q want %q", id, reasons[id], expected)
		}
	}
	if !strings.HasPrefix(reasons["adminUsers"], "skipped: excluded") {
		t.Errorf("excluded operation was not skipped: %q", reasons["adminUsers"])
	}
	if _, listed := reasons["getItemDuplicate"]; listed {
		t.Error("a duplicate method and path must not be listed twice")
	}
	var doc struct {
		Paths map[string]map[string]struct {
			OperationID string           `json:"operationId"`
			Parameters  []map[string]any `json:"parameters"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(document, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Paths) != 1 || len(doc.Paths["/items/{id}"]) != 2 {
		t.Fatalf("definition must hold only GET and HEAD /items/{id}: %s", document)
	}
	get := doc.Paths["/items/{id}"]["get"]
	if len(get.Parameters) != 2 {
		t.Fatalf("only path and query parameters are generated: %+v", get.Parameters)
	}
	for _, parameter := range get.Parameters {
		schema := parameter["schema"].(map[string]any)
		switch parameter["name"] {
		case "id":
			if parameter["in"] != "path" || parameter["required"] != true || schema["type"] != "integer" || schema["example"] != "42" {
				t.Errorf("path parameter lost its type or supplied example: %+v", parameter)
			}
		case "fields":
			if parameter["in"] != "query" || schema["type"] != "array" || schema["example"] != "name" {
				t.Errorf("query parameter lost its type or supplied example: %+v", parameter)
			}
		}
	}
	// HEAD declares no parameters but its path template still needs one.
	head := doc.Paths["/items/{id}"]["head"]
	if len(head.Parameters) != 1 || head.Parameters[0]["name"] != "id" || head.Parameters[0]["required"] != true {
		t.Fatalf("undeclared path template parameter must be added as required: %+v", head.Parameters)
	}
	if strings.Contains(string(document), "POST") || strings.Contains(strings.ToLower(string(document)), `"post"`) {
		t.Fatal("state-changing operation leaked into the definition")
	}
}

func TestBuildSchemathesisRunsOnlyThroughGatewayWithoutCredentialsOnArgv(t *testing.T) {
	req := schemathesisTestRequest(t, "https://api.example.test/app")
	req.TargetAuth = "Authorization: Bearer verified-session-token"
	req.APIEndpoints = []APIEndpoint{{Method: "GET", Path: "/items/{id}", OperationID: "getItem", Source: "openapi"}, {Method: "DELETE", Path: "/items/{id}", OperationID: "deleteItem", Source: "openapi"}}
	cfg := Config{SchemathesisPath: "schemathesis", RateRPS: 5}
	spec := buildSchemathesis(req, cfg)
	if spec.notApp != "" {
		t.Fatal(spec.notApp)
	}
	argv := strings.Join(spec.args, " ")
	for _, expected := range []string{"--config-file ", " run ", "--url https://api.example.test/app", "--checks not_a_server_error", "--phases examples,coverage,fuzzing", "--workers 1", "--max-redirects 0", "--tls-verify /tmp/ca.pem", "--rate-limit 5/s", "--report ndjson", "--generation-database none"} {
		if !strings.Contains(argv, expected) {
			t.Errorf("argv missing %q: %s", expected, argv)
		}
	}
	if strings.Contains(argv, "verified-session-token") || strings.Contains(argv, "Authorization") || slices.Contains(spec.args, "-H") {
		t.Fatalf("the gateway injects the session; it must not be on argv: %s", argv)
	}
	if spec.args[0] != "--config-file" || spec.args[2] != "run" {
		t.Fatalf("--config-file is a global option and must precede run: %v", spec.args)
	}
	if !spec.okExit[1] || spec.okExit[2] {
		t.Fatalf("exit 1 (failures or errors) is decided by the event log; exit 2 fails: %v", spec.okExit)
	}
	if len(spec.limitations) != 1 || !strings.Contains(spec.limitations[0].Reason, "state-changing method is not fuzzed") {
		t.Fatalf("a skipped operation must make the run's coverage visibly partial: %+v", spec.limitations)
	}
	if err := spec.prepare(); err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(filepath.Join(filepath.Dir(spec.artifact), "schemathesis.toml"))
	if err != nil || !strings.Contains(string(config), "unexpected-methods = []") {
		t.Fatalf("coverage-phase unexpected methods must be disabled: %s %v", config, err)
	}
	manifest, err := os.ReadFile(filepath.Join(filepath.Dir(spec.artifact), "operations.json"))
	if err != nil || !strings.Contains(string(manifest), `"deleteItem"`) || !strings.Contains(string(manifest), `"skipped"`) {
		t.Fatalf("every operation needs a recorded disposition: %s %v", manifest, err)
	}

	noGateway := req
	noGateway.GatewayURL = ""
	if spec := buildSchemathesis(noGateway, cfg); !strings.Contains(spec.notApp, "recording gateway") {
		t.Fatalf("Schemathesis must not run without the gateway: %q", spec.notApp)
	}
	writesOnly := req
	writesOnly.APIEndpoints = []APIEndpoint{{Method: "PUT", Path: "/items/{id}", OperationID: "putItem", Source: "openapi"}}
	if spec := buildSchemathesis(writesOnly, cfg); !strings.Contains(spec.notApp, "no approved read-only OpenAPI operation") || !strings.Contains(spec.notApp, "1 state-changing method is not fuzzed") {
		t.Fatalf("an empty definition must be not-applicable with reasons: %q", spec.notApp)
	}
}

func TestParseSchemathesisReportsServerErrorFromRealEventLog(t *testing.T) {
	findings, err := parseSchemathesis(filepath.Join("testdata", "schemathesis", "events-4.32.5.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one server error finding, got %+v", findings)
	}
	f := findings[0]
	// The recorded run's one server error was a fuzzed HEAD /items/{id} (HEAD has
	// no response body, so the evidence carries the request and status only).
	if f.Scanner != "schemathesis" || f.RuleID != "ST101" || f.Severity != "low" || f.CWE != "CWE-755" || f.Method != "HEAD" ||
		!strings.HasPrefix(f.Endpoint, "http://127.0.0.1:8080/app/items/") || f.Parameter != "id" || !strings.Contains(f.Evidence, "-> HTTP 500") || f.EvidenceRef == "" || f.SourceID != "schemathesis:ST101:HEAD /items/{id}" {
		t.Fatalf("finding lacks its request, response or location: %+v", f)
	}
	fatal, limitations, err := schemathesisRunState(filepath.Join("testdata", "schemathesis", "events-4.32.5.ndjson"))
	if err != nil || fatal != "" || len(limitations) != 0 {
		t.Fatalf("a completed run without errors is complete: fatal=%q limitations=%+v err=%v", fatal, limitations, err)
	}
}

func TestSchemathesisRunStateSeparatesErrorsFromFindings(t *testing.T) {
	fatal, limitations, err := schemathesisRunState(filepath.Join("testdata", "schemathesis", "network-errors-4.32.5.ndjson"))
	if err != nil || fatal != "" || len(limitations) != 1 || limitations[0].Kind != "test_case_errors" || !strings.Contains(limitations[0].Reason, "ConnectionError: 21") {
		t.Fatalf("network errors exit 1 like findings and must make the run partial: fatal=%q %+v %v", fatal, limitations, err)
	}
	if findings, err := parseSchemathesis(filepath.Join("testdata", "schemathesis", "network-errors-4.32.5.ndjson")); err != nil || len(findings) != 0 {
		t.Fatalf("errored test cases are not findings: %+v %v", findings, err)
	}
	fatal, _, err = schemathesisRunState(filepath.Join("testdata", "schemathesis", "schema-error-4.32.5.ndjson"))
	if err != nil || !strings.Contains(fatal, "LoaderError") {
		t.Fatalf("a schema loading failure must fail the run: %q %v", fatal, err)
	}
	truncated := filepath.Join(t.TempDir(), "events.ndjson")
	data, _ := os.ReadFile(filepath.Join("testdata", "schemathesis", "events-4.32.5.ndjson"))
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if err := os.WriteFile(truncated, []byte(strings.Join(lines[:len(lines)-1], "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, limitations, err := schemathesisRunState(truncated); err != nil || len(limitations) != 1 || limitations[0].Kind != "run_incomplete" {
		t.Fatalf("a log without its end event is partial: %+v %v", limitations, err)
	}
	malformed := filepath.Join(t.TempDir(), "events.ndjson")
	_ = os.WriteFile(malformed, []byte("{\"EngineStarted\":{}}\n{not json\n"), 0o600)
	if _, _, err := schemathesisRunState(malformed); err == nil {
		t.Fatal("a malformed event log must fail parsing, not count as clean")
	}
}

// The gateway answers blocked or failed requests itself with 4xx/5xx codes. A
// 502 from the gateway is not a target server error.
func TestParseSchemathesisDropsGatewayGeneratedResponses(t *testing.T) {
	scenario := func(caseID, status string, headers string) string {
		return `{"ScenarioFinished":{"phase":"fuzzing","status":"failure","recorder":{"label":"GET /items/{id}",` +
			`"cases":{"` + caseID + `":{"value":{"method":"GET","path_parameters":{"id":"x"}}}},` +
			`"checks":{"` + caseID + `":[{"name":"not_a_server_error","status":"failure","failure_info":{"failure":{"type":"ServerError","code":"ST101","operation":"GET /items/{id}","title":"Server error"}}}]},` +
			`"interactions":{"` + caseID + `":{"request":{"method":"GET","uri":"https://api.example.test/app/items/x"},"response":{"status_code":` + status + `,"headers":{` + headers + `},"content":{"$base64":""}}}}}}}`
	}
	path := filepath.Join(t.TempDir(), "events.ndjson")
	log := scenario("gw", "502", `"x-xalgorix-gateway-rejection":["1"]`) + "\n" + scenario("t1", "500", `"server":["fixture"]`) + "\n" + scenario("t2", "503", `"server":["fixture"]`) + "\n"
	if err := os.WriteFile(path, []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := parseSchemathesis(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].NativeMessageID != "t1" {
		t.Fatalf("gateway response must be dropped and repeats on one operation deduplicated: %+v", findings)
	}
}

func TestGatewayMarksItsOwnRejectionsAndStripsSpoofedMarker(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(GatewayRejectionHeader, "1")
		w.WriteHeader(500)
	}))
	defer target.Close()
	req := schemathesisTestRequest(t, target.URL+"/app", "/app/private")
	req.GatewayURL, req.GatewayCAPath = "", ""
	g, err := NewRecordingGateway(context.Background(), req, Config{}, "schemathesis")
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	proxy, _ := url.Parse(g.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}
	for _, tc := range []struct {
		method, path string
		status       int
		marked       bool
	}{{"GET", "/app/items/1", 500, false}, {"GET", "/app/private/x", 403, true}, {"DELETE", "/app/items/1", 403, true}} {
		request, _ := http.NewRequest(tc.method, target.URL+tc.path, nil)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != tc.status || (response.Header.Get(GatewayRejectionHeader) != "") != tc.marked {
			t.Errorf("%s %s: status=%d marker=%q", tc.method, tc.path, response.StatusCode, response.Header.Get(GatewayRejectionHeader))
		}
	}
}

func TestArtifactSanitizerRedactsSecretsInsideBase64Bodies(t *testing.T) {
	body := base64.StdEncoding.EncodeToString([]byte(`{"echo":"Authorization: Bearer verified-session-token"}`))
	plain := base64.StdEncoding.EncodeToString([]byte(`{"ok":true}`))
	path := filepath.Join(t.TempDir(), "events.ndjson")
	line := `{"ScenarioFinished":{"recorder":{"interactions":{"a":{"response":{"content":{"$base64":"` + body + `"}}},"b":{"response":{"content":{"$base64":"` + plain + `"}}}}}}}` + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := redactArtifact(path, []string{"verified-session-token"}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	var event map[string]map[string]map[string]map[string]map[string]map[string]map[string]string
	if err := json.Unmarshal(data, &event); err != nil {
		t.Fatal(err)
	}
	interactions := event["ScenarioFinished"]["recorder"]["interactions"]
	decoded, _ := base64.StdEncoding.DecodeString(interactions["a"]["response"]["content"]["$base64"])
	if strings.Contains(string(decoded), "verified-session-token") || !strings.Contains(string(decoded), "[REDACTED]") {
		t.Fatalf("encoded echo of the session survived redaction: %s", decoded)
	}
	if interactions["b"]["response"]["content"]["$base64"] != plain {
		t.Fatal("a body without secrets must keep its exact bytes")
	}
}

func TestSchemathesisIsSelectedOnlyWhenAnAPIDefinitionIsBound(t *testing.T) {
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeBlackBox, WorkflowVersion: "unified-v1",
		Types: []assessment.Type{assessment.TypeAPI}, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://api.example.test/"}}}
	stateOf := func(plan AssessmentPlan) PlanState {
		for _, decision := range plan.Decisions {
			if decision.Scanner == "schemathesis" && decision.TargetID == "app" {
				return decision.State
			}
		}
		return ""
	}
	available := map[string]bool{"schemathesis": true}
	if state := stateOf(PlanAssessment(PlanInput{Config: cfg, Availability: available})); state != PlanOptional {
		t.Fatalf("without an API definition Schemathesis stays optional, got %q", state)
	}
	cfg.APIDefinitions = []assessment.APIDefinitionBinding{{TargetID: "app", DefinitionID: strings.Repeat("a", 64)}}
	plan := PlanAssessment(PlanInput{Config: cfg, Availability: available})
	if state := stateOf(plan); state != PlanSelected {
		t.Fatalf("a bound API definition must select Schemathesis, got %q errors=%+v", state, plan.Errors)
	}
	if !HasAssessmentRunner("schemathesis") || !identityRoutedScanner("schemathesis") || !scannerUsesWebAuth("schemathesis") {
		t.Fatal("Schemathesis must have an adapter, per-identity jobs and the verified session")
	}
	cfg.ScannerSelection = assessment.ScannerSelection{Mode: "custom", Variants: []string{"nuclei"}}
	if state := stateOf(PlanAssessment(PlanInput{Config: cfg, Availability: available})); state == PlanSelected {
		t.Fatal("a custom selection that omits Schemathesis must be respected")
	}
}

func TestSchemathesisDefinitionIncludesWritesOnlyWhenOptedIn(t *testing.T) {
	endpoints := []APIEndpoint{
		{Method: "GET", Path: "/common/countries", Source: "openapi", Resolved: true, Eligible: true},
		{Method: "POST", Path: "/common/countries", Source: "openapi", Resolved: true, Eligible: false, RequestBodyRequired: true, RequestBodyContentTypes: []string{"application/json"}, RequestBodySchema: []byte(`{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`)},
		{Method: "DELETE", Path: "/common/countries/{id}", Source: "openapi", Resolved: true, Eligible: false, Parameters: []APIParameter{{Name: "id", Location: "path", Required: true, SchemaType: "string"}}},
	}
	parse := func(writeFuzz bool) map[string]bool {
		req := schemathesisTestRequest(t, "http://svc.test:5003/common")
		req.APIWriteFuzz, req.APIEndpoints = writeFuzz, endpoints
		doc, _, ops, err := schemathesisDefinition(req)
		if err != nil {
			t.Fatal(err)
		}
		included := map[string]bool{}
		for _, op := range ops {
			if op.Status == "included" {
				included[op.Method] = true
			}
		}
		if writeFuzz {
			var parsed struct {
				Paths map[string]map[string]struct {
					RequestBody json.RawMessage `json:"requestBody"`
				} `json:"paths"`
			}
			if json.Unmarshal(doc, &parsed) != nil {
				t.Fatal("generated schema is not JSON")
			}
			if len(parsed.Paths["/countries"]["post"].RequestBody) == 0 {
				t.Fatal("write operation has no requestBody in the generated schema")
			}
		}
		return included
	}
	readOnly := parse(false)
	if readOnly["GET"] != true || readOnly["POST"] || readOnly["DELETE"] {
		t.Fatalf("writes included without opt-in: %v", readOnly)
	}
	withWrites := parse(true)
	if !withWrites["GET"] || !withWrites["POST"] || !withWrites["DELETE"] {
		t.Fatalf("writes not included with opt-in: %v", withWrites)
	}
}
