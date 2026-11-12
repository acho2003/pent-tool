package scanner

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Schemathesis (pinned 4.32.5) generates property-based requests from an
// OpenAPI definition. Xalgorix never hands it the operator's original document:
// it receives a definition rebuilt from the approved, in-scope GET/HEAD
// operations only, it runs only through the recording gateway (which injects
// the verified session itself, enforces scope, exclusions, methods and the
// request budget, and records every request), and it checks only for server
// errors, because the rebuilt definition carries no response schemas.
const (
	schemathesisMaxDuration          = 20 * time.Minute
	schemathesisDefaultDuration      = 15 * time.Minute
	schemathesisDefaultExamples      = 25
	schemathesisDefaultWriteExamples = 200
	schemathesisThoroughExample      = 50
)

// schemathesisConfig disables the coverage phase's "unspecified HTTP method"
// cases. Without it Schemathesis 4.32.5 sends TRACE, QUERY, POST, PUT, PATCH and
// DELETE to every documented path even when the definition declares GET only
// (verified against the pinned release).
const schemathesisConfig = "[phases.coverage]\nunexpected-methods = []\n"

// schemathesisCheck is the only response check run. Conformance checks would
// judge responses against definitions Xalgorix invented, and ignored_auth would
// report the gateway's re-injected session as an authentication bypass.
const schemathesisCheck = "not_a_server_error"

type schemathesisRunner struct{}

func (schemathesisRunner) Name() string { return "schemathesis" }
func (schemathesisRunner) Descriptor() Descriptor {
	return Descriptor{Name: "schemathesis", Summary: "Property-based fuzzing of approved read-only OpenAPI operations", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightLight, Applies: appliesToHost}
}
func (r schemathesisRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	return executeSpec(ctx, r.Name(), req, cfg, buildSchemathesis(req, cfg), emit)
}

// SchemathesisOperation is the disposition of one API operation: whether it
// was included in the definition handed to Schemathesis, and why not.
type SchemathesisOperation struct {
	DefinitionID string `json:"definition_id,omitempty"`
	OperationID  string `json:"operation_id"`
	Method       string `json:"method"`
	Path         string `json:"path"`
	Status       string `json:"status"`
	Reason       string `json:"reason,omitempty"`
}

// schemathesisBaseURL is the approved application URL every operation path is
// joined under, matching apiEndpointURL, so Schemathesis's own capability
// probes (sent to the base URL) stay inside the approved boundary too.
func schemathesisBaseURL(target string) (*url.URL, error) {
	raw := strings.TrimSpace(target)
	if !strings.HasPrefix(strings.ToLower(raw), "http://") && !strings.HasPrefix(strings.ToLower(raw), "https://") {
		raw = "http://" + raw
	}
	base, err := url.Parse(raw)
	if err != nil || base.Host == "" || base.User != nil || (base.Scheme != "http" && base.Scheme != "https") {
		return nil, fmt.Errorf("Schemathesis requires an explicit HTTP(S) application URL")
	}
	base.Scheme, base.Host = strings.ToLower(base.Scheme), strings.ToLower(base.Host)
	base.RawQuery, base.Fragment, base.RawPath = "", "", ""
	base.Path = strings.TrimSuffix(base.Path, "/")
	return base, nil
}

var schemathesisPathParam = regexp.MustCompile(`\{([^{}/]+)\}`)

// schemathesisDefinition rebuilds an OpenAPI 3.0 document from the approved
// operations. Only GET/HEAD OpenAPI operations without a required body whose
// paths stay under the application URL, inside the approved scope and outside
// its exclusions are included; every other operation gets an explicit reason.
func schemathesisDefinition(req Request) ([]byte, string, []SchemathesisOperation, error) {
	base, err := schemathesisBaseURL(req.Target)
	if err != nil {
		return nil, "", nil, err
	}
	contextRule, err := applicationContextRegex(base.String())
	if err != nil {
		return nil, "", nil, err
	}
	contextPattern, err := regexp.Compile(contextRule)
	if err != nil {
		return nil, "", nil, err
	}
	paths := map[string]map[string]any{}
	usedIDs := map[string]bool{}
	seen := map[string]bool{}
	var operations []SchemathesisOperation
	for _, endpoint := range req.APIEndpoints {
		method := strings.ToUpper(strings.TrimSpace(endpoint.Method))
		key := method + " " + endpoint.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		op := SchemathesisOperation{DefinitionID: endpoint.DefinitionID, OperationID: endpoint.OperationID, Method: method, Path: endpoint.Path, Status: "skipped"}
		if reason := schemathesisSkipReason(req, base, contextPattern, endpoint, method); reason != "" {
			op.Reason = reason
			operations = append(operations, op)
			continue
		}
		operationID := strings.TrimSpace(endpoint.OperationID)
		if operationID == "" {
			operationID = strings.ToLower(method) + " " + endpoint.Path
		}
		for unique, n := operationID, 2; ; n++ {
			if !usedIDs[unique] {
				operationID = unique
				break
			}
			unique = fmt.Sprintf("%s-%d", operationID, n)
		}
		usedIDs[operationID] = true
		parameters, note := schemathesisParameters(base, endpoint)
		// Schemathesis appends schema paths to the base URL itself.
		schemaPath := relativeOperationPath(base.Path, endpoint.Path)
		if paths[schemaPath] == nil {
			paths[schemaPath] = map[string]any{}
		}
		operationDoc := map[string]any{
			"operationId": operationID,
			"parameters":  parameters,
			"responses":   map[string]any{"default": map[string]string{"description": "Any response"}},
		}
		if req.APIWriteFuzz && (method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE") {
			if body := schemathesisRequestBody(endpoint); body != nil {
				operationDoc["requestBody"] = body
			}
		}
		paths[schemaPath][strings.ToLower(method)] = operationDoc
		op.Status, op.Reason = "included", note
		operations = append(operations, op)
	}
	if len(paths) == 0 {
		return nil, base.String(), operations, nil
	}
	document, err := json.Marshal(map[string]any{
		"openapi": "3.0.3",
		"info":    map[string]string{"title": "Approved Xalgorix read-only API operations", "version": "1"},
		"paths":   paths,
	})
	return document, base.String(), operations, err
}

func schemathesisSkipReason(req Request, base *url.URL, boundary *regexp.Regexp, endpoint APIEndpoint, method string) string {
	writeMethod := method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE"
	switch {
	case endpoint.Source == "graphql":
		return "GraphQL operations are sent as POST bodies, which the read-only gateway policy does not admit for generated input"
	case writeMethod && !req.APIWriteFuzz:
		return "state-changing method is not fuzzed"
	case !writeMethod && method != "GET" && method != "HEAD":
		return "state-changing method is not fuzzed"
	case endpoint.RequestBodyRequired && !req.APIWriteFuzz:
		return "operation requires a request body"
	case !strings.HasPrefix(endpoint.Path, "/") || strings.ContainsAny(endpoint.Path, "?#\\"):
		return "operation path is not a plain absolute path"
	}
	if endpoint.Origin != "" {
		origin, err := url.Parse(endpoint.Origin)
		if err != nil || !strings.EqualFold(origin.Scheme, base.Scheme) || !strings.EqualFold(origin.Host, base.Host) {
			return "definition origin differs from the approved application URL"
		}
	}
	probe := *base
	concrete := schemathesisPathParam.ReplaceAllString(endpoint.Path, "x")
	for _, segment := range strings.Split(concrete, "/") {
		if segment == "." || segment == ".." {
			return "operation path escapes the application boundary"
		}
	}
	probe.Path = joinOperationPath(base.Path, concrete)
	raw := probe.String()
	if !boundary.MatchString(raw) {
		return "operation path is outside the application boundary"
	}
	if req.AppScope == nil {
		return "approved scope is required"
	}
	if ok, reason := req.AppScope.Allows(raw); !ok {
		return "outside approved scope: " + reason
	}
	if excluded, reason := req.AppScope.Excluded(method, raw); excluded {
		return "excluded: " + reason
	}
	return ""
}

// schemathesisParameters declares path and query parameters with their schema
// types, using operator-supplied values (already applied to RequestURL) as
// examples. Header and cookie parameters are not generated: the gateway owns
// credentials, and a required one is reported in the operation's note.
func schemathesisParameters(base *url.URL, endpoint APIEndpoint) ([]map[string]any, string) {
	examples := schemathesisSuppliedValues(base, endpoint)
	declared := map[string]bool{}
	var out []map[string]any
	var omitted []string
	for _, parameter := range endpoint.Parameters {
		location := strings.ToLower(parameter.Location)
		if location != "path" && location != "query" {
			if parameter.Required {
				omitted = append(omitted, location+":"+parameter.Name)
			}
			continue
		}
		if declared[location+"\x00"+parameter.Name] {
			continue
		}
		declared[location+"\x00"+parameter.Name] = true
		schema := schemathesisParameterSchema(parameter.SchemaType)
		if value, ok := examples[location+"\x00"+parameter.Name]; ok {
			schema["example"] = value
		}
		out = append(out, map[string]any{"name": parameter.Name, "in": location, "required": parameter.Required || location == "path", "schema": schema})
	}
	for _, match := range schemathesisPathParam.FindAllStringSubmatch(endpoint.Path, -1) {
		if declared["path\x00"+match[1]] {
			continue
		}
		declared["path\x00"+match[1]] = true
		schema := map[string]any{"type": "string"}
		if value, ok := examples["path\x00"+match[1]]; ok {
			schema["example"] = value
		}
		out = append(out, map[string]any{"name": match[1], "in": "path", "required": true, "schema": schema})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return fmt.Sprint(out[i]["in"], out[i]["name"]) < fmt.Sprint(out[j]["in"], out[j]["name"])
	})
	if out == nil {
		out = []map[string]any{}
	}
	note := ""
	if len(omitted) > 0 {
		sort.Strings(omitted)
		note = "required header or cookie parameters are not generated: " + strings.Join(omitted, ", ")
	}
	return out, note
}

func schemathesisParameterSchema(kind string) map[string]any {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "integer", "number", "boolean":
		return map[string]any{"type": strings.ToLower(strings.TrimSpace(kind))}
	case "array":
		return map[string]any{"type": "array", "items": map[string]any{"type": "string"}}
	default:
		return map[string]any{"type": "string"}
	}
}

// schemathesisSuppliedValues recovers the operator-supplied path and query
// values from a materialized request URL by aligning it with the template.
func schemathesisSuppliedValues(base *url.URL, endpoint APIEndpoint) map[string]string {
	values := map[string]string{}
	if endpoint.RequestURL == "" {
		return values
	}
	concrete, err := url.Parse(endpoint.RequestURL)
	if err != nil {
		return values
	}
	for name, list := range concrete.Query() {
		if len(list) > 0 {
			values["query\x00"+name] = list[0]
		}
	}
	relative := strings.TrimPrefix(concrete.EscapedPath(), (&url.URL{Path: base.Path}).EscapedPath())
	template := strings.Split(strings.Trim(endpoint.Path, "/"), "/")
	actual := strings.Split(strings.Trim(relative, "/"), "/")
	if len(template) != len(actual) {
		return values
	}
	for i, segment := range template {
		match := schemathesisPathParam.FindStringSubmatch(segment)
		if match == nil || match[0] != segment {
			continue
		}
		if value, err := url.PathUnescape(actual[i]); err == nil {
			values["path\x00"+match[1]] = value
		}
	}
	return values
}

func buildSchemathesis(req Request, cfg Config) commandSpec {
	duration := cfg.SchemathesisTimeout
	if duration <= 0 {
		duration = schemathesisDefaultDuration
	}
	if duration > schemathesisMaxDuration {
		duration = schemathesisMaxDuration
	}
	if strings.TrimSpace(cfg.SchemathesisPath) == "" {
		return commandSpec{notApp: "Schemathesis executable is not configured", timeout: duration}
	}
	if req.GatewayURL == "" || req.GatewayCAPath == "" {
		return commandSpec{notApp: "Schemathesis runs only through the recording gateway of the unified workflow", timeout: duration}
	}
	document, baseURL, operations, err := schemathesisDefinition(req)
	if err != nil {
		return commandSpec{notApp: err.Error(), timeout: duration}
	}
	included, skipped := 0, map[string]int{}
	for _, op := range operations {
		if op.Status == "included" {
			included++
		} else {
			skipped[op.Reason]++
		}
	}
	if included == 0 {
		reason := "Schemathesis has no approved read-only OpenAPI operation to test"
		if len(operations) > 0 {
			reason += " (" + schemathesisSkipSummary(skipped) + ")"
		}
		return commandSpec{notApp: reason, timeout: duration}
	}

	base := filepath.Join(req.ScanDir, "scanner-output", "schemathesis")
	artifact := filepath.Join(base, "events.ndjson")
	definitionPath := filepath.Join(base, "approved-operations.openapi.json")
	configPath := filepath.Join(base, "schemathesis.toml")
	operationsPath := filepath.Join(base, "operations.json")
	examples := schemathesisDefaultExamples
	if req.Profile == ProfileThorough || req.Profile == ProfileNextjsDeep {
		examples = schemathesisThoroughExample
	}
	// Write fuzzing caps generated requests per operation to the operator's
	// bound (default 200), so an opt-in destructive run stays bounded.
	if req.APIWriteFuzz {
		cap := req.APIWriteFuzzMax
		if cap <= 0 {
			cap = schemathesisDefaultWriteExamples
		}
		examples = cap
	}
	// Flags verified against the pinned 4.32.5 CLI:
	//   --phases examples,coverage,fuzzing : no stateful link-following phase
	//   --workers 1 / --rate-limit         : one request at a time, at the
	//                                        profile rate (the gateway also waits
	//                                        on the shared assessment budget)
	//   --max-redirects 0                  : a redirect is reported, not followed
	//   --generation-database none         : no example state outside this attempt
	//   --output-sanitize true             : mask credentials in its own output
	// The gateway proxy is appended by executeSpec; the gateway CA verifies TLS.
	args := []string{
		"--config-file", configPath,
		"run", definitionPath,
		"--url", baseURL,
		"--phases", "examples,coverage,fuzzing",
		"--checks", schemathesisCheck,
		"--workers", "1",
		"--max-examples", strconv.Itoa(examples),
		"--request-timeout", "10",
		"--request-retries", "0",
		"--max-redirects", "0",
		"--generation-database", "none",
		"--output-sanitize", "true",
		"--no-color",
		"--tls-verify", req.GatewayCAPath,
		"--report", "ndjson",
		"--report-ndjson-path", artifact,
	}
	if cfg.RateRPS > 0 {
		args = append(args, "--rate-limit", strconv.Itoa(cfg.RateRPS)+"/s")
	}
	var limitations []RunLimitation
	if len(skipped) > 0 {
		limitations = append(limitations, RunLimitation{Kind: "operations_not_tested", Reason: "API operations not tested by Schemathesis: " + schemathesisSkipSummary(skipped)})
	}
	manifest, err := json.MarshalIndent(map[string]any{"base_url": SafeTelemetryURL(baseURL), "check": schemathesisCheck, "max_examples": examples, "operations": operations}, "", "  ")
	if err != nil {
		return commandSpec{notApp: "Schemathesis operation manifest could not be encoded", timeout: duration}
	}
	return commandSpec{
		path:        cfg.SchemathesisPath,
		args:        args,
		artifact:    artifact,
		timeout:     duration,
		okExit:      map[int]bool{1: true}, // 1 = failures or errors found; the event log decides which
		limitations: limitations,
		classify: func(exitCode int, _ string) (string, string, bool) {
			if exitCode == 2 {
				return "failed", "Schemathesis could not load the approved operation definition or its configuration", true
			}
			return "", "", false
		},
		prepare: func() error {
			if err := os.MkdirAll(base, 0o700); err != nil {
				return fmt.Errorf("create Schemathesis output directory: %w", err)
			}
			for path, data := range map[string][]byte{definitionPath: document, configPath: []byte(schemathesisConfig), operationsPath: manifest} {
				if err := os.WriteFile(path, data, 0o600); err != nil {
					return fmt.Errorf("write Schemathesis input: %w", err)
				}
			}
			return nil
		},
	}
}

func schemathesisSkipSummary(skipped map[string]int) string {
	reasons := make([]string, 0, len(skipped))
	for reason, count := range skipped {
		reasons = append(reasons, fmt.Sprintf("%d %s", count, reason))
	}
	sort.Strings(reasons)
	return strings.Join(reasons, "; ")
}

// schemathesisRunState reads the event log for how the run ended. A fatal
// error fails the run; a run whose end was not recorded, that stopped early or
// whose test cases hit errors (network failures, gateway refusals) is partial.
func schemathesisRunState(path string) (fatal string, limitations []RunLimitation, err error) {
	file, err := os.Open(path)
	if err != nil {
		return "", nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 64<<20)
	finished, stopReason := false, ""
	errorsByType := map[string]int{}
	line := 0
	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}
		var event map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &event); err != nil {
			return "", nil, fmt.Errorf("parse Schemathesis events: line %d: %w", line, err)
		}
		for kind, body := range event {
			switch kind {
			case "EngineFinished":
				var value struct {
					StopReason string `json:"stop_reason"`
				}
				_ = json.Unmarshal(body, &value)
				finished, stopReason = true, value.StopReason
			case "FatalError":
				// 4.32.5 records {"exception": {"type": ..., "message": ...}}.
				var value struct {
					Exception struct {
						Type    string `json:"type"`
						Message string `json:"message"`
					} `json:"exception"`
				}
				_ = json.Unmarshal(body, &value)
				fatal = "Schemathesis stopped with a fatal error"
				detail := strings.TrimSpace(strings.SplitN(value.Exception.Message, "\n", 2)[0])
				if value.Exception.Type != "" {
					detail = strings.TrimSpace(value.Exception.Type + ": " + detail)
				}
				if detail != "" {
					fatal += ": " + detail
				}
			case "NonFatalError":
				var value struct {
					Value struct {
						Type string `json:"type"`
					} `json:"value"`
				}
				_ = json.Unmarshal(body, &value)
				name := value.Value.Type
				if name == "" {
					name = "error"
				}
				errorsByType[name]++
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return "", nil, fmt.Errorf("parse Schemathesis events: %w", err)
	}
	if fatal != "" {
		return fatal, nil, nil
	}
	if !finished {
		limitations = append(limitations, RunLimitation{Kind: "run_incomplete", Reason: "Schemathesis did not record the end of its run; results are partial"})
	} else if stopReason != "completed" {
		limitations = append(limitations, RunLimitation{Kind: "run_incomplete", Reason: "Schemathesis stopped before completing: " + stopReason})
	}
	if len(errorsByType) > 0 {
		var parts []string
		for name, count := range errorsByType {
			parts = append(parts, fmt.Sprintf("%s: %d", name, count))
		}
		sort.Strings(parts)
		limitations = append(limitations, RunLimitation{Kind: "test_case_errors", Reason: "Schemathesis test cases ended in errors and did not exercise the API (" + strings.Join(parts, ", ") + ")"})
	}
	return "", limitations, nil
}

type schemathesisInteraction struct {
	Request struct {
		Method string `json:"method"`
		URI    string `json:"uri"`
	} `json:"request"`
	Response *struct {
		StatusCode int                 `json:"status_code"`
		Headers    map[string][]string `json:"headers"`
		Content    struct {
			Base64 string `json:"$base64"`
		} `json:"content"`
	} `json:"response"`
}

type schemathesisCase struct {
	Value struct {
		PathParameters map[string]any `json:"path_parameters"`
		Query          map[string]any `json:"query"`
		Meta           struct {
			Phase struct {
				Name string `json:"name"`
				Data struct {
					Description string `json:"description"`
				} `json:"data"`
			} `json:"phase"`
		} `json:"meta"`
	} `json:"value"`
}

type schemathesisCheckResult struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	FailureInfo *struct {
		Failure struct {
			Type      string `json:"type"`
			Code      string `json:"code"`
			Operation string `json:"operation"`
			Title     string `json:"title"`
			Message   string `json:"message"`
		} `json:"failure"`
	} `json:"failure_info"`
}

type schemathesisScenario struct {
	Phase    string `json:"phase"`
	Recorder struct {
		Label        string                               `json:"label"`
		Cases        map[string]schemathesisCase          `json:"cases"`
		Checks       map[string][]schemathesisCheckResult `json:"checks"`
		Interactions map[string]schemathesisInteraction   `json:"interactions"`
	} `json:"recorder"`
}

// parseSchemathesis reports server errors the target itself returned for a
// generated request. One finding is kept per operation and failure code, from
// the first failing case in event order. Responses the recording gateway
// produced (blocked, budget or upstream failures) are not target behaviour and
// are dropped; so is any failure without a recorded response.
func parseSchemathesis(artifact string) ([]Finding, error) {
	file, err := os.Open(artifact)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 64<<20)
	var findings []Finding
	seen := map[string]bool{}
	line := 0
	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}
		var event struct {
			ScenarioFinished *schemathesisScenario `json:"ScenarioFinished"`
		}
		if err := json.Unmarshal([]byte(raw), &event); err != nil {
			return findings, fmt.Errorf("parse Schemathesis events: line %d: %w", line, err)
		}
		scenario := event.ScenarioFinished
		if scenario == nil {
			continue
		}
		caseIDs := make([]string, 0, len(scenario.Recorder.Checks))
		for id := range scenario.Recorder.Checks {
			caseIDs = append(caseIDs, id)
		}
		sort.Strings(caseIDs)
		for _, id := range caseIDs {
			for _, check := range scenario.Recorder.Checks[id] {
				if check.Status != "failure" || check.FailureInfo == nil {
					continue
				}
				failure := check.FailureInfo.Failure
				interaction, ok := scenario.Recorder.Interactions[id]
				if !ok || interaction.Response == nil || schemathesisGatewayResponse(interaction.Response.Headers) {
					continue
				}
				operation := failure.Operation
				if operation == "" {
					operation = scenario.Recorder.Label
				}
				key := operation + "\x00" + failure.Code
				if seen[key] {
					continue
				}
				seen[key] = true
				findings = append(findings, schemathesisFinding(operation, failure.Code, failure.Title, failure.Message, scenario.Phase, id, scenario.Recorder.Cases[id], interaction))
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return findings, fmt.Errorf("parse Schemathesis events: %w", err)
	}
	return findings, nil
}

func schemathesisGatewayResponse(headers map[string][]string) bool {
	for name := range headers {
		if strings.EqualFold(name, GatewayRejectionHeader) {
			return true
		}
	}
	return false
}

func schemathesisFinding(operation, code, title, message, phase, caseID string, generated schemathesisCase, interaction schemathesisInteraction) Finding {
	status := interaction.Response.StatusCode
	scenario := generated.Value.Meta.Phase.Data.Description
	if phase == "" {
		phase = generated.Value.Meta.Phase.Name
	}
	var parameters []string
	for name := range generated.Value.PathParameters {
		parameters = append(parameters, name)
	}
	for name := range generated.Value.Query {
		parameters = append(parameters, name)
	}
	sort.Strings(parameters)
	finding := Finding{
		SourceID:   "schemathesis:" + code + ":" + operation,
		Scanner:    "schemathesis",
		RuleID:     code,
		Title:      title,
		Severity:   "info",
		Target:     interaction.Request.URI,
		Endpoint:   interaction.Request.URI,
		Method:     strings.ToUpper(interaction.Request.Method),
		Confidence: "confirmed",
		// The case ID locates the request/response pair in the saved event log.
		EvidenceRef:     caseID,
		NativeMessageID: caseID,
	}
	if len(parameters) == 1 {
		finding.Parameter = parameters[0]
	}
	if code == "ST101" {
		finding.Title = "API server error on generated input"
		finding.Severity = "low"
		finding.CWE = "CWE-755"
		finding.Description = fmt.Sprintf("A schema-derived %s request to %s received HTTP %d from the target. A 5xx response to generated input usually means unvalidated input reached application code without error handling.", phase, operation, status)
		finding.Remediation = "Validate path and query parameters against their declared types and return a 4xx response for invalid input instead of an unhandled error."
	} else {
		finding.Description = strings.TrimSpace(fmt.Sprintf("Schemathesis check failed for %s during the %s phase. %s", operation, phase, message))
	}
	evidence := fmt.Sprintf("%s %s -> HTTP %d", finding.Method, interaction.Request.URI, status)
	if scenario != "" {
		evidence += "\nGenerated case: " + scenario
	}
	if len(parameters) > 0 {
		evidence += "\nGenerated parameters: " + strings.Join(parameters, ", ")
	}
	if body, err := base64.StdEncoding.DecodeString(interaction.Response.Content.Base64); err == nil && len(body) > 0 {
		excerpt := string(body)
		if len(excerpt) > 1000 {
			excerpt = excerpt[:1000]
		}
		evidence += "\nResponse excerpt: " + excerpt
	}
	finding.Evidence = evidence
	return finding
}

// schemathesisRequestBody returns the application/json requestBody object for a
// write operation, using the operation's captured body schema or a permissive
// object schema when it required a body but none was captured. Returns nil when
// the operation declares no body.
func schemathesisRequestBody(endpoint APIEndpoint) map[string]any {
	var schema any
	if len(endpoint.RequestBodySchema) > 0 {
		if json.Unmarshal(endpoint.RequestBodySchema, &schema) != nil {
			schema = nil
		}
	}
	if schema == nil {
		hasJSON := false
		for _, contentType := range endpoint.RequestBodyContentTypes {
			if strings.Contains(strings.ToLower(contentType), "json") {
				hasJSON = true
			}
		}
		if !hasJSON && !endpoint.RequestBodyRequired {
			return nil
		}
		schema = map[string]any{"type": "object"}
	}
	return map[string]any{"required": endpoint.RequestBodyRequired, "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
}
