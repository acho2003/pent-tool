package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func fuzzApprovalID(approval assessment.FuzzApproval) string {
	data, _ := json.Marshal(approval)
	return inventoryID(string(data))
}
func appendFuzzJobs(cfg assessment.AssessmentConfig, jobs []PlanJob, availability map[string]bool) []PlanJob {
	for _, approval := range cfg.FuzzApprovals {
		for _, target := range cfg.Targets {
			if target.ID != approval.TargetID {
				continue
			}
			state := PlanSelected
			if available, known := availability["wapiti"]; known && !available {
				state = PlanUnavailable
			}
			id := fuzzApprovalID(approval)
			jobs = append(jobs, PlanJob{ID: "wapiti-post:" + target.ID + ":" + id, Scanner: "wapiti", TargetID: target.ID, Target: target.Value, Variant: "wapiti-post:" + id, FuzzApprovalID: id, State: state, AssessmentType: assessment.TypeAPI, AssessmentTypes: []assessment.Type{assessment.TypeAPI}, Reason: "Explicit bounded repeated POST testing with a controlled fixture and cleanup"})
		}
	}
	return jobs
}

func prepareWapitiPostRequest(req *Request, surface *AttackSurface) error {
	approval := req.WapitiPostApproval
	if approval == nil || (req.Scope != "app:"+approval.TargetID && req.Scope != "host:"+approval.TargetID) || req.AuthContextID != "" || !expandedWorkflowRequest(*req) || !req.TypedAssessment || !req.TestEnvironment || req.AppScope == nil || !approval.RepeatTestingApproved || approval.Scanner != "wapiti" || approval.RequestLimit < 1 || approval.RequestLimit > 1000 || approval.Method != "POST" || approval.ContentType != "application/x-www-form-urlencoded" {
		return fmt.Errorf("bounded form fuzz approval is missing or invalid")
	}
	if !approvedWriteMatchesEndpoint(req.APIOperationEndpoints, approval.WriteApproval) {
		return fmt.Errorf("fuzz approval does not match a supplied API operation")
	}
	for _, endpoint := range req.APIOperationEndpoints {
		if endpoint.OperationID == approval.OperationID && endpoint.Path == approval.Path && strings.EqualFold(endpoint.Method, "POST") && len(endpoint.RequestBodyContentTypes) > 0 {
			compatible := false
			for _, contentType := range endpoint.RequestBodyContentTypes {
				if contentType == approval.ContentType {
					compatible = true
				}
			}
			if !compatible {
				return fmt.Errorf("supplied API operation does not support URL-encoded POST")
			}
		}
	}
	writeURL, err := scopedAPIPath(req.Target, approval.Path)
	if err != nil {
		return err
	}
	cleanupURL, err := scopedAPIPath(req.Target, approval.CleanupPath)
	if err != nil || approval.CleanupMethod != "DELETE" {
		return fmt.Errorf("form fuzzing requires an exact scoped DELETE cleanup")
	}
	for _, entry := range []struct{ method, url string }{{"POST", writeURL}, {"DELETE", cleanupURL}} {
		if allowed, _ := req.AppScope.Allows(entry.url); !allowed {
			return fmt.Errorf("fuzz or cleanup request is outside approved scope")
		}
		if excluded, _ := req.AppScope.Excluded(entry.method, entry.url); excluded {
			return fmt.Errorf("fuzz or cleanup request is excluded")
		}
	}
	body, err := readAPIFixture(req.APIFixtureDir, approval.FixtureRef)
	if err != nil || len(body) == 0 || len(body) > 64<<10 {
		return fmt.Errorf("bounded URL-encoded fixture is unavailable")
	}
	values, err := url.ParseQuery(string(body))
	if err != nil || len(values) == 0 || len(values) > 64 {
		return fmt.Errorf("fixture must contain valid bounded URL-encoded fields")
	}
	if err := ValidateWapitiFormFixture(body); err != nil {
		return err
	}
	if approval.CleanupRef != "" {
		if _, err := readAPIFixture(req.APIFixtureDir, approval.CleanupRef); err != nil {
			return fmt.Errorf("cleanup fixture unavailable")
		}
	}
	req.WapitiPostURL, req.WapitiPostBody = writeURL, string(body)
	req.EndpointTargets = []string{writeURL}
	req.StructuredDispatch = true
	endpoint, ok := requestVariantEndpoint(req.Scope, writeURL, "POST", approval.ContentType, string(body), req.TargetAuth != "")
	if !ok {
		return fmt.Errorf("form request cannot be materialized")
	}
	endpoint.State, endpoint.Kind, endpoint.ObservationKind = EndpointStateInScope, "api", "seed"
	endpoint.ObservedWithAuth, endpoint.RequiresAuth = false, nil
	endpoint.StateReason = "explicitly approved bounded form fuzz input"
	if surface != nil {
		indexes := map[string]int{}
		for i := range surface.Endpoints {
			indexes[surface.Endpoints[i].ID] = i
		}
		mergeSurfaceEndpoint(surface, indexes, endpoint)
		setEndpointCoverage(&surface.Endpoints[indexes[endpoint.ID]], EndpointScannerCoverage{Scanner: "wapiti", Status: "dispatched", Reason: endpoint.StateReason, StartedAt: time.Now().UTC().Format(time.RFC3339Nano)})
	}
	req.InputRequests = []ScannerRequestInput{{EndpointID: endpoint.ID, AuthContextID: endpoint.AuthContextID, InventoryScope: req.Scope, URL: writeURL, Method: "POST", ContentType: approval.ContentType, BodyDigest: endpoint.BodyDigest, Body: string(body), Selected: true, Reason: endpoint.StateReason}}
	req.Secrets = append(req.Secrets, string(body))
	for name, items := range values {
		if sensitiveTelemetryKey(name) {
			req.Secrets = append(req.Secrets, items...)
		}
	}
	return nil
}

const wapitiPostModules = "passive,xss:post,sql:post,file:post,redirect:post,crlf:post"

func buildWapitiPost(req Request, cfg Config) commandSpec {
	spec := buildWapiti(req, cfg)
	if spec.notApp != "" {
		return spec
	}
	for i := range spec.args {
		if spec.args[i] == "-m" && i+1 < len(spec.args) {
			spec.args[i+1] = wapitiPostModules
		}
	}
	spec.args = append(spec.args, "--data", req.WapitiPostBody)
	return spec
}

// The whole bounded campaign is journaled once before process execution. A new
// process cannot replay consent, reset its budget, or guess whether writes ran.
func runWapitiPost(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	if err := prepareWapitiPostRequest(&req, nil); err != nil {
		return failedServiceRun("wapiti", req, err.Error(), emit)
	}
	if req.Gateway == nil {
		return failedServiceRun("wapiti", req, "approved POST testing requires the recording gateway", emit)
	}
	journal, err := openRequestWriteJournal(req)
	if err != nil {
		return failedServiceRun("wapiti", req, "form fuzz journal unavailable", emit)
	}
	approval := req.WapitiPostApproval
	key := req.Scope + ":fuzz:" + fuzzApprovalID(*approval)
	cleanupURL, _ := scopedAPIPath(req.Target, approval.CleanupPath)
	entry := WriteJournalEntry{OperationID: key, JobID: "wapiti-post", Method: "POST", RedactedURL: req.WapitiPostURL, FixtureRef: approval.FixtureRef, CleanupMethod: "DELETE", CleanupURL: cleanupURL, CleanupRef: approval.CleanupRef}
	if err = journal.RecordIntent(entry); err != nil {
		return failedServiceRun("wapiti", req, "form fuzz consent is already journaled; replay was refused", emit)
	}
	req.Gateway.ArmFormFuzz()
	run := executePolicySpec(ctx, "wapiti", req, cfg, buildWapitiPost(req, cfg), emit)
	// Cleanup remains explicitly authorized after a scanner stop. It uses a short
	// detached deadline, the same origin binding, and a freshly verified session.
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := req.Gateway.drainFormFuzz(cleanupCtx); err != nil {
		markFormCleanupFailure(&run)
		run.Reason = "pending POST traffic could not be drained before cleanup"
		return run
	}
	auth := req.TargetAuth
	if req.AuthRefresh != nil {
		headers, err := req.AuthRefresh(cleanupCtx, strings.Split(auth, "\n"))
		if err != nil {
			markFormCleanupFailure(&run)
			run.Reason = "fuzz stopped; authentication prevented declared cleanup"
			run.AuthState = assessment.StateExpired
			return run
		}
		auth = strings.Join(headers, "\n")
	}
	body, err := readAPIFixture(req.APIFixtureDir, approval.CleanupRef)
	if approval.CleanupRef == "" {
		body, err = nil, nil
	}
	if err == nil {
		err = cfg.Budget.Wait(cleanupCtx)
	}
	if err == nil {
		var response *http.Response
		response, err = sendScopedAPIRequest(cleanupCtx, cfg, cleanupURL, "DELETE", body, approval.CleanupContentType, auth)
		if response != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
			response.Body.Close()
			req.Gateway.record(CoverageEvent{Kind: "observed", Phase: "cleanup", URL: cleanupURL, Method: "DELETE", ResponseCode: response.StatusCode, NativeRef: key})
			if response.StatusCode < 200 || response.StatusCode >= 300 {
				err = fmt.Errorf("cleanup returned non-success")
			}
		}
	}
	req.Gateway.mu.Lock()
	observed, uncertain := req.Gateway.formFuzzObserved, req.Gateway.formFuzzUncertain || req.Gateway.failed != nil
	req.Gateway.mu.Unlock()
	if err == nil && uncertain {
		err = fmt.Errorf("POST execution evidence is incomplete")
	}
	if err == nil {
		err = journal.MarkSent(key)
		if err == nil {
			err = journal.MarkCleanup(key, true)
		}
	}
	if err != nil {
		markFormCleanupFailure(&run)
		run.Reason = "declared form cleanup did not complete; journal prevents automatic resume"
		if run.Status == "completed" {
			run.Status = "failed"
		}
	}
	if err == nil && observed == 0 {
		run.Completeness, run.Outcome = "partial", "PARTIAL"
		run.Reason = "scanner produced no observed approved POST request"
		run.Limitations = append(run.Limitations, RunLimitation{Kind: "submission_unproven", Reason: run.Reason})
	}
	return run
}

func (g *RecordingGateway) admitFormFuzz(raw, contentType string, body []byte) bool {
	allowed, _ := g.admitFormFuzzDecision(raw, contentType, body)
	return allowed
}
func (g *RecordingGateway) admitFormFuzzDecision(raw, contentType string, body []byte) (bool, string) {
	approval := g.req.WapitiPostApproval
	if approval == nil {
		return false, ""
	}
	if !approval.RepeatTestingApproved || raw != g.req.WapitiPostURL || !g.req.TestEnvironment {
		return false, "POST is outside the exact approved form operation"
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return false, "POST content type is not the approved URL-encoded format"
	}
	if allowed, _ := g.req.AppScope.Allows(raw); !allowed {
		return false, "POST destination is outside approved scope"
	}
	if excluded, _ := g.req.AppScope.Excluded("POST", raw); excluded {
		return false, "POST operation is excluded"
	}
	values, err := url.ParseQuery(string(body))
	if err != nil || len(body) > 64<<10 {
		return false, "POST body is malformed or exceeds the fixture budget"
	}
	original, err := url.ParseQuery(g.req.WapitiPostBody)
	if err != nil || len(values) != len(original) {
		return false, "POST field structure differs from the approved fixture"
	}
	for name, items := range original {
		if len(values[name]) != len(items) {
			return false, "POST field multiplicity differs from the approved fixture"
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.formFuzzArmed {
		return false, "form fuzz journal intent is not active"
	}
	if g.formFuzzRequests >= approval.RequestLimit {
		return false, "approved POST request budget exhausted"
	}
	g.formFuzzRequests++
	g.formFuzzInFlight.Add(1)
	return true, ""
}

func markFormCleanupFailure(run *Run) {
	run.Completeness, run.GapKind = "partial", GapInterruptedWrite
	if run.Outcome != "TIMEOUT" && run.ExecutionOutcome != "TIMEOUT" {
		run.Outcome = "PARTIAL"
	}
	if run.Status == "completed" {
		run.Status = "failed"
	}
	run.Limitations = append(run.Limitations, RunLimitation{Kind: "cleanup_failed", Reason: "declared form cleanup did not complete; automatic resume is blocked by the write journal"})
}

func (g *RecordingGateway) drainFormFuzz(ctx context.Context) error {
	g.mu.Lock()
	g.formFuzzArmed = false
	g.mu.Unlock()
	done := make(chan struct{})
	go func() { g.formFuzzInFlight.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Wapiti 3.3.2 converts form pairs to a dictionary without decoding them.
// Only accept fixtures whose native encoding preserves the supplied request.
func wapitiPreservesFormFixture(body string) bool {
	seen := map[string]bool{}
	for _, pair := range strings.Split(body, "&") {
		parts := strings.Split(pair, "=")
		if len(parts) != 2 || parts[0] == "" || seen[parts[0]] {
			return false
		}
		seen[parts[0]] = true
		for _, part := range parts {
			for _, c := range part {
				if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("._~-", c)) {
					return false
				}
			}
		}
	}
	return len(seen) > 0
}

// ValidateWapitiFormFixture checks the installed adapter's exact-input support.
func ValidateWapitiFormFixture(body []byte) error {
	if len(body) == 0 || len(body) > 64<<10 || !wapitiPreservesFormFixture(string(body)) {
		return fmt.Errorf("installed Wapiti cannot preserve repeated or encoded form fields; use a capable API adapter")
	}
	values, err := url.ParseQuery(string(body))
	if err != nil || len(values) > 64 {
		return fmt.Errorf("form fixture exceeds the bounded field limit")
	}
	return nil
}
