package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

// AuthorizationResourceFixture identifies one supplied controlled read resource.
// A success marker prevents a login page or generic HTTP 200 from proving access.
type AuthorizationResourceFixture struct {
	URL            string `json:"url"`
	ResponseMarker string `json:"response_marker"`
}

type AuthorizationResult struct {
	EndpointID      string `json:"endpoint_id,omitempty"`
	AuthContextID   string `json:"auth_context_id,omitempty"`
	Identity        string `json:"identity"`
	Role            string `json:"role,omitempty"`
	OperationID     string `json:"operation_id"`
	FixtureRef      string `json:"fixture_ref"`
	URL             string `json:"url,omitempty"`
	Method          string `json:"method,omitempty"`
	Expected        string `json:"expected"`
	Observed        string `json:"observed,omitempty"`
	Status          string `json:"status"`
	ResponseCode    int    `json:"response_code,omitempty"`
	ResponseDigest  string `json:"response_digest,omitempty"`
	MarkerConfirmed bool   `json:"marker_confirmed"`
	Reason          string `json:"reason,omitempty"`
	EvidenceRef     string `json:"evidence_reference,omitempty"`
}

func authorizationInput(req Request, expectation assessment.AuthorizationExpectation) (AuthContext, APIEndpoint, AuthorizationResourceFixture, error) {
	var auth AuthContext
	for _, candidate := range req.AuthContexts {
		if candidate.Identity == expectation.Identity {
			auth = candidate
			break
		}
	}
	if auth.ID == "" || auth.State != assessment.StateVerified || auth.Refresh == nil || len(auth.Headers) == 0 {
		return auth, APIEndpoint{}, AuthorizationResourceFixture{}, fmt.Errorf("identity has no verified target-bound authentication context")
	}
	data, err := readAPIFixture(req.APIFixtureDir, expectation.ResourceFixtureRef)
	var fixture AuthorizationResourceFixture
	if err != nil || json.Unmarshal(data, &fixture) != nil || fixture.URL == "" || len(fixture.URL) > 8192 || fixture.ResponseMarker == "" || len(fixture.ResponseMarker) > 2000 {
		return auth, APIEndpoint{}, fixture, fmt.Errorf("resource fixture requires an exact URL and bounded response_marker")
	}
	target, e1 := assessment.ParseApprovedOrigin("", req.Target)
	destination, e2 := assessment.ParseApprovedOrigin("", fixture.URL)
	if e1 != nil || e2 != nil || target.Origin() != destination.Origin() || req.AppScope == nil {
		return auth, APIEndpoint{}, fixture, fmt.Errorf("resource fixture is outside the explicitly authenticated target origin")
	}
	if allowed, why := req.AppScope.Allows(fixture.URL); !allowed {
		return auth, APIEndpoint{}, fixture, fmt.Errorf("resource fixture is outside scope: %s", why)
	}
	if excluded, why := req.AppScope.Excluded(http.MethodGet, fixture.URL); excluded {
		return auth, APIEndpoint{}, fixture, fmt.Errorf("resource fixture is excluded: %s", why)
	}
	for _, endpoint := range req.APIEndpoints {
		if endpoint.TargetID != auth.TargetID || endpoint.OperationID != expectation.OperationID || endpoint.Method != http.MethodGet || !endpoint.Resolved || !endpoint.Eligible {
			continue
		}
		raw, err := apiEndpointURL(req.Target, endpoint)
		if err == nil && raw == fixture.URL {
			return auth, endpoint, fixture, nil
		}
	}
	return auth, APIEndpoint{}, fixture, fmt.Errorf("fixture URL does not match a materialized read-only API operation")
}

func authorizationEndpoint(fixture AuthorizationResourceFixture, auth AuthContext) AttackSurfaceEndpoint {
	endpoint, _ := normalizeAttackSurfaceEndpoint(fixture.URL, http.MethodGet, "authorization-fixture", "", 0, "", endpointParameters(fixture.URL), false, false)
	endpoint.AuthContextID = auth.ID
	endpoint.ID = inventoryID(endpoint.ID, auth.ID)
	endpoint.Kind, endpoint.ObservationKind = "api", "seed"
	endpoint.State, endpoint.StateReason = EndpointStateInScope, "supplied controlled-resource request for a named identity"
	return endpoint
}

func addAuthorizationRequestVariants(surface *AttackSurface, req Request) {
	if surface == nil {
		return
	}
	byID := map[string]int{}
	for i := range surface.Endpoints {
		byID[surface.Endpoints[i].ID] = i
	}
	for _, expectation := range req.AuthorizationExpectations {
		auth, _, fixture, err := authorizationInput(req, expectation)
		if err != nil {
			continue
		}
		mergeSurfaceEndpoint(surface, byID, authorizationEndpoint(fixture, auth))
	}
}

func runAuthorizationComparisons(ctx context.Context, req Request, cfg Config, run *Run, writeFinding func(Finding) error) (int, int, error) {
	if len(req.AuthorizationExpectations) == 0 {
		return 0, 0, nil
	}
	eventsPath := filepath.Join(req.ScanDir, "coverage-events.jsonl")
	events, err := os.OpenFile(eventsPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return 0, 0, err
	}
	defer events.Close()
	run.CoverageEventsPath = eventsPath
	record := func(result AuthorizationResult, kind string) error {
		event := CoverageEvent{Scanner: "apichecks", AttemptID: req.AttemptID, Method: result.Method, URL: SafeTelemetryURL(result.URL), Phase: "active_test", Kind: kind, At: time.Now().UTC().Format(time.RFC3339Nano), Reason: result.Reason, ResponseCode: result.ResponseCode, NativeRef: result.OperationID + ":" + result.AuthContextID}
		if result.EndpointID != "" {
			event.EndpointIDs = []string{result.EndpointID}
		}
		if err := json.NewEncoder(events).Encode(event); err != nil {
			return err
		}
		return events.Sync()
	}
	checked, gaps := 0, 0
	var results []AuthorizationResult
	for _, expectation := range req.AuthorizationExpectations {
		result := AuthorizationResult{Identity: expectation.Identity, OperationID: expectation.OperationID, FixtureRef: expectation.ResourceFixtureRef, Expected: expectation.Expect, Status: "skipped", Method: http.MethodGet, EvidenceRef: eventsPath}
		auth, endpoint, fixture, inputErr := authorizationInput(req, expectation)
		result.AuthContextID, result.Role = auth.ID, auth.Role
		result.URL = SafeTelemetryURL(fixture.URL)
		if inputErr != nil {
			result.Reason = inputErr.Error()
			results = append(results, result)
			gaps++
			continue
		}
		variant := authorizationEndpoint(fixture, auth)
		result.EndpointID = variant.ID
		selected := slices.ContainsFunc(req.InputRequests, func(input ScannerRequestInput) bool {
			return input.Selected && input.EndpointID == variant.ID && input.AuthContextID == auth.ID
		})
		if !selected {
			result.Reason = "role request was not selected by the inventory and request budget"
			results = append(results, result)
			gaps++
			continue
		}
		if err := browserRequestAllowed(req, cfg, http.MethodGet, fixture.URL); err != nil {
			result.Reason = "read-only request policy refused resource fixture"
			results = append(results, result)
			gaps++
			continue
		}
		current, refreshErr := auth.Refresh(ctx, slices.Clone(auth.Headers))
		if refreshErr != nil || len(current) == 0 {
			result.Reason = "identity authentication checkpoint expired"
			results = append(results, result)
			gaps++
			continue
		}
		if err := cfg.Budget.Wait(ctx); err != nil {
			result.Reason = "authorization comparison request budget exhausted"
			results = append(results, result)
			gaps++
			continue
		}
		if err := record(result, "submitted"); err != nil {
			return checked, gaps, err
		}
		response, requestErr := sendScopedAPIRequest(ctx, cfg, fixture.URL, endpoint.Method, nil, "", strings.Join(current, "\n"))
		if requestErr != nil {
			result.Status, result.Reason = "failed", "resource request failed"
			if err := record(result, "failed"); err != nil {
				return checked, gaps, err
			}
			results = append(results, result)
			gaps++
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
		response.Body.Close()
		result.ResponseCode = response.StatusCode
		sum := sha256.Sum256(body)
		result.ResponseDigest = hex.EncodeToString(sum[:])
		if err := record(result, "observed"); err != nil {
			return checked, gaps, err
		}
		result.Status = "unknown"
		switch {
		case readErr != nil || len(body) > 64<<10:
			result.Reason = "resource response unavailable or beyond the comparison limit"
		case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
			result.Observed = "deny"
		case response.StatusCode >= 200 && response.StatusCode < 300 && strings.Contains(string(body), fixture.ResponseMarker):
			result.Observed, result.MarkerConfirmed = "allow", true
		default:
			result.Reason = "response does not prove controlled resource access or explicit denial"
		}
		if result.Observed != "" {
			result.Status = "mismatch"
			if result.Expected == result.Observed {
				result.Status = "matched"
			}
		} else {
		}
		results = append(results, result)
	}
	// A deny-role HTTP 200 alone is insufficient: require the expected allow role
	// to confirm that the same controlled resource was actually served.
	allowBaselines := map[string]bool{}
	for _, result := range results {
		if result.Expected == "allow" && result.Observed == "allow" {
			allowBaselines[result.OperationID+"\x00"+result.FixtureRef] = true
		}
	}
	checked, gaps = 0, 0
	for i := range results {
		result := &results[i]
		if result.Status == "mismatch" && result.Expected == "deny" && result.Observed == "allow" {
			if !allowBaselines[result.OperationID+"\x00"+result.FixtureRef] {
				result.Status, result.Reason = "unknown", "expected allow identity did not confirm the controlled resource"
			} else {
				parsed, _ := url.Parse(result.URL)
				finding := newAPICheckFinding(req, APIEndpoint{Method: http.MethodGet, Path: parsed.EscapedPath(), Origin: parsed.Scheme + "://" + parsed.Host}, result.URL, "api-role-access-not-enforced", "API resource access violates supplied role expectation", "high", fmt.Sprintf("Identity %q was expected to be denied access, but HTTP %d returned the configured controlled-resource marker. The expected allow identity confirmed the same fixture.", result.Identity, result.ResponseCode), "CWE-863")
				finding.SourceID += ":" + result.AuthContextID + ":" + result.FixtureRef[:12]
				finding.EvidenceRef = eventsPath
				finding.EvidenceCompleteness = "status_and_controlled_resource_marker"
				if err := writeFinding(finding); err != nil {
					return checked, gaps, err
				}
			}
		}
		if result.Status == "mismatch" && result.Expected == "allow" {
			result.Status, result.Reason = "unknown", "expected allow identity did not receive the controlled resource"
		}
		if result.Status == "matched" || result.Status == "mismatch" {
			checked++
		} else {
			gaps++
		}
		eventKind := result.Status
		if result.Status == "matched" || result.Status == "mismatch" {
			eventKind = "completed"
		}
		if err := record(*result, eventKind); err != nil {
			return checked, gaps, err
		}
		if req.Inventory != nil {
			for j := range req.Inventory.Endpoints {
				endpoint := &req.Inventory.Endpoints[j]
				if endpoint.ID != result.EndpointID {
					continue
				}
				state := "completed"
				if result.Status == "unknown" || result.Status == "skipped" {
					state = "skipped"
				}
				if result.Status == "failed" {
					state = "failed"
				}
				coverage := EndpointScannerCoverage{Scanner: "apichecks", Status: state, Reason: result.Reason, AttemptID: req.AttemptID, PlanFingerprint: req.PlanFingerprint, EvidenceRef: eventsPath, FinishedAt: time.Now().UTC().Format(time.RFC3339Nano)}
				setEndpointCoverage(endpoint, coverage)
				endpoint.CoverageHistory = append(endpoint.CoverageHistory, coverage)
			}
		}
	}
	run.AuthorizationResults = append(run.AuthorizationResults, results...)
	return checked, gaps, nil
}
