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

type nextjsActionsRunner struct{}

func (nextjsActionsRunner) Name() string { return "nextjs-actions" }
func (nextjsActionsRunner) Descriptor() Descriptor {
	return Descriptor{Name: "nextjs-actions", Summary: "Approved one-shot Server Action identity/origin comparisons with verified cleanup", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightHeavy}
}

type preparedNextjsAction struct {
	approval          assessment.NextjsActionApproval
	fixture           NextjsActionFixture
	body, cleanupBody []byte
	inputs            []ScannerRequestInput
}

func nextjsActionAuth(req Request, identity string) (AuthContext, error) {
	if identity == "anonymous" {
		return AuthContext{ID: AuthenticationContextID(req.TargetID, "anonymous"), TargetID: req.TargetID, Identity: "anonymous", State: assessment.StateVerified}, nil
	}
	for _, auth := range req.AuthContexts {
		if auth.Identity == identity && auth.TargetID == req.TargetID && auth.ID != "" && auth.State == assessment.StateVerified && auth.Refresh != nil && len(auth.Headers) > 0 {
			return auth, nil
		}
	}
	return AuthContext{}, fmt.Errorf("action identity has no verified credential bound to this target")
}

func nextjsActionHeaders(ctx context.Context, auth AuthContext) (string, error) {
	if auth.Identity == "anonymous" {
		return "", nil
	}
	headers, err := auth.Refresh(ctx, slices.Clone(auth.Headers))
	if err != nil || len(headers) == 0 {
		return "", fmt.Errorf("action identity authentication checkpoint expired")
	}
	return strings.Join(headers, "\n"), nil
}

func prepareNextjsActionCampaigns(req Request) ([]preparedNextjsAction, error) {
	if !req.TypedAssessment || !req.TestEnvironment || req.AppScope == nil || req.TargetID == "" || req.AuthContextID != "" || !expandedWorkflowRequest(req) {
		return nil, fmt.Errorf("Server Action campaigns require an expanded typed assessment, declared test environment, and exact target scope")
	}
	config := assessment.AssessmentConfig{Mode: assessment.ModeGrayBox, Types: []assessment.Type{assessment.TypeWebApplication}, Targets: []assessment.Target{{ID: req.TargetID, Kind: assessment.KindURL, Value: req.Target}}, WorkflowVersion: req.WorkflowVersion, TestEnvironment: true, NextjsActionApprovals: req.NextjsActionApprovals}
	for _, auth := range req.AuthContexts {
		config.Access = append(config.Access, assessment.AccessBinding{TargetIDs: []string{auth.TargetID}, Identity: auth.Identity, Kind: assessment.AccessBearerToken, CredentialID: "runtime-only"})
	}
	if problems := assessment.ValidateNextjsActionApprovals(config); len(problems) > 0 {
		return nil, fmt.Errorf("invalid Server Action campaign: %s", problems[0].Message)
	}
	var campaigns []preparedNextjsAction
	for _, approval := range req.NextjsActionApprovals {
		if approval.TargetID != req.TargetID {
			return nil, fmt.Errorf("action approval belongs to a different target")
		}
		raw, err := readAPIFixture(req.APIFixtureDir, approval.FixtureRef)
		if err != nil {
			return nil, fmt.Errorf("action manifest fixture is missing or corrupt")
		}
		fixture, err := ValidateNextjsActionManifest(raw, req.Target, *req.AppScope)
		if err != nil {
			return nil, err
		}
		body, err := readAPIFixture(req.APIFixtureDir, fixture.BodyRef)
		if err != nil || len(body) > 64<<10 {
			return nil, fmt.Errorf("action request body is missing, corrupt, or larger than 64 KiB")
		}
		var cleanup []byte
		if fixture.CleanupBodyRef != "" {
			cleanup, err = readAPIFixture(req.APIFixtureDir, fixture.CleanupBodyRef)
			if err != nil || len(cleanup) > 64<<10 {
				return nil, fmt.Errorf("action cleanup body is missing, corrupt, or larger than 64 KiB")
			}
		}
		campaign := preparedNextjsAction{approval: approval, fixture: fixture, body: body, cleanupBody: cleanup}
		for _, c := range approval.Cases {
			target, _ := url.Parse(req.Target)
			foreign, _ := url.Parse(nextjsForeignOrigin)
			if c.CrossOrigin && sameNextjsOrigin(target, foreign) {
				return nil, fmt.Errorf("the origin-test header must differ from the target origin")
			}
			auth, err := nextjsActionAuth(req, c.Identity)
			if err != nil {
				return nil, err
			}
			ep, ok := requestVariantEndpoint(req.Scope, fixture.URL, http.MethodPost, fixture.ContentType, string(body), false)
			if !ok {
				return nil, fmt.Errorf("approved action request cannot be materialized")
			}
			ep.AuthContextID = auth.ID
			ep.ID = inventoryID(ep.ID, auth.ID, approval.ID, c.ID)
			campaign.inputs = append(campaign.inputs, ScannerRequestInput{EndpointID: ep.ID, AuthContextID: auth.ID, InventoryScope: req.Scope, URL: fixture.URL, Method: http.MethodPost, ContentType: fixture.ContentType, BodyDigest: fixture.BodyRef, Selected: true, Reason: "explicitly approved one-shot Server Action case"})
		}
		campaigns = append(campaigns, campaign)
	}
	return campaigns, nil
}

// prepareNextjsActionsRequest exposes exact approved variants in the ordinary
// manifest/inventory. The native runner revalidates every boundary at execution.
func prepareNextjsActionsRequest(req *Request, surface *AttackSurface) error {
	campaigns, err := prepareNextjsActionCampaigns(*req)
	if err != nil {
		return err
	}
	req.InputRequests = nil
	indexes := map[string]int{}
	if surface != nil {
		for i := range surface.Endpoints {
			indexes[surface.Endpoints[i].ID] = i
		}
	}
	for _, campaign := range campaigns {
		for _, input := range campaign.inputs {
			req.InputRequests = append(req.InputRequests, input)
			if surface == nil {
				continue
			}
			ep, _ := requestVariantEndpoint(req.Scope, input.URL, input.Method, input.ContentType, string(campaign.body), false)
			ep.ID, ep.AuthContextID = input.EndpointID, input.AuthContextID
			ep.State, ep.Kind, ep.ObservationKind = EndpointStateInScope, "api", "seed"
			ep.StateReason = input.Reason
			mergeSurfaceEndpoint(surface, indexes, ep)
		}
	}
	return nil
}

func (nextjsActionsRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) (run Run) {
	run = Run{Scanner: "nextjs-actions", Target: req.Target, Scope: req.Scope, Variant: nextjsActionsVersion, StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	finish := func(status, reason string) Run {
		run.Status, run.Reason, run.FinishedAt = status, reason, time.Now().UTC().Format(time.RFC3339Nano)
		return finalizeRun(run)
	}
	if len(req.NextjsActionApprovals) == 0 {
		return finish("skipped", "no explicitly approved Server Action cases")
	}
	campaigns, err := prepareNextjsActionCampaigns(req)
	if cfg.Budget == nil {
		cfg.Budget = NewAssessmentBudget(cfg.RateRPS, cfg.WebMaxEndpoints, cfg.WebBudget)
	}
	if err != nil {
		return finish("failed", err.Error())
	}
	journal, err := openRequestWriteJournal(req)
	if err != nil {
		run.GapKind = GapInterruptedWrite
		return finish("failed", "action write journal is unavailable; no action was sent")
	}
	// Any prior case intent refuses the whole replay before a new baseline runs.
	entries, err := LoadWriteJournal(journal.root)
	if err != nil {
		return finish("failed", "action write journal could not be read")
	}
	for _, campaign := range campaigns {
		for _, c := range campaign.approval.Cases {
			key := nextjsActionOperation(req, campaign.approval, c)
			if slices.ContainsFunc(entries, func(e WriteJournalEntry) bool { return e.OperationID == key }) {
				return finish("failed", "an action case was already journaled; campaign replay is refused")
			}
		}
	}
	dir := filepath.Join(req.ScanDir, "scanner-output", "nextjs-actions")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return finish("failed", "create action evidence directory failed")
	}
	findings, err := os.OpenFile(filepath.Join(dir, "findings.jsonl"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return finish("failed", "create action findings failed")
	}
	defer findings.Close()
	run.ArtifactPath = findings.Name()
	events, err := os.OpenFile(filepath.Join(dir, "coverage-events.jsonl"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return finish("failed", "create action request evidence failed")
	}
	defer events.Close()
	run.CoverageEventsPath = events.Name()
	results, err := os.OpenFile(filepath.Join(dir, "action-results.jsonl"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return finish("failed", "create action case evidence failed")
	}
	defer results.Close()
	record := func(input ScannerRequestInput, raw, method, phase, kind, reason string, status int) error {
		event := CoverageEvent{Scanner: "nextjs-actions", AttemptID: req.AttemptID, URL: SafeTelemetryURL(raw), Method: method, Phase: phase, Kind: kind, Reason: reason, ResponseCode: status, At: time.Now().UTC().Format(time.RFC3339Nano)}
		if phase == "active_test" {
			event.EndpointIDs = []string{input.EndpointID}
		}
		if err := json.NewEncoder(events).Encode(event); err != nil {
			return err
		}
		return events.Sync()
	}
	persist := func(result AuthorizationResult) error {
		run.AuthorizationResults = append(run.AuthorizationResults, result)
		if err := json.NewEncoder(results).Encode(result); err != nil {
			return err
		}
		return results.Sync()
	}
	if emit != nil {
		emit(Event{Type: "scanner_started", Scanner: run.Scanner, Run: run})
	}
	// Every request goes through origin/path policy, resolved-address guards,
	// independent credentials, shared rate/endpoint/time budgets, and no redirects.
	send := func(input ScannerRequestInput, raw, method, phase string, body []byte, contentType string, auth AuthContext, headers http.Header) (*http.Response, error) {
		allowed, _ := req.AppScope.Allows(raw)
		excluded, _ := req.AppScope.Excluded(method, raw)
		if !allowed || excluded {
			return nil, fmt.Errorf("action request refused by scope or exclusions")
		}
		endpoint, _ := normalizeAttackSurfaceEndpoint(raw, method, "nextjs-actions", "", 0, "", endpointParameters(raw), false, false)
		endpointID := endpoint.ID
		if phase == "active_test" {
			endpointID = input.EndpointID
		}
		if len(cfg.Budget.ReserveEndpoints([]string{endpointID})) == 0 {
			return nil, fmt.Errorf("action endpoint budget exhausted")
		}
		if err := cfg.Budget.Wait(ctx); err != nil {
			return nil, fmt.Errorf("action request budget exhausted")
		}
		credentials, err := nextjsActionHeaders(ctx, auth)
		if err != nil {
			return nil, err
		}
		if err := record(input, raw, method, phase, "submitted", "", 0); err != nil {
			return nil, fmt.Errorf("action evidence could not be persisted")
		}
		response, err := sendScopedAPIRequestWithHeaders(ctx, cfg, raw, method, body, contentType, credentials, headers)
		if err != nil {
			_ = record(input, raw, method, phase, "failed", "action request failed", 0)
			return nil, fmt.Errorf("action request failed")
		}
		if err := record(input, raw, method, phase, "observed", "", response.StatusCode); err != nil {
			response.Body.Close()
			return nil, fmt.Errorf("action response evidence could not be persisted")
		}
		return response, nil
	}
	state := func(campaign preparedNextjsAction, input ScannerRequestInput, owner AuthContext) (string, string, error) {
		response, err := send(input, campaign.fixture.VerificationURL, http.MethodGet, "verification", nil, "", owner, http.Header{"Accept": {"application/json, text/plain;q=0.8"}, "Cache-Control": {"no-cache"}})
		if err != nil {
			return "", "", err
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
		response.Body.Close()
		if err != nil || len(body) > 64<<10 || response.StatusCode < 200 || response.StatusCode >= 300 {
			return "", "", fmt.Errorf("controlled action state could not be verified")
		}
		if _, err := nextjsActionHeaders(ctx, owner); err != nil {
			return "", "", err
		}
		ready, changed := strings.Contains(string(body), campaign.fixture.ReadyMarker), strings.Contains(string(body), campaign.fixture.ChangedMarker)
		hash := sha256.Sum256(body)
		digest := hex.EncodeToString(hash[:])
		if ready == changed {
			return "", digest, fmt.Errorf("controlled action state is ambiguous")
		}
		if changed {
			return "allow", digest, nil
		}
		return "deny", digest, nil
	}
	stop := func(result AuthorizationResult, gap GapKind, reason string) Run {
		result.Status, result.Reason = "unknown", reason
		if err := persist(result); err != nil {
			gap, reason = GapInterruptedWrite, "action case evidence could not be persisted"
		}
		run.GapKind = gap
		return finish("failed", reason)
	}
	for _, campaign := range campaigns {
		owner, _ := nextjsActionAuth(req, campaign.approval.OwnerIdentity)
		baselineConfirmed := false
		for i, c := range campaign.approval.Cases {
			input := campaign.inputs[i]
			auth, _ := nextjsActionAuth(req, c.Identity)
			result := AuthorizationResult{CaseID: c.ID, Identity: c.Identity, Role: auth.Role, AuthContextID: auth.ID, EndpointID: input.EndpointID, OperationID: campaign.approval.ID, FixtureRef: campaign.approval.FixtureRef, Representation: "server-action", URL: SafeTelemetryURL(campaign.fixture.URL), Method: http.MethodPost, Expected: c.Expect, Status: "unknown", EvidenceRef: events.Name()}
			if c.CrossOrigin {
				result.Representation = "server-action-cross-origin"
			}
			before, _, err := state(campaign, input, owner)
			if err != nil || before != "deny" {
				return stop(result, GapPrerequisiteFailed, "controlled resource was not confirmed ready before the action; no action was sent")
			}
			// Validate acting credentials before burning the one-shot write intent.
			if _, err := nextjsActionHeaders(ctx, auth); err != nil {
				return stop(result, GapAuthExpired, "acting identity verification expired before the action")
			}
			key := nextjsActionOperation(req, campaign.approval, c)
			entry := WriteJournalEntry{OperationID: key, JobID: "nextjs-actions", Method: http.MethodPost, RedactedURL: campaign.fixture.URL, FixtureRef: campaign.approval.FixtureRef, CleanupMethod: campaign.fixture.CleanupMethod, CleanupURL: campaign.fixture.CleanupURL, CleanupRef: campaign.fixture.CleanupBodyRef}
			if err := journal.RecordIntent(entry); err != nil {
				return stop(result, GapInterruptedWrite, "action intent could not be recorded or was already journaled; no action was sent")
			}
			actionURL, _ := url.Parse(campaign.fixture.URL)
			origin := actionURL.Scheme + "://" + actionURL.Host
			if c.CrossOrigin {
				origin = nextjsForeignOrigin
			}
			headers := http.Header{"Next-Action": {campaign.fixture.ActionID}, "Origin": {origin}, "Accept": {"text/x-component"}}
			response, sendErr := send(input, campaign.fixture.URL, http.MethodPost, "active_test", campaign.body, campaign.fixture.ContentType, auth, headers)
			if sendErr != nil {
				return stop(result, GapInterruptedWrite, "action outcome is unknown; cleanup was not attempted, manual cleanup may be required, and journal prevents replay")
			}
			result.ResponseCode = response.StatusCode
			_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
			response.Body.Close()
			if err := journal.MarkSent(key); err != nil {
				return stop(result, GapInterruptedWrite, "action answered but its journal state could not be persisted; manual cleanup may be required")
			}
			observed, digest, verifyErr := state(campaign, input, owner)
			result.ResponseDigest = digest
			_, authErr := nextjsActionHeaders(ctx, auth)
			// Cleanup is always attempted after an answered action, including a denial
			// or unverifiable state. It must itself be followed by a ready-state check.
			cleanupResponse, cleanupErr := send(input, campaign.fixture.CleanupURL, campaign.fixture.CleanupMethod, "cleanup", campaign.cleanupBody, campaign.fixture.CleanupContentType, owner, nil)
			cleanupOK := cleanupErr == nil
			if cleanupResponse != nil {
				_, err := io.Copy(io.Discard, io.LimitReader(cleanupResponse.Body, 64<<10))
				cleanupResponse.Body.Close()
				cleanupOK = cleanupOK && err == nil && cleanupResponse.StatusCode >= 200 && cleanupResponse.StatusCode < 300
			}
			if cleanupOK {
				reset, _, err := state(campaign, input, owner)
				cleanupOK = err == nil && reset == "deny"
			}
			markErr := journal.MarkCleanup(key, cleanupOK)
			result.CleanupStatus = "verified"
			if !cleanupOK || markErr != nil {
				result.CleanupStatus = "failed"
			}
			if verifyErr == nil && readErr == nil && authErr == nil {
				result.Observed, result.MarkerConfirmed = observed, observed == "allow"
				result.Status = "matched"
				if observed != c.Expect {
					result.Status = "mismatch"
				}
			}
			// The allowed baseline is only usable after both mutation and reset are
			// proven. Denied cases can never establish their own positive baseline.
			if i == 0 {
				baselineConfirmed = result.Status == "matched" && result.Observed == "allow" && result.CleanupStatus == "verified"
			}
			if baselineConfirmed && c.Expect == "deny" && result.Observed == "allow" {
				rule, title, cwe := "nextjs-action-authorization", "Server Action changed controlled data despite a deny expectation", "CWE-863"
				if c.CrossOrigin {
					rule, title, cwe = "nextjs-action-origin", "Server Action accepted an explicitly disallowed origin", "CWE-346"
				}
				finding := Finding{SourceID: nextjsSourceID(rule, req.TargetID+"\x00"+campaign.approval.ID+"\x00"+c.ID), Scanner: "nextjs-actions", RuleID: rule, Title: title, Severity: "high", Target: req.Target, Endpoint: SafeTelemetryURL(campaign.fixture.URL), Method: http.MethodPost, CWE: cwe, Confidence: "confirmed", Description: "An approved one-shot action case changed a controlled test resource contrary to the supplied access expectation. The allowed baseline independently proved the action and verified its reset.", Evidence: fmt.Sprintf("case %s; identity %s; expected deny; controlled state changed; action HTTP %d; cleanup %s; body and marker values not retained", c.ID, c.Identity, result.ResponseCode, result.CleanupStatus), EvidenceRef: events.Name(), EvidenceCompleteness: "controlled_state_transition_and_allow_baseline", Remediation: "Enforce authentication, resource authorization, input validation, and the intended allowed-origin policy inside the Server Action. Retest with the same controlled resource."}
				if err := json.NewEncoder(findings).Encode(finding); err != nil {
					return stop(result, GapInterruptedWrite, "confirmed action finding could not be persisted")
				}
				if err := findings.Sync(); err != nil {
					return stop(result, GapInterruptedWrite, "confirmed action finding could not be synced")
				}
			}
			if result.CleanupStatus != "verified" {
				return stop(result, GapInterruptedWrite, "action cleanup was not verified; manual cleanup may be required and remaining cases were stopped")
			}
			if i == 0 && !baselineConfirmed {
				return stop(result, GapPrerequisiteFailed, "allowed action baseline did not prove a controlled state change; remaining cases were stopped")
			}
			if result.Status == "unknown" {
				return stop(result, GapRequestFailed, "action state or identity could not be verified; remaining cases were stopped")
			}
			if err := persist(result); err != nil {
				run.GapKind = GapInterruptedWrite
				return finish("failed", "action case evidence could not be persisted")
			}
		}
	}
	return finish("completed", fmt.Sprintf("verified %d approved one-shot action cases with controlled state and cleanup", len(run.AuthorizationResults)))
}

func nextjsActionOperation(req Request, a assessment.NextjsActionApproval, c assessment.NextjsActionCase) string {
	return "nextjs-action:" + req.TargetID + ":" + a.ID + ":" + c.ID
}
