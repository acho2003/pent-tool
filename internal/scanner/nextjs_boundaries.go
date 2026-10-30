package scanner

import (
	"context"
	"crypto/rand"
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
	"strconv"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

type nextjsBoundariesRunner struct{}

func (nextjsBoundariesRunner) Name() string { return "nextjs-boundaries" }
func (nextjsBoundariesRunner) Descriptor() Descriptor {
	return Descriptor{Name: "nextjs-boundaries", Summary: "Controlled cache isolation, redirect and callback fetch checks", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightHeavy}
}

type preparedBoundary struct {
	approval        assessment.NextjsBoundaryApproval
	fixture         NextjsBoundaryFixture
	cleanup         []byte
	token, probeURL string
	inputs          []ScannerRequestInput
}

func prepareBoundaryProbes(req *Request, surface *AttackSurface) ([]preparedBoundary, error) {
	if !req.TypedAssessment || !req.TestEnvironment || req.AppScope == nil || req.TargetID == "" || req.AuthContextID != "" || !expandedWorkflowRequest(*req) {
		return nil, fmt.Errorf("boundary probes require an expanded typed test assessment with exact scope")
	}
	config := assessment.AssessmentConfig{Mode: assessment.ModeGrayBox, Types: []assessment.Type{assessment.TypeWebApplication}, Targets: []assessment.Target{{ID: req.TargetID, Kind: assessment.KindURL, Value: req.Target}}, WorkflowVersion: req.WorkflowVersion, TestEnvironment: true, NextjsBoundaryApprovals: req.NextjsBoundaryApprovals}
	for _, auth := range req.AuthContexts {
		config.Access = append(config.Access, assessment.AccessBinding{TargetIDs: []string{auth.TargetID}, Identity: auth.Identity, Kind: assessment.AccessBearerToken, CredentialID: "runtime-only"})
	}
	if problems := assessment.ValidateNextjsBoundaryApprovals(config); len(problems) > 0 {
		return nil, fmt.Errorf("invalid boundary approval: %s", problems[0].Message)
	}
	if req.NextjsBoundaryTokens == nil {
		req.NextjsBoundaryTokens = map[string]string{}
	}
	var prepared []preparedBoundary
	var inputs []ScannerRequestInput
	for _, approval := range req.NextjsBoundaryApprovals {
		raw, err := readAPIFixture(req.APIFixtureDir, approval.FixtureRef)
		if err != nil {
			return nil, fmt.Errorf("boundary manifest is missing or corrupt")
		}
		f, err := ValidateNextjsBoundaryManifest(raw, req.Target, *req.AppScope)
		if err != nil {
			return nil, err
		}
		if f.Kind != approval.Kind {
			return nil, fmt.Errorf("boundary manifest kind differs from the approved kind")
		}
		p := preparedBoundary{approval: approval, fixture: f, probeURL: f.URL}
		if f.CleanupBodyRef != "" {
			p.cleanup, err = readAPIFixture(req.APIFixtureDir, f.CleanupBodyRef)
			if err != nil || len(p.cleanup) > 64<<10 {
				return nil, fmt.Errorf("boundary cleanup body is missing, corrupt, or oversized")
			}
		}
		identities := []string{approval.Identity}
		if f.Kind == "cache" {
			identities = append([]string{approval.OwnerIdentity}, identities...)
		} else {
			u, _ := url.Parse(f.URL)
			query := u.Query()
			destination := f.DestinationURL
			if f.Kind == "proxy" {
				p.token = req.NextjsBoundaryTokens[approval.ID]
				if p.token == "" {
					value := make([]byte, 16)
					if _, err := rand.Read(value); err != nil {
						return nil, fmt.Errorf("callback correlation unavailable")
					}
					p.token = hex.EncodeToString(value)
					req.NextjsBoundaryTokens[approval.ID] = p.token
				}
				callback, _ := url.Parse(f.CallbackURL)
				q := callback.Query()
				q.Set("scan_token", p.token)
				callback.RawQuery = q.Encode()
				destination = callback.String()
			}
			query.Set(f.Parameter, destination)
			u.RawQuery = query.Encode()
			p.probeURL = u.String()
			if allowed, _ := req.AppScope.Allows(p.probeURL); !allowed {
				return nil, fmt.Errorf("materialized URL probe is outside scope")
			}
			if excluded, _ := req.AppScope.Excluded("GET", p.probeURL); excluded {
				return nil, fmt.Errorf("materialized URL probe is excluded")
			}
		}
		for i, identity := range identities {
			auth, err := nextjsActionAuth(*req, identity)
			if err != nil {
				return nil, err
			}
			ep, ok := normalizeAttackSurfaceEndpoint(p.probeURL, "GET", "nextjs-boundaries", "", 0, "", endpointParameters(p.probeURL), false, false)
			if !ok {
				return nil, fmt.Errorf("boundary request cannot be materialized")
			}
			ep.ID = inventoryID(ep.ID, approval.ID, auth.ID, strconv.Itoa(i))
			ep.AuthContextID = auth.ID
			input := ScannerRequestInput{EndpointID: ep.ID, AuthContextID: auth.ID, InventoryScope: req.Scope, URL: p.probeURL, Method: "GET", Selected: true, Reason: "explicitly approved controlled boundary probe"}
			p.inputs = append(p.inputs, input)
			inputs = append(inputs, input)
			if surface != nil {
				ep.State, ep.Kind, ep.ObservationKind = EndpointStateInScope, "api", "seed"
				indexes := map[string]int{}
				for j := range surface.Endpoints {
					indexes[surface.Endpoints[j].ID] = j
				}
				mergeSurfaceEndpoint(surface, indexes, ep)
			}
		}
		prepared = append(prepared, p)
	}
	req.InputRequests = inputs
	return prepared, nil
}

type boundaryResponse struct {
	status int
	header http.Header
	body   []byte
	digest string
}
type boundaryClient struct {
	ctx    context.Context
	req    Request
	cfg    Config
	events *os.File
}

func (c boundaryClient) send(input ScannerRequestInput, raw, method, phase string, body []byte, contentType string, auth AuthContext, headers http.Header) (boundaryResponse, error) {
	var result boundaryResponse
	if ok, _ := c.req.AppScope.Allows(raw); !ok {
		return result, fmt.Errorf("boundary request is outside scope")
	}
	if excluded, _ := c.req.AppScope.Excluded(method, raw); excluded {
		return result, fmt.Errorf("boundary request is excluded")
	}
	if method == "GET" {
		if err := browserRequestAllowed(c.req, Config{}, method, raw); err != nil {
			return result, fmt.Errorf("boundary read policy refused request")
		}
	}
	id := input.EndpointID
	if phase != "active_test" {
		ep, _ := normalizeAttackSurfaceEndpoint(raw, method, "nextjs-boundaries", "", 0, "", endpointParameters(raw), false, false)
		id = ep.ID
	}
	if len(c.cfg.Budget.ReserveEndpoints([]string{id})) == 0 {
		return result, fmt.Errorf("boundary endpoint budget exhausted")
	}
	if err := c.cfg.Budget.Wait(c.ctx); err != nil {
		return result, fmt.Errorf("boundary request budget exhausted")
	}
	if auth.Identity != "anonymous" {
		bound, _ := url.Parse(c.req.Target)
		destination, err := url.Parse(raw)
		if err != nil || auth.TargetID != c.req.TargetID || !sameNextjsOrigin(bound, destination) {
			return result, fmt.Errorf("boundary credentials are not bound to this destination")
		}
	}
	credentials, err := nextjsActionHeaders(c.ctx, auth)
	if err != nil {
		return result, err
	}
	record := func(kind string, status int) error {
		event := CoverageEvent{Scanner: "nextjs-boundaries", AttemptID: c.req.AttemptID, URL: SafeTelemetryURL(raw), Method: method, Phase: phase, Kind: kind, ResponseCode: status, At: time.Now().UTC().Format(time.RFC3339Nano)}
		if phase == "active_test" {
			event.EndpointIDs = []string{input.EndpointID}
		}
		if err := json.NewEncoder(c.events).Encode(event); err != nil {
			return err
		}
		return c.events.Sync()
	}
	if err := record("submitted", 0); err != nil {
		return result, fmt.Errorf("boundary evidence could not be persisted")
	}
	response, err := sendScopedAPIRequestWithHeaders(c.ctx, c.cfg, raw, method, body, contentType, credentials, headers)
	if err != nil {
		_ = record("failed", 0)
		return result, fmt.Errorf("boundary request failed")
	}
	result.status, result.header = response.StatusCode, response.Header.Clone()
	result.body, err = io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	response.Body.Close()
	if eventErr := record("observed", result.status); eventErr != nil {
		return result, fmt.Errorf("boundary response evidence could not be persisted")
	}
	if err != nil || len(result.body) > 64<<10 {
		return result, fmt.Errorf("boundary response was incomplete or oversized")
	}
	if _, err := nextjsActionHeaders(c.ctx, auth); err != nil {
		return result, err
	}
	hash := sha256.Sum256(result.body)
	result.digest = hex.EncodeToString(hash[:])
	return result, nil
}

func boundaryDenied(f NextjsBoundaryFixture, r boundaryResponse) bool {
	return !strings.Contains(string(r.body), f.PrivateMarker) && (r.status == 401 || r.status == 403 || (r.status >= 200 && r.status < 300 && strings.Contains(string(r.body), f.DeniedMarker)))
}
func boundaryPrivate(f NextjsBoundaryFixture, r boundaryResponse) bool {
	return r.status >= 200 && r.status < 300 && strings.Contains(string(r.body), f.PrivateMarker) && !strings.Contains(string(r.body), f.DeniedMarker)
}
func boundaryCacheHit(header http.Header) bool {
	for _, name := range []string{"X-Nextjs-Cache", "X-Vercel-Cache", "CF-Cache-Status", "X-Cache"} {
		if strings.EqualFold(strings.TrimSpace(header.Get(name)), "HIT") {
			return true
		}
	}
	age, err := strconv.ParseUint(strings.TrimSpace(header.Get("Age")), 10, 64)
	return err == nil && age > 0
}

func (nextjsBoundariesRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) (run Run) {
	run = Run{Status: "running", Scanner: "nextjs-boundaries", Target: req.Target, Scope: req.Scope, Variant: nextjsBoundariesVersion, StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	finish := func(status, reason string) Run {
		run.Status, run.Reason, run.FinishedAt = status, reason, time.Now().UTC().Format(time.RFC3339Nano)
		if run.ArtifactPath != "" {
			findings, err := ParseRun(run)
			if err != nil {
				run.Status, run.ParserOutcome, run.Outcome, run.Completeness = "failed", "FAILED", "PARSER_FAILED", "unknown"
			} else {
				run.ParserOutcome = "SUCCESS"
				if status == "completed" {
					run.Completeness, run.Outcome = "complete", "SUCCESS_NO_FINDINGS"
					if len(findings) > 0 {
						run.Outcome = "SUCCESS_WITH_FINDINGS"
					}
				}
				if len(run.Limitations) > 0 || status == "failed" {
					run.Completeness = "partial"
					run.Outcome = "PARTIAL"
				}
			}
		}
		return finalizeRun(run)
	}
	if len(req.NextjsBoundaryApprovals) == 0 {
		return finish("skipped", "no explicitly approved boundary probes")
	}
	prepared, err := prepareBoundaryProbes(&req, nil)
	if err != nil {
		return finish("failed", err.Error())
	}
	if cfg.Budget == nil {
		cfg.Budget = NewAssessmentBudget(cfg.RateRPS, cfg.WebMaxEndpoints, cfg.WebBudget)
	}
	for _, p := range prepared {
		external := ""
		if p.fixture.Kind == "proxy" {
			external = p.fixture.CallbackURL
		}
		if p.fixture.Kind == "redirect" {
			external = p.fixture.DestinationURL
		}
		if external != "" {
			client, err := guardedOriginClient(ctx, cfg, external)
			if err != nil {
				return finish("failed", "controlled external destination refused by execution guard")
			}
			client.CloseIdleConnections()
		}
	}
	var journal *WriteJournal
	if slices.ContainsFunc(prepared, func(p preparedBoundary) bool { return p.fixture.Kind == "cache" }) {
		journal, err = openRequestWriteJournal(req)
		if err != nil {
			return finish("failed", "cache journal unavailable; no probe was sent")
		}
		entries, err := LoadWriteJournal(journal.root)
		if err != nil {
			return finish("failed", "cache journal could not be read")
		}
		for _, p := range prepared {
			key := boundaryOperation(req, p)
			if p.fixture.Kind == "cache" && slices.ContainsFunc(entries, func(e WriteJournalEntry) bool { return e.OperationID == key }) {
				return finish("failed", "cache probe already journaled; automatic replay refused")
			}
		}
	}
	dir := filepath.Join(req.ScanDir, "scanner-output", "nextjs-boundaries")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return finish("failed", "create boundary evidence directory failed")
	}
	findings, err := os.OpenFile(filepath.Join(dir, "findings.jsonl"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return finish("failed", "create boundary findings failed")
	}
	defer findings.Close()
	run.ArtifactPath = findings.Name()
	events, err := os.OpenFile(filepath.Join(dir, "coverage-events.jsonl"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return finish("failed", "create boundary receipts failed")
	}
	defer events.Close()
	run.CoverageEventsPath = events.Name()
	client := boundaryClient{ctx: ctx, req: req, cfg: cfg, events: events}
	if emit != nil {
		emit(Event{Type: "scanner_started", Scanner: run.Scanner, Run: run})
	}
	for _, p := range prepared {
		auth, _ := nextjsActionAuth(req, p.approval.Identity)
		result := AuthorizationResult{CaseID: p.approval.ID, Identity: auth.Identity, Role: auth.Role, AuthContextID: auth.ID, EndpointID: p.inputs[len(p.inputs)-1].EndpointID, OperationID: p.approval.ID, FixtureRef: p.approval.FixtureRef, Representation: p.fixture.Kind + "-boundary", URL: SafeTelemetryURL(p.probeURL), Method: "GET", Expected: "deny", Status: "unknown", EvidenceRef: events.Name()}
		var finding *Finding
		critical := false
		switch p.fixture.Kind {
		case "cache":
			result, finding, critical = runCacheBoundary(client, p, result, journal)
		case "redirect":
			result, finding = runRedirectBoundary(client, p, result)
		case "proxy":
			result, finding = runProxyBoundary(client, p, result)
		}
		run.AuthorizationResults = append(run.AuthorizationResults, result)
		if finding != nil {
			if err := json.NewEncoder(findings).Encode(finding); err != nil {
				run.GapKind = GapInterruptedWrite
				return finish("failed", "boundary finding could not be persisted")
			}
			if err := findings.Sync(); err != nil {
				return finish("failed", "boundary finding could not be synced")
			}
		}
		if critical {
			run.GapKind = GapInterruptedWrite
			return finish("failed", result.Reason)
		}
		if result.Status == "unknown" {
			run.Limitations = append(run.Limitations, RunLimitation{Kind: "boundary_inconclusive", Reason: "probe " + p.approval.ID + ": " + result.Reason})
		}
	}
	return finish("completed", fmt.Sprintf("completed %d controlled boundary probes; inconclusive outcomes remain coverage gaps", len(prepared)))
}

func boundaryOperation(req Request, p preparedBoundary) string {
	return "nextjs-cache:" + req.TargetID + ":" + p.approval.ID
}
func boundaryFinding(c boundaryClient, p preparedBoundary, rule, title, severity, cwe, evidence string) *Finding {
	remediation := "Enforce the intended server boundary policy."
	switch p.fixture.Kind {
	case "cache":
		remediation = "Keep private responses out of shared caches, preserve identity and representation boundaries, and enforce authorization at the origin."
	case "redirect":
		remediation = "Normalize redirect URLs and permit only intended local targets or a strict destination allowlist."
	case "proxy":
		remediation = "Allowlist server-side fetch destinations and redirect targets. For Next.js image optimization, review images.remotePatterns and local-IP restrictions."
	}
	return &Finding{SourceID: nextjsSourceID(rule, c.req.TargetID+"\x00"+p.approval.ID), Scanner: "nextjs-boundaries", RuleID: rule, Title: title, Severity: severity, Target: c.req.Target, Endpoint: SafeTelemetryURL(p.probeURL), Method: "GET", CWE: cwe, Confidence: "confirmed", Description: evidence, Evidence: evidence, EvidenceRef: c.events.Name(), Remediation: remediation}
}

func runCacheBoundary(c boundaryClient, p preparedBoundary, result AuthorizationResult, journal *WriteJournal) (AuthorizationResult, *Finding, bool) {
	f := p.fixture
	owner, _ := nextjsActionAuth(c.req, p.approval.OwnerIdentity)
	denied, _ := nextjsActionAuth(c.req, p.approval.Identity)
	result.CacheAttribution = "unverified"
	cold, err := c.send(p.inputs[1], f.URL, "GET", "verification", nil, "", denied, authorizationRepresentationHeaders(f.ConsumerRepresentation))
	if err != nil || !boundaryDenied(f, cold) {
		result.Reason = "cold denied-user control did not prove denial; no authenticated fill was sent"
		return result, nil, false
	}
	bypass, err := c.send(p.inputs[1], f.BypassURL, "GET", "verification", nil, "", denied, authorizationRepresentationHeaders(f.ConsumerRepresentation))
	if err != nil || !boundaryDenied(f, bypass) {
		result.Reason = "uncached control did not prove denial; no authenticated fill was sent"
		return result, nil, false
	}
	key := boundaryOperation(c.req, p)
	if err := journal.RecordIntent(WriteJournalEntry{OperationID: key, JobID: "nextjs-boundaries", Method: "GET", RedactedURL: f.URL, FixtureRef: p.approval.FixtureRef, CleanupURL: f.CleanupURL, CleanupMethod: f.CleanupMethod, CleanupRef: f.CleanupBodyRef}); err != nil {
		result.Reason = "cache intent unavailable or already journaled; no fill sent"
		return result, nil, true
	}
	fill, fillErr := c.send(p.inputs[0], f.URL, "GET", "active_test", nil, "", owner, authorizationRepresentationHeaders(f.Representation))
	if fill.status == 0 {
		result.Reason = "cache fill outcome is unknown; manual reset may be required and replay is refused"
		return result, nil, true
	}
	if err := journal.MarkSent(key); err != nil {
		result.Reason = "cache fill answered but journal update failed; manual reset may be required"
		return result, nil, true
	}
	positive := fillErr == nil && boundaryPrivate(f, fill) && authorizationRepresentationMatches(f.Representation, fill.header.Get("Content-Type"), fill.body)
	var warm boundaryResponse
	var warmErr error
	if positive {
		warm, warmErr = c.send(p.inputs[1], f.URL, "GET", "active_test", nil, "", denied, authorizationRepresentationHeaders(f.ConsumerRepresentation))
		bypass, err = c.send(p.inputs[1], f.BypassURL, "GET", "verification", nil, "", denied, authorizationRepresentationHeaders(f.ConsumerRepresentation))
	}
	leak := positive && warmErr == nil && boundaryPrivate(f, warm)
	if leak {
		result.Status, result.Observed, result.MarkerConfirmed = "mismatch", "allow", true
		if err == nil && boundaryDenied(f, bypass) && boundaryCacheHit(warm.header) {
			result.CacheAttribution = "confirmed"
		}
	} else if positive && warmErr == nil && boundaryDenied(f, warm) {
		result.Status, result.Observed = "matched", "deny"
		result.CacheAttribution = "no_leak_observed"
	} else {
		result.Reason = "owner fill or warm response did not establish a controlled comparison"
	}
	result.ResponseCode, result.ResponseDigest = warm.status, warm.digest
	reset, resetErr := c.send(p.inputs[0], f.CleanupURL, f.CleanupMethod, "cleanup", p.cleanup, f.CleanupContentType, owner, nil)
	resetOK := resetErr == nil && reset.status >= 200 && reset.status < 300
	if resetOK {
		after, err := c.send(p.inputs[1], f.URL, "GET", "verification", nil, "", denied, authorizationRepresentationHeaders(f.ConsumerRepresentation))
		resetOK = err == nil && boundaryDenied(f, after)
	}
	result.CleanupStatus = "verified"
	if err := journal.MarkCleanup(key, resetOK); err != nil || !resetOK {
		result.CleanupStatus = "failed"
		result.Reason = "cache reset was not verified; manual cleanup may be required and remaining probes were stopped"
	}
	var finding *Finding
	if leak {
		title := "Private controlled response disclosed after an authenticated cache fill"
		if result.CacheAttribution == "confirmed" {
			title = "Shared cache disclosed a private controlled response across identities"
		}
		finding = boundaryFinding(c, p, "nextjs-cache-private-disclosure", title, "high", "CWE-200", "A cold denied-user request was denied, the owner confirmed the private test marker, and a subsequent denied-user request received that marker. Cache attribution: "+result.CacheAttribution+"; reset: "+result.CleanupStatus+". Marker values and response bodies were not retained.")
	}
	return result, finding, !resetOK || result.CleanupStatus == "failed"
}

func runRedirectBoundary(c boundaryClient, p preparedBoundary, result AuthorizationResult) (AuthorizationResult, *Finding) {
	auth, _ := nextjsActionAuth(c.req, p.approval.Identity)
	control, err := c.send(p.inputs[0], p.fixture.URL, "GET", "verification", nil, "", auth, nil)
	original, _ := url.Parse(p.fixture.URL)
	expected, _ := original.Parse(p.fixture.ControlValue)
	redirected := func(response boundaryResponse, base *url.URL) *url.URL {
		if response.status != 301 && response.status != 302 && response.status != 303 && response.status != 307 && response.status != 308 {
			return nil
		}
		u, err := base.Parse(response.header.Get("Location"))
		if err != nil || response.header.Get("Location") == "" {
			return nil
		}
		return u
	}
	location := redirected(control, original)
	if err != nil || location == nil || !sameNextjsOrigin(expected, location) || location.EscapedPath() != expected.EscapedPath() || location.RawQuery != expected.RawQuery {
		result.Reason = "local redirect control was not confirmed; external probe was not sent"
		return result, nil
	}
	response, err := c.send(p.inputs[0], p.probeURL, "GET", "active_test", nil, "", auth, nil)
	result.ResponseCode, result.ResponseDigest = response.status, response.digest
	if err != nil {
		result.Reason = "redirect probe did not complete"
		return result, nil
	}
	destination, _ := url.Parse(p.fixture.DestinationURL)
	probe, _ := url.Parse(p.probeURL)
	location = redirected(response, probe)
	if location != nil && location.User == nil && location.Fragment == "" && sameNextjsOrigin(location, destination) && location.EscapedPath() == destination.EscapedPath() && location.RawQuery == destination.RawQuery {
		result.Status, result.Observed, result.MarkerConfirmed = "mismatch", "allow", true
		return result, boundaryFinding(c, p, "nextjs-open-redirect", "Observed URL input redirected to an explicitly disallowed external destination", "medium", "CWE-601", "The local redirect control matched its supplied destination, then the same parameter selected the exact controlled external destination. Neither redirect was followed.")
	}
	if response.status == 400 || response.status == 401 || response.status == 403 || location != nil && sameNextjsOrigin(original, location) {
		result.Status, result.Observed = "matched", "deny"
	} else {
		result.Reason = "response did not prove an external redirect or explicit rejection"
	}
	return result, nil
}

type boundaryCallbackEvent struct {
	Token  string `json:"token"`
	Count  int    `json:"count"`
	Method string `json:"method"`
}

func runProxyBoundary(c boundaryClient, p preparedBoundary, result AuthorizationResult) (AuthorizationResult, *Finding) {
	anonymous := AuthContext{Identity: "anonymous"}
	auth, _ := nextjsActionAuth(c.req, p.approval.Identity)
	events, _ := url.Parse(p.fixture.EventsURL)
	query := events.Query()
	query.Set("scan_token", p.token)
	events.RawQuery = query.Encode()
	readEvent := func() (boundaryCallbackEvent, error) {
		r, err := c.send(p.inputs[0], events.String(), "GET", "verification", nil, "", anonymous, nil)
		var event boundaryCallbackEvent
		if err != nil || r.status != 200 || json.Unmarshal(r.body, &event) != nil || event.Token != p.token || event.Count < 0 {
			return event, fmt.Errorf("callback event control is invalid")
		}
		return event, nil
	}
	before, err := readEvent()
	if err != nil || before.Count != 0 {
		result.Reason = "fresh callback control was not empty; URL probe was not sent"
		return result, nil
	}
	hash := sha256.Sum256([]byte(p.token))
	result.CorrelationDigest = hex.EncodeToString(hash[:])
	response, sendErr := c.send(p.inputs[0], p.probeURL, "GET", "active_test", nil, "", auth, nil)
	result.ResponseCode, result.ResponseDigest = response.status, response.digest
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(200 * time.Millisecond)
			select {
			case <-c.ctx.Done():
				timer.Stop()
				result.Reason = "callback observation cancelled"
				return result, nil
			case <-timer.C:
			}
		}
		event, err := readEvent()
		if err != nil {
			result.Reason = "callback event verification failed"
			return result, nil
		}
		if event.Count > 0 && (event.Method == "GET" || event.Method == "HEAD") {
			result.Status, result.Observed, result.MarkerConfirmed = "mismatch", "allow", true
			return result, boundaryFinding(c, p, "nextjs-url-fetch-policy", "URL input fetched an explicitly disallowed controlled destination", "medium", "CWE-918", "A fresh per-probe callback token had zero events before the URL-input request and a correlated GET/HEAD event afterward. The scanner never requested the callback URL or followed a target redirect. Internal-network access and browser exploitation were not tested.")
		}
	}
	result.Reason = "no correlated callback in the bounded observation window; fetch denial is not proven"
	if sendErr != nil {
		result.Reason = "URL probe response was unavailable and no correlated callback proved a fetch"
	}
	return result, nil
}
