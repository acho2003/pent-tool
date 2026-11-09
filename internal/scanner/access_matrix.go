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
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

// The access matrix is Xalgorix's native counterpart of the Autorize Burp
// extension, which needs an interactive Burp session and cannot run headless.
// It replays read-only requests that one verified identity actually observed,
// as every other verified identity and anonymously, and compares responses.
//
// Autorize reports any equal response as a bypass, which floods results with
// shared and public pages. A finding here needs all of: a reproducible owner
// baseline; an anonymous control that is denied (so the request is protected
// at all); an equivalent, non-trivial response for the other identity; and
// that identity's own crawl never reaching the request (so it is not simply a
// page every user is shown). Everything else is recorded with its verdict.
const (
	accessMatrixMaxCandidates = 100
	accessMatrixBodyLimit     = 256 << 10
	accessMatrixMinBody       = 64
)

// Access matrix verdicts.
const (
	AccessEnforced          = "enforced"
	AccessBypassSuspected   = "bypass_suspected"
	AccessShared            = "shared"
	AccessPublic            = "public"
	AccessEquivalent        = "equivalent_unprotected_unknown"
	AccessDifferentResponse = "different_response"
	AccessUnknown           = "unknown"
	AccessDenied            = "denied"
)

// AccessMatrixResult is one replay of an observed request as another identity.
type AccessMatrixResult struct {
	EndpointID         string `json:"endpoint_id"`
	Method             string `json:"method"`
	URL                string `json:"url"`
	OwnerContextID     string `json:"owner_context_id"`
	OwnerIdentity      string `json:"owner_identity"`
	OwnerRole          string `json:"owner_role,omitempty"`
	OwnerStatus        int    `json:"owner_status,omitempty"`
	AuthContextID      string `json:"auth_context_id,omitempty"`
	Identity           string `json:"identity"`
	Role               string `json:"role,omitempty"`
	ResponseCode       int    `json:"response_code,omitempty"`
	AnonymousStatus    int    `json:"anonymous_status,omitempty"`
	ObservedByIdentity bool   `json:"observed_by_identity"`
	Verdict            string `json:"verdict"`
	Reason             string `json:"reason,omitempty"`
	EvidenceRef        string `json:"evidence_reference,omitempty"`
}

type accessMatrixRunner struct{}

func (accessMatrixRunner) Name() string { return "authz-matrix" }
func (accessMatrixRunner) Descriptor() Descriptor {
	return Descriptor{Name: "authz-matrix", Summary: "Autorize-style replay of observed requests across verified identities", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightLight}
}

type accessIdentity struct {
	auth    AuthContext
	headers []string
}

type accessResponse struct {
	status   int
	location string
	digest   string
	size     int
	err      string
}

func (accessMatrixRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	run := Run{Scanner: "authz-matrix", Target: req.Target, Scope: req.Scope, Status: "running", StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	finish := func(status, reason string) Run {
		run.Status, run.Reason = status, reason
		return finalizeRun(run)
	}
	if !req.TypedAssessment || req.AppScope == nil || req.Inventory == nil {
		return finish("not_applicable", "the access matrix requires a typed assessment with an approved scope and inventory")
	}
	identities, primaryKey := accessMatrixIdentities(req)
	if len(identities) < 2 {
		run.GapKind = GapEmptyInput
		return finish("not_applicable", "the access matrix needs at least two verified identities for this target")
	}
	candidates := accessMatrixCandidates(req, identities, primaryKey)
	if len(candidates) == 0 {
		run.GapKind = GapEmptyInput
		return finish("not_applicable", "no read-only request observed by a verified identity was selected for the access matrix")
	}
	base := filepath.Join(req.ScanDir, "scanner-output", "authz-matrix")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return finish("failed", "create access matrix output directory: "+err.Error())
	}
	run.ArtifactPath = filepath.Join(base, "findings.jsonl")
	eventsPath := filepath.Join(req.ScanDir, "coverage-events.jsonl")
	events, err := os.OpenFile(eventsPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return finish("failed", "create access matrix coverage events: "+err.Error())
	}
	defer events.Close()
	run.CoverageEventsPath = eventsPath
	if emit != nil {
		emit(Event{Type: "scanner_started", Scanner: run.Scanner, Run: run})
	}
	record := func(kind string, endpoint AttackSurfaceEndpoint, contextID string, code int, reason string) error {
		event := CoverageEvent{Scanner: "authz-matrix", AttemptID: req.AttemptID, Method: endpoint.Method, URL: SafeTelemetryURL(endpoint.URL), Phase: "active_test", Kind: kind, At: time.Now().UTC().Format(time.RFC3339Nano), Reason: reason, ResponseCode: code, EndpointIDs: []string{endpoint.ID}, NativeRef: "authz-matrix:" + contextID}
		if err := json.NewEncoder(events).Encode(event); err != nil {
			return err
		}
		return events.Sync()
	}

	// Each identity is renewed once before and verified once after the matrix;
	// a session lost in between turns its rows into unknowns.
	secrets := slices.Clone(req.Secrets)
	for key, identity := range identities {
		current, err := identity.auth.Refresh(ctx, slices.Clone(identity.auth.Headers))
		if err != nil || len(current) == 0 {
			delete(identities, key)
			run.Limitations = append(run.Limitations, RunLimitation{Kind: "identity_unavailable", Reason: "identity " + identity.auth.Identity + " could not renew its session; it was left out of the matrix"})
			continue
		}
		identity.headers = current
		identities[key] = identity
		for _, line := range current {
			if _, value, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(value) != "" {
				secrets = append(secrets, strings.TrimSpace(value))
			}
		}
	}
	if len(identities) < 2 {
		return finish("failed", "fewer than two identities kept a verified session; the access matrix was not run")
	}
	send := func(endpoint AttackSurfaceEndpoint, contextID string, headers []string) accessResponse {
		if err := browserRequestAllowed(req, cfg, endpoint.Method, endpoint.URL); err != nil {
			return accessResponse{err: "read-only request policy refused the request: " + err.Error()}
		}
		if cfg.Budget != nil {
			if err := cfg.Budget.Wait(ctx); err != nil {
				return accessResponse{err: "assessment request budget exhausted"}
			}
		}
		if err := record("submitted", endpoint, contextID, 0, ""); err != nil {
			return accessResponse{err: "coverage evidence could not be stored"}
		}
		response, err := sendScopedAPIRequestWithHeaders(ctx, cfg, endpoint.URL, endpoint.Method, nil, "", strings.Join(headers, "\n"), http.Header{"Accept": {"*/*"}})
		if err != nil {
			_ = record("failed", endpoint, contextID, 0, "request failed")
			return accessResponse{err: "request failed: " + safeAPIError(err)}
		}
		defer response.Body.Close()
		body, readErr := io.ReadAll(io.LimitReader(response.Body, accessMatrixBodyLimit+1))
		_ = record("observed", endpoint, contextID, response.StatusCode, "")
		result := accessResponse{status: response.StatusCode, location: response.Header.Get("Location")}
		if readErr != nil || len(body) > accessMatrixBodyLimit {
			result.err = "response unavailable or beyond the comparison limit"
			return result
		}
		normalized := normalizeAccessBody(body)
		sum := sha256.Sum256(normalized)
		result.digest, result.size = hex.EncodeToString(sum[:]), len(normalized)
		return result
	}

	var results []AccessMatrixResult
	var pending []accessFinding
	matrixPath := filepath.Join(base, "matrix.jsonl")
	keys := make([]string, 0, len(identities))
	for key := range identities {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			break
		}
		owner, ok := identities[candidate.owner]
		if !ok {
			continue
		}
		endpoint := candidate.endpoint
		row := func(identity AuthContext) AccessMatrixResult {
			return AccessMatrixResult{EndpointID: endpoint.ID, Method: endpoint.Method, URL: SafeTelemetryURL(endpoint.URL), OwnerContextID: owner.auth.ID, OwnerIdentity: owner.auth.Identity, OwnerRole: owner.auth.Role, AuthContextID: identity.ID, Identity: identity.Identity, Role: identity.Role, EvidenceRef: matrixPath}
		}
		baseline := send(endpoint, owner.auth.ID, owner.headers)
		anonymous := send(endpoint, "anonymous", nil)
		anonymousRow := row(AuthContext{Identity: "anonymous"})
		anonymousRow.OwnerStatus, anonymousRow.ResponseCode, anonymousRow.AnonymousStatus = baseline.status, anonymous.status, anonymous.status
		anonymousRow.Verdict, anonymousRow.Reason = classifyAccess(endpoint, baseline, anonymous)
		switch anonymousRow.Verdict {
		case AccessEnforced:
			anonymousRow.Verdict = AccessDenied
		case AccessEquivalent:
			anonymousRow.Verdict, anonymousRow.Reason = AccessPublic, "anonymous requests receive the owner's response"
		}
		results = append(results, anonymousRow)
		for _, key := range keys {
			if key == candidate.owner {
				continue
			}
			other := identities[key]
			result := row(other.auth)
			result.OwnerStatus, result.AnonymousStatus = baseline.status, anonymous.status
			result.ObservedByIdentity = candidate.observedBy[key]
			response := send(endpoint, other.auth.ID, other.headers)
			result.ResponseCode = response.status
			result.Verdict, result.Reason = classifyAccess(endpoint, baseline, response)
			if result.Verdict == AccessEquivalent {
				anonymousDenied := anonymousRow.Verdict == AccessDenied
				switch {
				case anonymous.err == "" && anonymous.status == baseline.status && anonymous.digest == baseline.digest:
					result.Verdict, result.Reason = AccessPublic, "anonymous requests receive the same response; the request is not access-controlled"
				case !anonymousDenied:
					result.Reason = "the response matches the owner's, but the anonymous control was not denied, so protection is unproven"
				case result.ObservedByIdentity:
					result.Verdict, result.Reason = AccessShared, "this identity's own browsing reached the same request; the response is shared between identities"
				default:
					result.Verdict = AccessBypassSuspected
					result.Reason = "anonymous access is denied, the identity's own browsing never reached this request, yet it receives the owner's response"
					pending = append(pending, accessMatrixFinding(req, endpoint, owner.auth, other.auth, baseline, response, anonymous, matrixPath))
				}
			}
			results = append(results, result)
		}
	}
	// Verify every session after the matrix: rows and findings for an identity
	// whose session was lost cannot be trusted. A stopped matrix sends nothing
	// more, so its suspected bypasses stay unconfirmed and are withheld.
	lost := map[string]bool{}
	stopped := ctx.Err() != nil
	if stopped {
		pending = nil
		run.Limitations = append(run.Limitations, RunLimitation{Kind: "stopped", Reason: "the matrix was stopped before sessions were re-verified; suspected bypasses were withheld"})
	} else {
		for _, identity := range identities {
			if verified, err := identity.auth.Refresh(ctx, slices.Clone(identity.headers)); err != nil || len(verified) == 0 {
				lost[identity.auth.ID] = true
				run.Limitations = append(run.Limitations, RunLimitation{Kind: "identity_expired", Reason: "identity " + identity.auth.Identity + " lost its session during the matrix; its results are unknown"})
			}
		}
	}
	file, err := os.OpenFile(run.ArtifactPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return finish("failed", "create access matrix artifact: "+err.Error())
	}
	matrix, err := os.OpenFile(matrixPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		file.Close()
		return finish("failed", "create access matrix evidence: "+err.Error())
	}
	counts := map[string]int{}
	for i := range results {
		result := &results[i]
		if lost[result.AuthContextID] || lost[result.OwnerContextID] {
			result.Verdict, result.Reason = AccessUnknown, "a compared identity lost its session during the matrix"
		}
		counts[result.Verdict]++
		if err := json.NewEncoder(matrix).Encode(result); err != nil {
			file.Close()
			matrix.Close()
			return finish("failed", "write access matrix evidence: "+err.Error())
		}
	}
	findings := 0
	for _, finding := range pending {
		owner, other := finding.authContexts()
		if lost[owner] || lost[other] {
			continue
		}
		if err := json.NewEncoder(file).Encode(finding.Finding); err != nil {
			file.Close()
			matrix.Close()
			return finish("failed", "write access matrix artifact: "+err.Error())
		}
		findings++
	}
	if err := file.Close(); err != nil {
		matrix.Close()
		return finish("failed", "close access matrix artifact: "+err.Error())
	}
	if err := matrix.Close(); err != nil {
		return finish("failed", "close access matrix evidence: "+err.Error())
	}
	for _, path := range []string{run.ArtifactPath, matrixPath} {
		if err := redactArtifact(path, secrets); err != nil {
			invalidateUnsafeArtifact(&run)
			return finish("failed", "access matrix artifact redaction failed; artifact is unavailable")
		}
	}
	run.AccessMatrix = results
	run.ExecutionOutcome = "SUCCESS"
	run.ParserOutcome = "SUCCESS"
	run.Completeness = "complete"
	run.Outcome = "SUCCESS_NO_FINDINGS"
	if findings > 0 {
		run.Outcome = "SUCCESS_WITH_FINDINGS"
	}
	if counts[AccessUnknown] > 0 || len(run.Limitations) > 0 {
		run.Completeness, run.Outcome = "partial", "PARTIAL"
	}
	if stopped {
		run.Status = "cancelled"
		run.Reason = "access matrix stopped; completed comparisons were retained"
		return finalizeRun(run)
	}
	summary := fmt.Sprintf("compared %d observed requests across %d identities and anonymous: %d enforced, %d denied to anonymous, %d shared, %d public, %d suspected bypass, %d unknown", len(candidates), len(identities), counts[AccessEnforced], counts[AccessDenied], counts[AccessShared], counts[AccessPublic], counts[AccessBypassSuspected], counts[AccessUnknown])
	return finish("completed", summary)
}

type accessCandidate struct {
	endpoint   AttackSurfaceEndpoint
	owner      string
	observedBy map[string]bool
}

// accessMatrixIdentities keys verified identities by the context ID their
// inventory observations carry. The primary identity's observations are
// recorded under the inventory's target-bound context.
func accessMatrixIdentities(req Request) (map[string]accessIdentity, string) {
	identities := map[string]accessIdentity{}
	primaryKey := inventoryID(req.Inventory.Scope, "target-bound")
	for _, auth := range req.AuthContexts {
		if auth.TargetID != req.TargetID || auth.State != assessment.StateVerified || auth.Refresh == nil || len(auth.Headers) == 0 || auth.Identity == "anonymous" {
			continue
		}
		key := auth.ID
		if auth.Primary {
			key = primaryKey
		}
		identities[key] = accessIdentity{auth: auth}
	}
	if _, ok := identities[primaryKey]; !ok && strings.TrimSpace(req.TargetAuth) != "" && req.AuthRefresh != nil {
		identities[primaryKey] = accessIdentity{auth: AuthContext{ID: primaryKey, TargetID: req.TargetID, Identity: "primary", Primary: true, State: assessment.StateVerified, Headers: strings.Split(req.TargetAuth, "\n"), Refresh: req.AuthRefresh}}
	}
	return identities, primaryKey
}

func accessMatrixCandidates(req Request, identities map[string]accessIdentity, primaryKey string) []accessCandidate {
	selected := map[string]bool{}
	for _, input := range req.InputRequests {
		if input.Selected {
			selected[input.EndpointID] = true
		}
	}
	observed := map[string]map[string]bool{}
	for _, endpoint := range req.Inventory.Endpoints {
		if endpoint.ObservationKind != "observed" || !endpoint.ObservedWithAuth {
			continue
		}
		key := endpoint.Method + " " + endpoint.URL
		if observed[key] == nil {
			observed[key] = map[string]bool{}
		}
		observed[key][endpoint.AuthContextID] = true
	}
	var out []accessCandidate
	seen := map[string]bool{}
	for _, endpoint := range req.Inventory.Endpoints {
		if !selected[endpoint.ID] {
			continue
		}
		if _, known := identities[endpoint.AuthContextID]; !known {
			continue
		}
		key := endpoint.Method + " " + endpoint.URL
		if seen[key+"\x00"+endpoint.AuthContextID] {
			continue
		}
		seen[key+"\x00"+endpoint.AuthContextID] = true
		out = append(out, accessCandidate{endpoint: endpoint, owner: endpoint.AuthContextID, observedBy: observed[key]})
		if len(out) >= accessMatrixMaxCandidates {
			break
		}
	}
	return out
}

// accessMatrixEligible is the dispatch gate: a GET the identity's own browsing
// actually observed with its session, whose route name does not suggest a
// state change.
func accessMatrixEligible(ep AttackSurfaceEndpoint) (bool, string) {
	switch {
	case ep.Method != http.MethodGet:
		return false, "the access matrix compares GET responses only"
	case !ep.ObservedWithAuth || ep.AuthContextID == "":
		return false, "request was not observed with a verified identity"
	case ep.ObservationKind != "observed":
		return false, "only requests a browser or crawler actually observed are replayed"
	}
	if parsed, err := url.Parse(ep.URL); err == nil && nextjsUnsafeRouteName.MatchString(parsed.EscapedPath()) {
		return false, "route name suggests a state-changing GET"
	}
	return true, ""
}

// classifyAccess compares an identity's response with the owner's baseline.
func classifyAccess(endpoint AttackSurfaceEndpoint, baseline, response accessResponse) (string, string) {
	switch {
	case baseline.err != "":
		return AccessUnknown, "owner baseline unavailable: " + baseline.err
	case baseline.status < 200 || baseline.status > 299:
		return AccessUnknown, fmt.Sprintf("owner baseline returned HTTP %d, so there is nothing to compare", baseline.status)
	case baseline.size < accessMatrixMinBody:
		return AccessUnknown, "owner response is too small to compare meaningfully"
	case response.err != "":
		return AccessUnknown, response.err
	case response.status == http.StatusUnauthorized || response.status == http.StatusForbidden:
		return AccessEnforced, fmt.Sprintf("HTTP %d", response.status)
	case response.status == http.StatusNotFound:
		return AccessEnforced, "HTTP 404 (resource hidden from this identity)"
	case response.status >= 300 && response.status <= 399:
		if accessRedirectsAway(endpoint.URL, response.location) {
			return AccessEnforced, "redirected away from the requested resource"
		}
		return AccessUnknown, fmt.Sprintf("HTTP %d to the same resource", response.status)
	case response.status != baseline.status:
		return AccessUnknown, fmt.Sprintf("HTTP %d differs from the owner's HTTP %d", response.status, baseline.status)
	case response.digest == baseline.digest:
		return AccessEquivalent, "response matches the owner's"
	default:
		return AccessDifferentResponse, "response content differs from the owner's"
	}
}

func accessRedirectsAway(requestURL, location string) bool {
	if strings.TrimSpace(location) == "" {
		return true
	}
	from, err1 := url.Parse(requestURL)
	to, err2 := url.Parse(location)
	if err1 != nil || err2 != nil {
		return true
	}
	to = from.ResolveReference(to)
	return to.Host != from.Host || strings.TrimSuffix(to.Path, "/") != strings.TrimSuffix(from.Path, "/")
}

// Volatile values that differ on every response and would hide equality:
// CSRF tokens, CSP nonces, timestamps and long opaque tokens.
var accessVolatile = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(name=["']?[\w-]*csrf[\w-]*["']?[^>]*?value=)["'][^"']*["']`),
	regexp.MustCompile(`(?i)(<meta[^>]+name=["'][\w-]*csrf[\w-]*["'][^>]+content=)["'][^"']*["']`),
	regexp.MustCompile(`(?i)(nonce=)["'][^"']*["']`),
	regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?`),
	regexp.MustCompile(`[A-Za-z0-9_\-+/=]{40,}`),
}

func normalizeAccessBody(body []byte) []byte {
	normalized := body
	for _, pattern := range accessVolatile {
		if pattern.NumSubexp() > 0 {
			normalized = pattern.ReplaceAll(normalized, []byte(`${1}"~"`))
		} else {
			normalized = pattern.ReplaceAll(normalized, []byte("~"))
		}
	}
	return []byte(strings.TrimSpace(string(normalized)))
}

type accessFinding struct {
	Finding
	ownerContext, otherContext string
}

func (f accessFinding) authContexts() (string, string) { return f.ownerContext, f.otherContext }

func accessMatrixFinding(req Request, endpoint AttackSurfaceEndpoint, owner, other AuthContext, baseline, response, anonymous accessResponse, matrixPath string) accessFinding {
	label := func(auth AuthContext) string {
		if auth.Role != "" {
			return fmt.Sprintf("%q (role %q)", auth.Identity, auth.Role)
		}
		return fmt.Sprintf("%q", auth.Identity)
	}
	parsed, _ := url.Parse(endpoint.URL)
	finding := newAPICheckFinding(req, APIEndpoint{Method: endpoint.Method, Path: parsed.EscapedPath(), Origin: parsed.Scheme + "://" + parsed.Host}, endpoint.URL, "access-matrix-bypass-suspected", "Possible broken access control: another identity receives this identity's response", "medium",
		fmt.Sprintf("Identity %s observed this request while browsing. Replayed with identity %s, it returned HTTP %d with a response equivalent to the owner's, while an anonymous request was denied (HTTP %d) and identity %s's own browsing never reached it. Confirm whether %s should have access; this is a tentative result without supplied role expectations.", label(owner), label(other), response.status, anonymous.status, label(other), label(other)), "CWE-285")
	finding.Scanner = "authz-matrix"
	finding.SourceID = "authz-matrix:" + inventoryID(endpoint.Method+" "+endpoint.URL, owner.ID, other.ID)
	finding.Confidence = "tentative"
	finding.EvidenceRef = matrixPath
	finding.Evidence = fmt.Sprintf("Owner %s: HTTP %d, normalized response sha256 %s (%d bytes)\nIdentity %s: HTTP %d, identical normalized response\nAnonymous: HTTP %d (denied)\nIdentity %s's own browsing did not observe %s %s", label(owner), baseline.status, baseline.digest, baseline.size, label(other), response.status, anonymous.status, label(other), endpoint.Method, SafeTelemetryURL(endpoint.URL))
	finding.EvidenceCompleteness = "status_and_normalized_response_digest"
	finding.Remediation = "Enforce server-side authorization for this resource or function based on the caller's role and ownership, and deny other identities explicitly."
	return accessFinding{Finding: finding, ownerContext: owner.ID, otherContext: other.ID}
}

func parseAccessMatrix(path string) ([]Finding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var findings []Finding
	decoder := json.NewDecoder(file)
	for {
		var finding Finding
		if err := decoder.Decode(&finding); err == io.EOF {
			return findings, nil
		} else if err != nil {
			return findings, fmt.Errorf("parse access matrix findings: %w", err)
		}
		if finding.Scanner == "authz-matrix" && finding.SourceID != "" && finding.Endpoint != "" {
			findings = append(findings, finding)
		}
	}
}

var _ Runner = accessMatrixRunner{}
