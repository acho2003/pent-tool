package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

// apiWritesRunner is the only component that executes state-changing API
// requests. Every write is journaled before network I/O and is never replayed.
type apiWritesRunner struct{}

func (apiWritesRunner) Name() string { return "apiwrites" }
func (apiWritesRunner) Descriptor() Descriptor {
	return Descriptor{Name: "apiwrites", Summary: "Exactly-once approved API writes with declared cleanup", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightHeavy}
}

func (apiWritesRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	started := time.Now().UTC()
	run := Run{Scanner: "apiwrites", Target: req.Target, Scope: req.Scope, Variant: "apiwrites", StartedAt: started.Format(time.RFC3339Nano), Authenticated: req.TargetAuth != ""}
	finish := func(status, reason string) Run {
		run.Status, run.Reason = status, reason
		run.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if status == "completed" || status == "failed" {
			if status == "failed" {
				run.ExitCode = 1
			} else {
				run.ExitCode = 0
			}
		}
		return run
	}
	if len(req.WriteApprovals) == 0 {
		return finish("skipped", "no explicitly approved API writes")
	}
	if !req.TypedAssessment || !req.TestEnvironment || req.AppScope == nil {
		return finish("failed", "approved writes require a typed assessment, declared test environment, and application scope")
	}
	fixtureDir := req.APIFixtureDir
	if strings.TrimSpace(fixtureDir) == "" {
		fixtureDir = cfg.APIFixtureDir
	}
	if strings.TrimSpace(fixtureDir) == "" {
		return finish("failed", "API fixture store is unavailable")
	}
	journal, err := openRequestWriteJournal(req)
	if err != nil {
		run.GapKind = GapInterruptedWrite
		return finish("failed", "write journal is unreadable; refusing to send approved API requests")
	}
	artifactDir := filepath.Join(req.ScanDir, "scanner-output", "apiwrites")
	if err := os.MkdirAll(artifactDir, 0700); err != nil {
		return finish("failed", "could not create API write evidence directory")
	}
	artifact := filepath.Join(artifactDir, "results.jsonl")
	file, err := os.OpenFile(artifact, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return finish("failed", "could not create API write evidence artifact")
	}
	run.ArtifactPath = artifact
	defer file.Close()
	budget := cfg.Budget
	if budget == nil {
		budget = NewAssessmentBudget(cfg.RateRPS, cfg.WebMaxEndpoints, cfg.WebBudget)
	}
	failures := 0
	for _, approval := range req.WriteApprovals {
		result := APIEndpointResult{Method: approval.Method, Path: approval.Path, Status: "skipped"}
		if !approvedWriteMatchesEndpoint(req.APIOperationEndpoints, approval) && !approvedWriteMatchesEndpoint(req.APIEndpoints, approval) {
			result.Reason = "approved write does not match a bound OpenAPI operation"
			failures++
			appendAPICheckResult(&run, result)
			continue
		}
		if (approval.Method != http.MethodPost && approval.Method != http.MethodPut && approval.Method != http.MethodPatch && approval.Method != http.MethodDelete) || (approval.CleanupMethod != http.MethodDelete && approval.CleanupMethod != http.MethodPut && approval.CleanupMethod != http.MethodPatch) {
			result.Reason = "write or cleanup method is not permitted by the API write adapter"
			failures++
			appendAPICheckResult(&run, result)
			continue
		}
		writeURL, urlErr := scopedAPIPath(req.Target, approval.Path)
		if urlErr != nil {
			result.Reason = "approved write path is invalid"
			failures++
			appendAPICheckResult(&run, result)
			continue
		}
		if allowed, reason := req.AppScope.Allows(writeURL); !allowed {
			result.Reason = "write path is outside application scope: " + reason
			failures++
			appendAPICheckResult(&run, result)
			continue
		}
		if excluded, reason := req.AppScope.Excluded(approval.Method, writeURL); excluded {
			result.Reason = "write path is excluded: " + reason
			failures++
			appendAPICheckResult(&run, result)
			continue
		}
		body, bodyErr := readAPIFixture(fixtureDir, approval.FixtureRef)
		if approval.FixtureRef == "" && approval.Method == http.MethodDelete {
			body, bodyErr = nil, nil
		}
		if bodyErr != nil {
			result.Reason = "approved request fixture is missing or corrupt"
			failures++
			appendAPICheckResult(&run, result)
			continue
		}
		cleanupURL, cleanupErr := scopedAPIPath(req.Target, approval.CleanupPath)
		if cleanupErr != nil || approval.CleanupMethod == "" {
			result.Reason = "declared cleanup request is invalid"
			failures++
			appendAPICheckResult(&run, result)
			continue
		}
		if allowed, reason := req.AppScope.Allows(cleanupURL); !allowed {
			result.Reason = "cleanup path is outside application scope: " + reason
			failures++
			appendAPICheckResult(&run, result)
			continue
		}
		if excluded, reason := req.AppScope.Excluded(approval.CleanupMethod, cleanupURL); excluded {
			result.Reason = "cleanup path is excluded: " + reason
			failures++
			appendAPICheckResult(&run, result)
			continue
		}
		cleanupBody, bodyErr := readAPIFixture(fixtureDir, approval.CleanupRef)
		if approval.CleanupRef == "" && approval.CleanupMethod == http.MethodDelete {
			cleanupBody, bodyErr = nil, nil
		}
		if bodyErr != nil {
			result.Reason = "declared cleanup fixture is missing or corrupt"
			failures++
			appendAPICheckResult(&run, result)
			continue
		}
		operationKey := req.Scope + ":" + approval.Method + ":" + approval.Path
		entry := WriteJournalEntry{OperationID: operationKey, JobID: "apiwrites", Method: approval.Method, RedactedURL: writeURL, FixtureRef: approval.FixtureRef, CleanupMethod: approval.CleanupMethod, CleanupURL: cleanupURL, CleanupRef: approval.CleanupRef}
		if err := journal.RecordIntent(entry); err != nil {
			result.Reason = "write is already journaled or the journal could not be updated; request was not sent"
			failures++
			appendAPICheckResult(&run, result)
			continue
		}
		if err := budget.Wait(ctx); err != nil {
			result.Reason = "assessment budget stopped the write before network I/O: " + err.Error()
			failures++
			// Intent is deliberately left unresolved; even cancellation at this
			// point must not permit a later process to replay this approval.
			run.GapKind = GapInterruptedWrite
			appendAPICheckResult(&run, result)
			continue
		}
		response, sendErr := sendScopedAPIRequest(ctx, cfg, writeURL, approval.Method, body, approval.ContentType, req.TargetAuth)
		if sendErr != nil {
			result.Reason = "write outcome is unknown; journal prevents replay"
			run.GapKind = GapInterruptedWrite
			failures++
			appendAPICheckResult(&run, result)
			continue
		}
		if err := journal.MarkSent(operationKey); err != nil {
			response.Body.Close()
			result.Reason = "write answered but journal state could not be updated; cleanup was not attempted"
			run.GapKind = GapInterruptedWrite
			failures++
			appendAPICheckResult(&run, result)
			continue
		}
		responseStatus := response.StatusCode
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		response.Body.Close()
		result.Status = "written"
		if responseStatus < 200 || responseStatus >= 300 {
			result.Reason = fmt.Sprintf("write returned HTTP %d; cleanup was still attempted", responseStatus)
			failures++
		}
		if err := budget.Wait(ctx); err != nil {
			_ = journal.MarkCleanup(operationKey, false)
			result.Status, result.Reason = "cleanup_failed", "write answered but budget ended before declared cleanup"
			run.GapKind = GapInterruptedWrite
			failures++
			appendAPICheckResult(&run, result)
			continue
		}
		cleanupResponse, cleanupSendErr := sendScopedAPIRequest(ctx, cfg, cleanupURL, approval.CleanupMethod, cleanupBody, approval.CleanupContentType, req.TargetAuth)
		cleanupOK := cleanupSendErr == nil
		if cleanupOK {
			status := cleanupResponse.StatusCode
			_, _ = io.Copy(io.Discard, io.LimitReader(cleanupResponse.Body, 64<<10))
			cleanupResponse.Body.Close()
			cleanupOK = status >= 200 && status < 300
		}
		if markErr := journal.MarkCleanup(operationKey, cleanupOK); markErr != nil {
			result.Status, result.Reason = "cleanup_failed", "cleanup finished but its journal outcome could not be persisted"
			failures++
		} else if !cleanupOK {
			result.Status, result.Reason = "cleanup_failed", "write was sent but declared cleanup did not complete successfully"
			failures++
		} else if responseStatus >= 200 && responseStatus < 300 {
			result.Status = "completed"
		}
		appendAPICheckResult(&run, result)
	}
	for _, result := range run.APIEndpointResults {
		if err := json.NewEncoder(file).Encode(result); err != nil {
			return finish("failed", "could not persist API write evidence")
		}
	}
	if err := file.Sync(); err != nil {
		return finish("failed", "could not sync API write evidence")
	}
	if failures > 0 {
		return finish("failed", fmt.Sprintf("%d approved API write or cleanup checks failed or were skipped", failures))
	}
	return finish("completed", "approved API writes were sent once and declared cleanup completed")
}

func approvedWriteMatchesEndpoint(endpoints []APIEndpoint, approval assessment.WriteApproval) bool {
	for _, endpoint := range endpoints {
		if (endpoint.Source == "openapi" || endpoint.Source == "") && endpoint.OperationID == approval.OperationID &&
			strings.EqualFold(endpoint.Method, approval.Method) && endpoint.Path == approval.Path {
			return true
		}
	}
	return false
}

func scopedAPIPath(applicationURL, operationPath string) (string, error) {
	if !strings.HasPrefix(operationPath, "/") || strings.ContainsAny(operationPath, "?#\\{}") {
		return "", errors.New("invalid absolute API path")
	}
	pathValue, err := url.PathUnescape(operationPath)
	if err != nil {
		return "", err
	}
	for _, segment := range strings.Split(pathValue, "/") {
		if segment == "." || segment == ".." {
			return "", errors.New("path traversal")
		}
	}
	base, err := url.Parse(applicationURL)
	if err != nil || base.Host == "" || base.User != nil || (base.Scheme != "http" && base.Scheme != "https") {
		return "", errors.New("invalid application URL")
	}
	base.Path = strings.TrimSuffix(base.Path, "/") + "/" + strings.TrimLeft(pathValue, "/")
	base.RawPath, base.RawQuery, base.Fragment = "", "", ""
	return base.String(), nil
}

func readAPIFixture(dir, ref string) ([]byte, error) {
	if ref == "" {
		return nil, errors.New("missing fixture reference")
	}
	decoded, err := hex.DecodeString(ref)
	if err != nil || len(decoded) != sha256.Size {
		return nil, errors.New("invalid fixture reference")
	}
	data, err := os.ReadFile(filepath.Join(dir, ref+".body"))
	if err != nil || len(data) == 0 || len(data) > 1<<20 {
		return nil, errors.New("fixture is missing or outside configured size limits")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != ref {
		return nil, errors.New("fixture content checksum mismatch")
	}
	return data, nil
}

func sendScopedAPIRequest(ctx context.Context, cfg Config, rawURL, method string, body []byte, contentType, authLines string) (*http.Response, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	addresses, err := resolveAPICheckAddresses(ctx, parsed.Hostname())
	if err != nil {
		return nil, err
	}
	var addressStrings []string
	for _, address := range addresses {
		addressStrings = append(addressStrings, address.String())
	}
	if cfg.ScopeGuard != nil {
		if blocked, reason := cfg.ScopeGuard(rawURL, addressStrings); blocked {
			return nil, fmt.Errorf("scope guard refused approved write: %s", reason)
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if contentType != "" && len(body) > 0 {
		request.Header.Set("Content-Type", contentType)
	}
	request.Header.Set("Accept", "application/json, text/plain;q=0.8, */*;q=0.1")
	for _, line := range strings.Split(authLines, "\n") {
		name, value, ok := strings.Cut(line, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || name == "" || strings.ContainsAny(name+value, "\r\n\x00") || !validCredentialHeader(name) {
			continue
		}
		request.Header.Add(name, value)
	}
	return apiCheckClientFor(parsed, addresses).Do(request)
}

func validCredentialHeader(name string) bool {
	switch strings.ToLower(name) {
	case "host", "content-length", "transfer-encoding", "connection", "proxy-authorization", "proxy-connection":
		return false
	default:
		return true
	}
}
