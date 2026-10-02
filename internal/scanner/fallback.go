package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/storage"
)

const (
	FallbackMaxCandidates = 20
	FallbackMaxBodyBytes  = 256 << 10
)

// Fallback validation reasons. Only FallbackReasonMatched reclassifies a
// finding; every other reason records why the finding was left unchanged.
const (
	FallbackReasonMatched         = "SPA_OR_WILDCARD_FALLBACK"
	FallbackReasonDiffered        = "RESPONSE_DIFFERED_FROM_CANARY"
	FallbackReasonUnavailable     = "VALIDATION_UNAVAILABLE"
	FallbackReasonOutOfScope      = "OUT_OF_SCOPE"
	FallbackReasonExcluded        = "EXCLUDED"
	FallbackReasonScopeGuard      = "SCOPE_GUARD_BLOCKED"
	FallbackReasonBudgetExhausted = "BUDGET_EXHAUSTED"
	FallbackReasonCancelled       = "CANCELLED"
)

// FallbackValidationSchemaVersion versions fallback-validation.json.
const FallbackValidationSchemaVersion = 1

type FallbackValidation struct {
	Fingerprint       string  `json:"fingerprint"`
	Endpoint          string  `json:"endpoint,omitempty"`
	Status            int     `json:"status"`
	ContentType       string  `json:"content_type,omitempty"`
	BodyHash          string  `json:"body_hash,omitempty"`
	BodySize          int     `json:"body_size,omitempty"`
	CanaryStatus      int     `json:"canary_status"`
	CanaryContentType string  `json:"canary_content_type,omitempty"`
	CanaryBodyHash    string  `json:"canary_body_hash,omitempty"`
	Similarity        float64 `json:"similarity,omitempty"`
	Reason            string  `json:"reason,omitempty"`
	ObservedAt        string  `json:"observed_at"`
}

// Matched reports whether the endpoint was indistinguishable from the canary.
func (v FallbackValidation) Matched() bool { return v.Reason == FallbackReasonMatched }

// FallbackValidationOptions bounds the network validation step. The zero value
// authorizes no request: Scope must allow every URL fetched.
type FallbackValidationOptions struct {
	// Scope is checked (Allows and Excluded for GET) before every request.
	Scope assessment.AppScope
	// Budget is the assessment-wide budget; each GET waits on it. Nil means
	// no shared budget.
	Budget *AssessmentBudget
	// ScopeGuard is the caller's execution-time guard (Config.ScopeGuard).
	ScopeGuard func(rawURL string, resolved []string) (blocked bool, reason string)
}

// FallbackValidationRecord is the persisted outcome of the scan-time
// validation, reused by later rebuilds and report regeneration so they never
// contact targets.
type FallbackValidationRecord struct {
	SchemaVersion int                  `json:"schema_version"`
	ValidatedAt   string               `json:"validated_at"`
	Results       []FallbackValidation `json:"results"`
}

// FallbackValidationPath is where the scan-time validation results live.
func FallbackValidationPath(scanDir string) string {
	return filepath.Join(scanDir, "fallback-validation.json")
}

// SaveFallbackValidations atomically persists validation results for scanDir.
func SaveFallbackValidations(scanDir string, results []FallbackValidation) error {
	if err := storage.EnsureSecureDir(scanDir); err != nil {
		return err
	}
	record := FallbackValidationRecord{SchemaVersion: FallbackValidationSchemaVersion, ValidatedAt: time.Now().UTC().Format(time.RFC3339Nano), Results: append([]FallbackValidation{}, results...)}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return storage.WriteAtomic(FallbackValidationPath(scanDir), append(data, '\n'))
}

// LoadFallbackValidations returns the stored validation results, or false when
// the scan has none (validation never ran, or the file is unreadable).
func LoadFallbackValidations(scanDir string) ([]FallbackValidation, bool) {
	data, err := os.ReadFile(FallbackValidationPath(scanDir))
	if err != nil {
		return nil, false
	}
	var record FallbackValidationRecord
	if json.Unmarshal(data, &record) != nil || record.SchemaVersion != FallbackValidationSchemaVersion {
		return nil, false
	}
	return record.Results, true
}

// ApplyFallbackValidations marks POTENTIAL findings whose endpoint matched the
// canary as LIKELY_FALSE_POSITIVE and returns how many changed. It performs no
// network access; callers recompute the summary.
func ApplyFallbackValidations(snapshot *FindingsSnapshot, results []FallbackValidation) int {
	if snapshot == nil {
		return 0
	}
	changed := 0
	for _, validation := range results {
		if !validation.Matched() {
			continue
		}
		for i := range snapshot.UniqueFindings {
			if snapshot.UniqueFindings[i].Fingerprint == validation.Fingerprint && snapshot.UniqueFindings[i].Status == StatusPotential {
				snapshot.UniqueFindings[i].Status = StatusLikelyFalsePositive
				snapshot.UniqueFindings[i].ValidationReason = validation.Reason
				changed++
			}
		}
	}
	return changed
}

func suspiciousFallbackPath(raw string) bool {
	lower := strings.ToLower(raw)
	for _, marker := range []string{"/.env", "/.ht", "/.bash_history", "/.sh_history", "backup", ".bak", "/debug", "/actuator", "/metrics"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func responseBodySignature(body []byte) (string, int) {
	trimmed := strings.Join(strings.Fields(strings.ReplaceAll(string(body), "\r", "")), " ")
	h := sha256.Sum256([]byte(trimmed))
	return hex.EncodeToString(h[:]), len(body)
}

// fallbackRequestGate checks scope, exclusions, the caller's guard and the
// budget immediately before one GET. It returns "" when the request may be
// sent, otherwise the reason it was refused.
func fallbackRequestGate(ctx context.Context, opts FallbackValidationOptions, raw string) string {
	if reason := fallbackScopeRefusal(opts, raw); reason != "" {
		return reason
	}
	if err := opts.Budget.Wait(ctx); err != nil {
		if errors.Is(err, ErrBudgetExhausted) {
			return FallbackReasonBudgetExhausted
		}
		return FallbackReasonCancelled
	}
	return ""
}

func fallbackScopeRefusal(opts FallbackValidationOptions, raw string) string {
	if ok, _ := opts.Scope.Allows(raw); !ok {
		return FallbackReasonOutOfScope
	}
	if excluded, _ := opts.Scope.Excluded(http.MethodGet, raw); excluded {
		return FallbackReasonExcluded
	}
	if opts.ScopeGuard != nil {
		if blocked, _ := opts.ScopeGuard(raw, nil); blocked {
			return FallbackReasonScopeGuard
		}
	}
	return ""
}

func validateFallbackURL(ctx context.Context, client *http.Client, opts FallbackValidationOptions, endpoint, canary string) FallbackValidation {
	result := FallbackValidation{Endpoint: endpoint, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	fetch := func(raw string) (int, string, string, int, string) {
		if reason := fallbackRequestGate(ctx, opts, raw); reason != "" {
			return 0, "", "", 0, reason
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		if err != nil {
			return 0, "", "", 0, FallbackReasonUnavailable
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, "", "", 0, FallbackReasonUnavailable
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, FallbackMaxBodyBytes+1))
		if err != nil || len(body) > FallbackMaxBodyBytes {
			return 0, "", "", 0, FallbackReasonUnavailable
		}
		hash, size := responseBodySignature(body)
		return resp.StatusCode, strings.ToLower(strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0])), hash, size, ""
	}
	status, contentType, hash, size, reason := fetch(endpoint)
	if reason != "" {
		result.Reason = reason
		return result
	}
	canaryStatus, canaryType, canaryHash, _, reason := fetch(canary)
	if reason != "" {
		result.Reason = reason
		return result
	}
	result.Status, result.ContentType, result.BodyHash, result.BodySize = status, contentType, hash, size
	result.CanaryStatus, result.CanaryContentType, result.CanaryBodyHash = canaryStatus, canaryType, canaryHash
	if status == canaryStatus && contentType == canaryType && hash == canaryHash {
		result.Similarity, result.Reason = 1, FallbackReasonMatched
		return result
	}
	result.Reason = FallbackReasonDiffered
	return result
}

// fallbackCanary returns a deterministic never-linked URL on the endpoint's
// origin: the origin root when the scope allows it, otherwise the endpoint's
// own directory, so a path-prefixed scope can still be validated.
func fallbackCanary(opts FallbackValidationOptions, u *url.URL) string {
	origin := u.Scheme + "://" + u.Host
	sum := sha256Bytes([]byte(origin))
	name := "xalgorix-canary-" + hex.EncodeToString(sum[:6])
	root := origin + "/" + name
	if fallbackScopeRefusal(opts, root) == "" {
		return root
	}
	dir := path.Dir(u.EscapedPath())
	if !strings.HasSuffix(dir, "/") {
		dir += "/"
	}
	return origin + dir + name
}

// ValidateSPAFallback probes only suspicious GET endpoints and one deterministic
// same-origin canary per endpoint. It is a scan-finalisation step: it must run
// with the scan's context, scope and budget, and its results are persisted
// (SaveFallbackValidations) so rebuilds and report regeneration reuse them via
// ApplyFallbackValidations without network access. Every GET is checked
// against opts.Scope, its exclusions and opts.ScopeGuard, waits on
// opts.Budget, and never follows redirects. It returns one result per
// candidate, including refused ones; only Matched results reclassify.
func ValidateSPAFallback(ctx context.Context, snapshot *FindingsSnapshot, opts FallbackValidationOptions) []FallbackValidation {
	if snapshot == nil {
		return nil
	}
	byID := make(map[string]RawObservation, len(snapshot.RawObservations))
	for _, o := range snapshot.RawObservations {
		byID[o.ID] = o
	}
	candidates := make([]struct{ fp, endpoint string }, 0)
	for _, finding := range snapshot.UniqueFindings {
		if finding.Status == StatusObservation || finding.DedupeScope == DedupeHost {
			continue
		}
		for _, id := range finding.ObservationIDs {
			o := byID[id]
			if !suspiciousFallbackPath(o.Endpoint) {
				continue
			}
			u, err := url.Parse(o.Endpoint)
			if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
				continue
			}
			candidates = append(candidates, struct{ fp, endpoint string }{finding.Fingerprint, o.Endpoint})
			if len(candidates) >= FallbackMaxCandidates {
				break
			}
		}
		if len(candidates) >= FallbackMaxCandidates {
			break
		}
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	results := make([]FallbackValidation, 0, len(candidates))
	stopped := ""
	for _, candidate := range candidates {
		var result FallbackValidation
		if stopped != "" {
			result = FallbackValidation{Endpoint: candidate.endpoint, Reason: stopped, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		} else {
			u, _ := url.Parse(candidate.endpoint)
			result = validateFallbackURL(ctx, client, opts, candidate.endpoint, fallbackCanary(opts, u))
			if result.Reason == FallbackReasonBudgetExhausted || result.Reason == FallbackReasonCancelled {
				stopped = result.Reason
			}
		}
		result.Fingerprint = candidate.fp
		results = append(results, result)
	}
	return results
}

func sha256Bytes(value []byte) []byte { h := sha256.Sum256(value); return h[:] }
