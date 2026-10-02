package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	FallbackMaxCandidates = 20
	FallbackMaxBodyBytes  = 256 << 10
)

type FallbackValidation struct {
	Fingerprint       string  `json:"fingerprint"`
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

func validateFallbackURL(ctx context.Context, client *http.Client, endpoint, canary string) (FallbackValidation, bool) {
	result := FallbackValidation{ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	fetch := func(raw string) (int, string, string, int, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		if err != nil {
			return 0, "", "", 0, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, "", "", 0, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, FallbackMaxBodyBytes+1))
		if err != nil {
			return 0, "", "", 0, err
		}
		if len(body) > FallbackMaxBodyBytes {
			return 0, "", "", 0, io.ErrShortBuffer
		}
		hash, size := responseBodySignature(body)
		return resp.StatusCode, strings.ToLower(strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0])), hash, size, nil
	}
	status, contentType, hash, size, err := fetch(endpoint)
	if err != nil {
		result.Reason = "VALIDATION_UNAVAILABLE"
		return result, false
	}
	canaryStatus, canaryType, canaryHash, _, err := fetch(canary)
	if err != nil {
		result.Reason = "VALIDATION_UNAVAILABLE"
		return result, false
	}
	result.Status, result.ContentType, result.BodyHash, result.BodySize = status, contentType, hash, size
	result.CanaryStatus, result.CanaryContentType, result.CanaryBodyHash = canaryStatus, canaryType, canaryHash
	if status == canaryStatus && contentType == canaryType && hash == canaryHash {
		result.Similarity, result.Reason = 1, "SPA_OR_WILDCARD_FALLBACK"
		return result, true
	}
	result.Reason = "RESPONSE_DIFFERED_FROM_CANARY"
	return result, false
}

// ValidateSPAFallback probes only suspicious GET endpoints and one deterministic
// same-origin canary per origin. It is deliberately a separate step so callers
// can omit it for read-only historical projections.
func ValidateSPAFallback(ctx context.Context, snapshot *FindingsSnapshot) []FallbackValidation {
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
			if err != nil || u.Scheme == "" || u.Host == "" {
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
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return http.ErrUseLastResponse
		}
		if len(via) > 0 && !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	results := make([]FallbackValidation, 0, len(candidates))
	for _, candidate := range candidates {
		u, _ := url.Parse(candidate.endpoint)
		origin := u.Scheme + "://" + u.Host
		sum := sha256Bytes([]byte(origin))
		canary := origin + "/xalgorix-canary-" + hex.EncodeToString(sum[:6])
		if result, match := validateFallbackURL(ctx, client, candidate.endpoint, canary); match {
			result.Fingerprint = candidate.fp
			results = append(results, result)
		}
	}
	return results
}

func sha256Bytes(value []byte) []byte { h := sha256.Sum256(value); return h[:] }
