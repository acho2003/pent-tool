package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// exposureCheck is one catalog entry: a path probed relative to the approved
// target root, and a short human purpose. Catalogs stay small and reviewable.
type exposureCheck struct {
	ID, Path, Purpose string
}

// exposureVerdict is a classifier's judgement of one probed response. An empty
// Classification means "not a finding" and the response is discarded. Evidence
// must be redaction-safe: it is written to the findings artifact and must never
// carry a raw secret value — report shapes, counts and header fingerprints, not
// response bodies.
type exposureVerdict struct {
	Classification string
	Severity       string
	Title          string
	Evidence       string
}

// exposureClassifier decides whether one probed response is a finding. body is
// capped at exposureBodyLimit bytes. It must not place raw secrets in the
// verdict it returns.
type exposureClassifier func(check exposureCheck, resp *http.Response, body []byte) exposureVerdict

const exposureBodyLimit = 32 * 1024

// runExposureCatalog walks a small catalog of sensitive paths with read-only
// GETs, enforcing the approved scope and exclusions on every request and every
// redirect hop, and writes one finding per positive classification. It is the
// shared engine behind the bounded read-only exposure adapters (actuator, VCS,
// exposed files): each supplies only its scanner id, catalog version, catalog
// and classifier. Like kube-exposure/nextjs-assets it validates each request
// natively, so it is gateway-equivalent and carries no direct-egress caveat.
func runExposureCatalog(ctx context.Context, req Request, cfg Config, emit EmitFunc, scanner, catalogVersion, label string, catalog []exposureCheck, classify exposureClassifier) Run {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	run := Run{Scanner: scanner, Target: req.Target, Scope: req.Scope, Status: "running", StartedAt: now, Variant: catalogVersion}
	finish := func(status, reason string) Run {
		run.Status, run.Reason, run.FinishedAt = status, reason, time.Now().UTC().Format(time.RFC3339Nano)
		return finalizeRun(run)
	}
	if !req.TypedAssessment || req.AppScope == nil {
		return finish("failed", label+" checks require a typed URL assessment scope")
	}
	base, err := url.Parse(strings.TrimSpace(req.Target))
	if err != nil || base.Scheme == "" || base.Host == "" || base.User != nil || (base.Scheme != "http" && base.Scheme != "https") {
		return finish("failed", "target must be an absolute HTTP(S) URL without credentials")
	}
	if emit != nil {
		emit(Event{Type: "scanner_started", Scanner: run.Scanner, Run: run})
	}
	dir := filepath.Join(req.ScanDir, "scanner-output", scanner)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return finish("failed", "create artifact directory: "+err.Error())
	}
	artifact := filepath.Join(dir, "findings.jsonl")
	file, err := os.OpenFile(artifact, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return finish("failed", "create artifact: "+err.Error())
	}
	defer file.Close()
	run.ArtifactPath = artifact
	// Each origin gets a client pinned to the addresses the scope guard judged;
	// redirects are followed here so every hop is checked against the approved
	// scope and exclusions before it is requested.
	clients := map[string]*http.Client{}
	refused := map[string]error{}
	get := func(raw string) (*http.Response, error) {
		for hop := 0; ; hop++ {
			parsed, err := url.Parse(raw)
			if err != nil {
				return nil, err
			}
			origin := parsed.Scheme + "://" + parsed.Host
			if err := refused[origin]; err != nil {
				return nil, err
			}
			client := clients[origin]
			if client == nil {
				if client, err = guardedOriginClient(ctx, cfg, raw); err != nil {
					refused[origin] = err
					return nil, err
				}
				clients[origin] = client
			}
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
			if err != nil {
				return nil, err
			}
			resp, err := client.Do(request)
			if err != nil {
				return nil, err
			}
			location := resp.Header.Get("Location")
			if resp.StatusCode < 300 || resp.StatusCode > 399 || location == "" {
				return resp, nil
			}
			resp.Body.Close()
			next, err := parsed.Parse(location)
			if err != nil {
				return nil, fmt.Errorf("redirect refused: invalid location")
			}
			if hop >= 2 {
				return nil, fmt.Errorf("redirect limit exceeded")
			}
			next.Fragment = ""
			if ok, reason := req.AppScope.Allows(next.String()); !ok {
				return nil, fmt.Errorf("redirect refused: %s", reason)
			}
			if excluded, _ := req.AppScope.Excluded(http.MethodGet, next.String()); excluded {
				return nil, fmt.Errorf("redirect refused: the redirect target is excluded")
			}
			raw = next.String()
		}
	}
	attempted, completed, findings := 0, 0, 0
	var lastErr string
	for _, check := range catalog {
		if err := ctx.Err(); err != nil {
			run.Status, run.GapKind, run.Reason = "failed", GapCancelled, "checks cancelled before catalog completion"
			break
		}
		candidate := *base
		candidate.RawQuery, candidate.Fragment = "", ""
		candidate.Path = path.Join(strings.TrimSuffix(base.Path, "/"), check.Path)
		if strings.HasSuffix(check.Path, "/") {
			candidate.Path += "/"
		}
		raw := candidate.String()
		if ok, _ := req.AppScope.Allows(raw); !ok {
			continue
		}
		if excluded, _ := req.AppScope.Excluded(http.MethodGet, raw); excluded {
			continue
		}
		if err := cfg.Budget.Wait(ctx); err != nil {
			run.Status, run.GapKind, run.Reason = "failed", GapBudgetExhausted, "assessment request budget stopped remaining checks: "+err.Error()
			break
		}
		attempted++
		resp, err := get(raw)
		if err != nil {
			lastErr = probeRequestError(err)
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, exposureBodyLimit))
		resp.Body.Close()
		if readErr != nil {
			lastErr = "response read failed: " + readErr.Error()
			continue
		}
		completed++
		verdict := classify(check, resp, body)
		if verdict.Classification == "" {
			continue
		}
		sev := verdict.Severity
		if sev == "" {
			sev = "info"
		}
		evidence := verdict.Evidence
		if evidence == "" {
			indicator := strings.TrimSpace(strings.Join([]string{resp.Header.Get("Server"), resp.Header.Get("Content-Type")}, "; "))
			evidence = fmt.Sprintf("HTTP %d; indicators: %s; classification: %s", resp.StatusCode, indicator, verdict.Classification)
		}
		title := verdict.Title
		if title == "" {
			title = check.Purpose
		}
		findings++
		_ = json.NewEncoder(file).Encode(Finding{SourceID: scanner + ":" + check.ID, Scanner: scanner, RuleID: check.ID, Title: title, Severity: sev, Target: req.Target, Endpoint: sanitizeProbeURL(raw), Method: http.MethodGet, Description: check.Purpose, Evidence: evidence, Confidence: verdict.Classification})
	}
	if run.Status == "running" {
		if completed == 0 {
			run.Status, run.GapKind, run.Reason = "failed", GapRequestFailed, fmt.Sprintf("no catalog request completed (%d attempted; %s)", attempted, firstNonEmptyStr(lastErr, "all requests were refused or failed"))
		} else {
			run.Status, run.Reason = "completed", fmt.Sprintf("completed %d/%d bounded read-only %s checks; %d findings", completed, attempted, label, findings)
		}
	}
	return finish(run.Status, run.Reason)
}

func firstNonEmptyStr(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func probeRequestError(err error) string {
	text := strings.TrimSpace(err.Error())
	for _, marker := range []string{"x509:", "no such host", "connection refused", "i/o timeout", "context deadline exceeded", "redirect refused", "redirect limit exceeded"} {
		if i := strings.Index(strings.ToLower(text), strings.ToLower(marker)); i >= 0 {
			return text[i:]
		}
	}
	return text
}

func sanitizeProbeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	u.User, u.RawQuery, u.Fragment = nil, "", ""
	return u.String()
}

// parseExposureFindings reads the jsonl findings written by runExposureCatalog.
func parseExposureFindings(path string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Finding
	dec := json.NewDecoder(f)
	for {
		var v Finding
		if err := dec.Decode(&v); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
