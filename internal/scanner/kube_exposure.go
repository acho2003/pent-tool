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
	"regexp"
	"strings"
	"time"
)

type kubeExposureRunner struct{}

func (kubeExposureRunner) Name() string { return "kube-exposure" }
func (kubeExposureRunner) Descriptor() Descriptor {
	return Descriptor{Name: "kube-exposure", Summary: "Bounded read-only Kubernetes exposure checks", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightLight}
}

var kubeSensitive = regexp.MustCompile(`(?i)(system:[a-z0-9._-]+|[a-z0-9-]+\.(default|kube-system)\.svc|kubernetes[_ -]?(api|control)|namespace|pod/[a-z0-9-]+)`)

func (kubeExposureRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	run := Run{Scanner: "kube-exposure", Target: req.Target, Scope: req.Scope, Status: "running", StartedAt: now, Variant: kubeExposureCatalogVersion}
	finish := func(status, reason string) Run {
		run.Status, run.Reason, run.FinishedAt = status, reason, time.Now().UTC().Format(time.RFC3339Nano)
		return finalizeRun(run)
	}
	if !req.TypedAssessment || req.AppScope == nil {
		return finish("failed", "Kubernetes exposure checks require a typed URL assessment scope")
	}
	base, err := url.Parse(strings.TrimSpace(req.Target))
	if err != nil || base.Scheme == "" || base.Host == "" || base.User != nil || (base.Scheme != "http" && base.Scheme != "https") {
		return finish("failed", "target must be an absolute HTTP(S) URL without credentials")
	}
	if emit != nil {
		emit(Event{Type: "scanner_started", Scanner: run.Scanner, Run: run})
	}
	dir := filepath.Join(req.ScanDir, "scanner-output", "kube-exposure")
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
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	checks := append([]kubeExposureCheck{{ID: "supplied-url", Path: base.EscapedPath(), Purpose: "supplied URL response"}}, kubeExposureCatalog...)
	completed := 0
	for _, check := range checks {
		if err := ctx.Err(); err != nil {
			run.Status, run.GapKind, run.Reason = "failed", GapCancelled, "checks cancelled before catalog completion"
			break
		}
		candidate := *base
		candidate.RawQuery, candidate.Fragment = "", ""
		if check.ID != "supplied-url" {
			candidate.Path = path.Join(strings.TrimSuffix(base.Path, "/"), check.Path)
		}
		raw := candidate.String()
		if ok, _ := req.AppScope.Allows(raw); !ok {
			continue
		}
		if err := cfg.Budget.Wait(ctx); err != nil {
			run.Status, run.GapKind, run.Reason = "failed", GapBudgetExhausted, "assessment request budget stopped remaining checks: "+err.Error()
			break
		}
		resp, err := client.Get(raw)
		if err != nil {
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
		resp.Body.Close()
		if readErr != nil {
			continue
		}
		completed++
		text := string(body)
		lower := strings.ToLower(text)
		header := strings.ToLower(resp.Header.Get("Server") + " " + resp.Header.Get("Content-Type"))
		indicator := strings.TrimSpace(strings.Join([]string{resp.Header.Get("Server"), resp.Header.Get("Content-Type")}, "; "))
		classification, sev, title := "inconclusive", "info", check.Purpose
		if check.ID == "kubernetes-api" && resp.StatusCode == http.StatusOK && strings.Contains(lower, "gitversion") {
			classification, title = "confirmed_exposure", "Unauthenticated Kubernetes API version endpoint"
			sev = "medium"
		}
		if check.ID == "supplied-url" && (strings.Contains(lower, "kubernetes") || strings.Contains(header, "ingress")) {
			classification, title = "probable_service", "Kubernetes-related response fingerprint"
		}
		if kubeSensitive.MatchString(text) {
			classification, title = "information_disclosure", "Kubernetes internal service information disclosed"
			sev = "low"
		}
		if classification != "inconclusive" {
			_ = json.NewEncoder(file).Encode(Finding{SourceID: "kube-exposure:" + check.ID, Scanner: "kube-exposure", RuleID: check.ID, Title: title, Severity: sev, Target: req.Target, Endpoint: sanitizeKubeURL(raw), Method: http.MethodGet, Description: check.Purpose, Evidence: fmt.Sprintf("HTTP %d; indicators: %s; classification: %s", resp.StatusCode, indicator, classification), Confidence: classification})
		}
	}
	if run.Status == "running" {
		if completed == 0 {
			run.Status, run.GapKind, run.Reason = "failed", GapRequestFailed, "no catalog request completed"
		} else {
			run.Status, run.Reason = "completed", fmt.Sprintf("completed %d bounded read-only Kubernetes exposure checks", completed)
		}
	}
	return finish(run.Status, run.Reason)
}

func sanitizeKubeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	u.User, u.RawQuery, u.Fragment = nil, "", ""
	return u.String()
}

func parseKubeExposure(path string) ([]Finding, error) {
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
