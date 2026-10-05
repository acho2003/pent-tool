package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"net/url"
)

// browserRequestAllowed is shared by browser discovery and request recording.
// Discovery does not submit forms or treat GET exclusions as harmless.
func browserRequestAllowed(req Request, cfg Config, method, rawURL string) error {
	if req.AppScope == nil {
		return fmt.Errorf("approved scope required")
	}
	if ok, reason := req.AppScope.Allows(rawURL); !ok {
		return fmt.Errorf("%s", reason)
	}
	if excluded, reason := req.AppScope.Excluded(method, rawURL); excluded {
		return fmt.Errorf("excluded: %s", reason)
	}
	if parsed, err := url.Parse(rawURL); err == nil {
		query := strings.TrimSpace(parsed.Query().Get("query"))
		if strings.Contains(query, "{") || strings.HasPrefix(query, "query ") || strings.HasPrefix(query, "query(") || strings.HasPrefix(query, "mutation") || strings.HasPrefix(query, "subscription") {
			document, err := parser.ParseQuery(&ast.Source{Input: query})
			if err != nil {
				return fmt.Errorf("GraphQL query is invalid")
			}
			for _, operation := range document.Operations {
				if operation.Operation != ast.Query {
					return fmt.Errorf("GraphQL writes require explicit operation approval")
				}
			}
		}
	}
	if method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions {
		return fmt.Errorf("state-changing browser request requires explicit operation approval")
	}
	if cfg.ScopeGuard != nil {
		if blocked, reason := cfg.ScopeGuard(rawURL, nil); blocked {
			return fmt.Errorf("%s", reason)
		}
	}
	return nil
}

// DiscoverBrowser records browser requests through an intercepted, bounded Go
// client. Chrome cannot follow a redirect outside the approved request gate.
func DiscoverBrowser(ctx context.Context, req Request, cfg Config) (run Run) {
	run = Run{Scanner: "browser", Target: req.Target, Scope: req.Scope, Status: "running", StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	defer func() { run = finalizeRun(run) }()
	if cfg.KatanaChromePath == "" {
		run.Status, run.Reason = "not_applicable", "Chromium is unavailable"
		return
	}
	if err := os.MkdirAll(req.ScanDir, 0700); err != nil {
		run.Status, run.Reason = "failed", err.Error()
		return
	}
	run.ArtifactPath = filepath.Join(req.ScanDir, "browser.jsonl")
	f, err := os.OpenFile(run.ArtifactPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		run.Status, run.Reason = "failed", err.Error()
		return
	}
	defer f.Close()
	timeout := cfg.KatanaTimeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var authMu sync.Mutex
	lastAuthCheck := time.Time{}
	var authFailure error
	verifyAuth := func() error {
		authMu.Lock()
		defer authMu.Unlock()
		if authFailure != nil {
			return authFailure
		}
		if req.TargetAuth == "" {
			return nil
		}
		if req.AuthRefresh == nil {
			authFailure = fmt.Errorf("browser authentication requires a runtime verifier")
			return authFailure
		}
		if time.Since(lastAuthCheck) < 30*time.Second {
			return nil
		}
		headers, err := req.AuthRefresh(ctx, strings.Split(req.TargetAuth, "\n"))
		if err != nil {
			authFailure = fmt.Errorf("browser authentication checkpoint failed")
			return authFailure
		}
		req.TargetAuth = strings.Join(headers, "\n")
		lastAuthCheck = time.Now()
		return nil
	}
	if err := verifyAuth(); err != nil {
		markAuthExpired(&run)
		run.Reason = err.Error()
		return
	}
	profileDir, err := os.MkdirTemp(req.ScanDir, "browser-profile-")
	if err != nil {
		run.Status, run.Reason = "failed", err.Error()
		return
	}
	defer os.RemoveAll(profileDir)
	launch := launcher.New().Context(ctx).Bin(cfg.KatanaChromePath).UserDataDir(profileDir).Headless(true).NoSandbox(true).Leakless(false)
	control, err := launch.Launch()
	if err != nil {
		run.Status, run.Reason = "failed", "launch Chromium: "+err.Error()
		return
	}
	defer launch.Cleanup()
	browser := rod.New().Context(ctx).ControlURL(control)
	if err := browser.Connect(); err != nil {
		run.Status, run.Reason = "failed", err.Error()
		return
	}
	defer browser.Close()
	var mu sync.Mutex
	var workers sync.WaitGroup
	closing := false
	encoder := json.NewEncoder(f)
	observed := map[string]bool{}
	count := 0
	partial := false
	limitReasons := map[string]bool{}
	markLimit := func(reason string) { mu.Lock(); partial = true; limitReasons[reason] = true; mu.Unlock() }
	max := cfg.WebMaxEndpoints
	if max <= 0 {
		max = 500
	}
	record := func(row any) {
		mu.Lock()
		defer mu.Unlock()
		if err := encoder.Encode(row); err != nil {
			partial = true
			limitReasons["browser observation could not be persisted"] = true
		}
	}
	router := browser.HijackRequests()
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	bound, _ := assessment.ParseApprovedOrigin("", req.Target)
	err = router.Add("*", "", func(h *rod.Hijack) {
		mu.Lock()
		if closing {
			mu.Unlock()
			h.Response.Fail(proto.NetworkErrorReasonBlockedByClient)
			return
		}
		workers.Add(1)
		mu.Unlock()
		defer workers.Done()
		rawURL, method := h.Request.URL().String(), h.Request.Method()
		if err := verifyAuth(); err != nil {
			cancel()
			h.Response.Fail(proto.NetworkErrorReasonBlockedByClient)
			return
		}
		requestBody := []byte(h.Request.Body())
		if err := browserDiscoveryRequestAllowed(req, cfg, method, rawURL, h.Request.Req().Header.Get("Content-Type"), requestBody); err != nil {
			markLimit("browser request excluded by approved policy: " + err.Error())
			h.Response.Fail(proto.NetworkErrorReasonBlockedByClient)
			return
		}
		mu.Lock()
		if count >= max {
			partial = true
			limitReasons[fmt.Sprintf("browser HTTP request limit reached (%d)", max)] = true
			mu.Unlock()
			h.Response.Fail(proto.NetworkErrorReasonBlockedByClient)
			return
		}
		count++
		mu.Unlock()
		if err := cfg.Budget.Wait(ctx); err != nil {
			markLimit("assessment rate or time budget ended during browser discovery")
			h.Response.Fail(proto.NetworkErrorReasonBlockedByClient)
			return
		}
		origin, _ := assessment.ParseApprovedOrigin("", rawURL)
		sameOrigin := origin.Scheme == bound.Scheme && origin.Host == bound.Host && origin.Port == bound.Port
		authMu.Lock()
		boundHeaders := req.TargetAuth
		authMu.Unlock()
		for _, header := range strings.Split(boundHeaders, "\n") {
			name, _, ok := strings.Cut(header, ":")
			if ok {
				h.Request.Req().Header.Del(strings.TrimSpace(name))
			}
		}
		if sameOrigin {
			for _, header := range strings.Split(boundHeaders, "\n") {
				name, value, ok := strings.Cut(header, ":")
				if ok {
					h.Request.Req().Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
				}
			}
		} else {
			h.Request.Req().Header.Del("Authorization")
			h.Request.Req().Header.Del("Cookie")
		}
		response, err := client.Do(h.Request.Req().WithContext(ctx))
		if err != nil {
			h.Response.Fail(proto.NetworkErrorReasonFailed)
			markLimit("browser upstream request failed")
			return
		}
		defer response.Body.Close()
		body, readErr := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
		if readErr != nil || len(body) > 2<<20 {
			markLimit("browser response exceeded 2097152 bytes or could not be read")
			h.Response.Fail(proto.NetworkErrorReasonFailed)
			return
		}
		h.Response.Payload().ResponseCode = response.StatusCode
		for name, values := range response.Header {
			for _, v := range values {
				h.Response.SetHeader(name, v)
			}
		}
		h.Response.SetBody(body)
		// Bodies/credentials are not copied into public discovery artifacts.
		requestRecord := map[string]any{"endpoint": rawURL, "method": method, "source": "browser", "headers": map[string]string{"content-type": h.Request.Req().Header.Get("Content-Type")}}
		if len(requestBody) > 0 {
			sum := sha256.Sum256(requestBody)
			requestRecord["body_digest"] = hex.EncodeToString(sum[:])
			requestRecord["parameters"] = bodyParameters(string(requestBody), h.Request.Req().Header.Get("Content-Type"))
		}
		row := map[string]any{"timestamp": time.Now().UTC().Format(time.RFC3339Nano), "request": requestRecord, "response": map[string]any{"status_code": response.StatusCode, "headers": map[string]string{"content-type": response.Header.Get("Content-Type")}}}
		record(row)
		mu.Lock()
		observed[rawURL] = true
		mu.Unlock()
	})
	if err != nil {
		run.Status, run.Reason = "failed", err.Error()
		return
	}
	go router.Run()
	var stopOnce sync.Once
	stopWorkers := func() {
		stopOnce.Do(func() {
			mu.Lock()
			closing = true
			mu.Unlock()
			_ = router.Stop()
			cancel()
			workers.Wait()
			client.CloseIdleConnections()
		})
	}
	defer stopWorkers()
	type entry struct {
		url   string
		depth int
	}
	queue := []entry{{req.Target, 0}}
	visited := map[string]bool{}
	for len(queue) > 0 && ctx.Err() == nil {
		next := queue[0]
		queue = queue[1:]
		if visited[next.url] {
			continue
		}
		visited[next.url] = true
		if err := browserRequestAllowed(req, cfg, "GET", next.url); err != nil {
			continue
		}
		pageCtx, pageCancel := context.WithTimeout(ctx, 20*time.Second)
		page, err := browser.Context(pageCtx).Page(proto.TargetCreateTarget{URL: "about:blank"})
		if err == nil {
			err = page.Navigate(next.url)
		}
		if err == nil {
			err = page.WaitLoad()
			if err == nil {
				page.WaitRequestIdle(300*time.Millisecond, nil, nil, nil)()
			}
		}
		if err == nil {
			result, e := page.Eval(`() => JSON.stringify({links:Array.from(document.querySelectorAll('a[href]')).map(a=>a.href),forms:Array.from(document.forms).map(f=>({action:f.action,method:f.method,fields:Array.from(f.elements).filter(e=>e.name).map(e=>({name:e.name}))}))})`)
			if e == nil {
				var extracted struct {
					Links []string         `json:"links"`
					Forms []map[string]any `json:"forms"`
				}
				if json.Unmarshal([]byte(result.Value.Str()), &extracted) == nil {
					record(map[string]any{"request": map[string]any{"endpoint": next.url, "method": "GET", "source": "browser-dom"}, "forms": extracted.Forms})
					if next.depth >= katanaDefaultDepth && len(extracted.Links) > 0 {
						markLimit(fmt.Sprintf("browser crawl depth limit reached (%d)", katanaDefaultDepth))
					}
					if next.depth < katanaDefaultDepth {
						for _, link := range extracted.Links {
							if len(queue)+len(visited) < max {
								queue = append(queue, entry{link, next.depth + 1})
							} else {
								markLimit(fmt.Sprintf("browser navigation queue limit reached (%d)", max))
							}
						}
					}
				}
			}
		} else {
			markLimit("browser navigation or page loading failed (20-second navigation deadline)")
		}
		if page != nil {
			_ = page.Close()
		}
		pageCancel()
	}
	timedOut := ctx.Err() != nil
	stopWorkers()
	mu.Lock()
	defer mu.Unlock()
	run.Status = "completed"
	authMu.Lock()
	run.Authenticated = req.TargetAuth != "" && authFailure == nil
	if authFailure != nil {
		markAuthExpired(&run)
		run.Reason = authFailure.Error()
		authMu.Unlock()
		return
	}
	authMu.Unlock()
	run.Completeness = "complete"
	if timedOut {
		limitReasons["browser discovery cancelled or time budget exhausted"] = true
	}
	if timedOut || partial {
		reasons := make([]string, 0, len(limitReasons))
		for reason := range limitReasons {
			reasons = append(reasons, reason)
		}
		sort.Strings(reasons)
		for _, reason := range reasons {
			run.Limitations = append(run.Limitations, RunLimitation{Kind: "browser_discovery_limit", Reason: reason})
		}
		run.Outcome, run.Completeness, run.Reason = "PARTIAL", "partial", strings.Join(reasons, "; ")
	}
	if count == 0 {
		run.Status, run.Reason = "failed", "browser produced no approved HTTP observations"
	}
	return
}
