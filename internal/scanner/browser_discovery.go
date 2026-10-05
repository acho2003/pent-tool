package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/xalgord/xalgorix/v4/internal/assessment"
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
	encoder := json.NewEncoder(f)
	observed := map[string]bool{}
	count := 0
	partial := false
	max := cfg.WebMaxEndpoints
	if max <= 0 {
		max = 500
	}
	record := func(row any) {
		mu.Lock()
		defer mu.Unlock()
		if err := encoder.Encode(row); err != nil {
			partial = true
		}
	}
	router := browser.HijackRequests()
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	bound, _ := assessment.ParseApprovedOrigin("", req.Target)
	err = router.Add("*", "", func(h *rod.Hijack) {
		rawURL, method := h.Request.URL().String(), h.Request.Method()
		if err := browserRequestAllowed(req, cfg, method, rawURL); err != nil {
			h.Response.Fail(proto.NetworkErrorReasonBlockedByClient)
			return
		}
		mu.Lock()
		if count >= max {
			partial = true
			mu.Unlock()
			h.Response.Fail(proto.NetworkErrorReasonBlockedByClient)
			return
		}
		count++
		mu.Unlock()
		if err := cfg.Budget.Wait(ctx); err != nil {
			mu.Lock()
			partial = true
			mu.Unlock()
			h.Response.Fail(proto.NetworkErrorReasonBlockedByClient)
			return
		}
		origin, _ := assessment.ParseApprovedOrigin("", rawURL)
		sameOrigin := origin.Scheme == bound.Scheme && origin.Host == bound.Host && origin.Port == bound.Port
		if sameOrigin {
			for _, header := range strings.Split(req.TargetAuth, "\n") {
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
			mu.Lock()
			partial = true
			mu.Unlock()
			return
		}
		defer response.Body.Close()
		body, readErr := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
		if readErr != nil || len(body) > 2<<20 {
			mu.Lock()
			partial = true
			mu.Unlock()
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
		row := map[string]any{"timestamp": time.Now().UTC().Format(time.RFC3339Nano), "request": map[string]any{"endpoint": rawURL, "method": method, "source": "browser", "headers": map[string]string{"content-type": h.Request.Header("Content-Type")}}, "response": map[string]any{"status_code": response.StatusCode, "headers": map[string]string{"content-type": response.Header.Get("Content-Type")}}}
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
	defer router.Stop()
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
					if next.depth < katanaDefaultDepth {
						for _, link := range extracted.Links {
							if len(queue)+len(visited) < max {
								queue = append(queue, entry{link, next.depth + 1})
							} else {
								mu.Lock()
								partial = true
								mu.Unlock()
							}
						}
					}
				}
			}
		} else {
			mu.Lock()
			partial = true
			mu.Unlock()
		}
		if page != nil {
			_ = page.Close()
		}
		pageCancel()
	}
	mu.Lock()
	defer mu.Unlock()
	run.Status = "completed"
	run.Authenticated = req.TargetAuth != ""
	run.Completeness = "complete"
	if ctx.Err() != nil || partial {
		run.Outcome, run.Completeness, run.Reason = "PARTIAL", "partial", "browser discovery reached a request, response-size, navigation, depth or time limit"
	}
	if count == 0 {
		run.Status, run.Reason = "failed", "browser produced no approved HTTP observations"
	}
	return
}
