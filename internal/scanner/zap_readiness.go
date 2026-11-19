package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// zapReadyTimeout bounds how long a ZAP job waits for the shared daemon to
// become responsive before starting. It is sized to cover a daemon that is
// slow-recovering or has just been restarted (ZAP cold-starts in ~30-45s), so
// an operator (or a Docker restart policy) recovering a degraded daemon mid-run
// is absorbed instead of failing every remaining service. Override with
// XALGORIX_ZAP_READY_TIMEOUT_SEC (0 disables the wait).
func zapReadyTimeout() time.Duration {
	if v := strings.TrimSpace(os.Getenv("XALGORIX_ZAP_READY_TIMEOUT_SEC")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return time.Duration(n) * time.Second
		}
	}
	return 90 * time.Second
}

// zapVersionProbe is one lightweight liveness check against the ZAP daemon.
func zapVersionProbe(ctx context.Context, client *http.Client, cfg Config) error {
	q := url.Values{"apikey": {cfg.ZAPAPIKey}}
	endpoint := strings.TrimRight(cfg.ZAPURL, "/") + "/JSON/core/view/version/?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	// Readiness means the daemon answers at all. A 4xx (e.g. a rejected request
	// or bad API key) still proves it is up and responsive — the caller's real
	// API call validates the response. Only a 5xx (overloaded/unavailable)
	// counts as not-yet-ready, alongside connection errors and timeouts.
	if resp.StatusCode >= 500 {
		return fmt.Errorf("ZAP version endpoint returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// zapAwaitReady probes the ZAP daemon's version endpoint with exponential
// backoff until it answers, or until window elapses. It lets a ZAP job start
// against a daemon that is momentarily slow or restarting instead of failing
// instantly, and when the daemon is genuinely gone it returns a clear,
// actionable error after a bounded wait rather than leaving the heavier scan
// operations to each burn their full budget. window <= 0 skips the wait.
func zapAwaitReady(ctx context.Context, cfg Config, window time.Duration, log func(string)) error {
	if window <= 0 {
		return nil
	}
	client := &http.Client{}
	deadline := time.Now().Add(window)
	backoff := time.Second
	for attempt := 1; ; attempt++ {
		probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := zapVersionProbe(probeCtx, client, cfg)
		cancel()
		if err == nil {
			if attempt > 1 && log != nil {
				log(fmt.Sprintf("ZAP daemon became responsive after %d attempt(s)", attempt))
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("ZAP daemon did not become responsive within %s; restart the ZAP service and retry", window)
		}
		if attempt == 1 && log != nil {
			log("ZAP daemon is not responding yet; waiting for it to recover before starting the scan")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if remaining := time.Until(deadline); remaining < backoff {
			backoff = remaining
		}
		if backoff < 8*time.Second {
			backoff *= 2
		}
	}
}
