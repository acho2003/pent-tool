package scanner

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// The only upstream is the explicitly supplied owned loopback production app.
// This fixture models both a broken shared key and identity isolation, without
// contacting a CDN or altering any external cache.
func frameworkCacheProxy(t *testing.T, backend string, isolated bool) *httptest.Server {
	t.Helper()
	target, err := url.Parse(backend)
	if err != nil {
		t.Fatal(err)
	}
	type cached struct {
		header http.Header
		body   []byte
	}
	var mu sync.Mutex
	entries := map[string]cached{}
	key := func(r *http.Request) string {
		k := r.URL.RequestURI() + "\x00" + r.Header.Get("RSC")
		if isolated {
			k += "\x00" + r.Header.Get("Cookie")
		}
		return k
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ModifyResponse = func(response *http.Response) error {
		r := response.Request
		if r.URL.Query().Get("uncached") == "1" || !strings.HasSuffix(r.URL.Path, "/resource") || response.StatusCode != 200 {
			return nil
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
		response.Body.Close()
		if err != nil {
			return err
		}
		response.Body = io.NopCloser(bytes.NewReader(body))
		if len(body) > 64<<10 {
			return nil
		}
		mu.Lock()
		entries[key(r)] = cached{response.Header.Clone(), bytes.Clone(body)}
		mu.Unlock()
		return nil
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/reset-proxy-cache" && r.Method == "DELETE" {
			if r.Header.Get("Cookie") != "lab-role=owner" {
				http.Error(w, "denied", 403)
				return
			}
			mu.Lock()
			clear(entries)
			mu.Unlock()
			w.WriteHeader(204)
			return
		}
		// ReverseProxy prepends the upstream base path. Cache lookup uses the same
		// path as its response hook, so this also exercises nested deployments.
		lookup := r.Clone(r.Context())
		lookup.URL = new(url.URL)
		*lookup.URL = *r.URL
		lookup.URL.Path = strings.TrimSuffix(target.Path, "/") + r.URL.Path
		mu.Lock()
		entry, hit := entries[key(lookup)]
		mu.Unlock()
		if hit && r.URL.Query().Get("uncached") != "1" {
			for name, values := range entry.header {
				w.Header()[name] = append([]string(nil), values...)
			}
			w.Header().Set("X-Cache", "HIT")
			w.Write(entry.body)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	return server
}

func frameworkProxyCacheAcceptance(t *testing.T, backend string) []frameworkLabRow {
	t.Helper()
	var rows []frameworkLabRow
	for _, representation := range []string{"html", "rsc"} {
		for _, isolated := range []bool{false, true} {
			proxy := frameworkCacheProxy(t, backend, isolated)
			resource := proxy.URL + "/resource"
			if representation == "rsc" {
				canonical, _ := url.Parse(frameworkRSCResource(t, backend))
				resource += "?" + canonical.RawQuery
			}
			fixture := cacheBoundaryManifest(proxy.URL)
			fixture.URL = resource
			parsed, _ := url.Parse(resource)
			query := parsed.Query()
			query.Set("uncached", "1")
			parsed.RawQuery = query.Encode()
			fixture.BypassURL = parsed.String()
			fixture.CleanupURL = proxy.URL + "/reset-proxy-cache"
			fixture.Representation = representation
			fixture.ConsumerRepresentation = representation
			req, cfg := boundaryFixture(t, proxy.URL, fixture, "")
			frameworkIdentities(&req, proxy.URL)
			run := (nextjsBoundariesRunner{}).Run(t.Context(), req, cfg, nil)
			findings, err := ParseRun(run)
			expected := 1
			mode := "shared-key"
			if isolated {
				expected = 0
				mode = "isolated-key"
			}
			passed := err == nil && len(findings) == expected && run.Status == "completed" && len(run.AuthorizationResults) == 1 && run.AuthorizationResults[0].CleanupStatus == "verified"
			if !isolated && passed {
				passed = run.AuthorizationResults[0].CacheAttribution == "confirmed"
			}
			rows = append(rows, frameworkLabRow{Variant: "patched", Check: "local-proxy-" + representation + "-" + mode, Findings: len(findings), Requests: frameworkRecordedRequests(run), Passed: passed, Outcome: run.Outcome})
			if !passed {
				t.Errorf("local proxy %s %s failed: findings=%v err=%v run=%+v", representation, mode, findings, err, run)
			}
			proxy.Close()
		}
	}
	return rows
}
