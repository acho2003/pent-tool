package scanner

import (
	"context"
	"errors"
	"net/http"
	"net/url"
)

// guardedOriginClient resolves the host of rawURL, lets the execution scope
// guard judge the URL and every address it resolved to, and returns a client
// pinned to those addresses that uses no proxy and follows no redirects. Native
// HTTP adapters use it so DNS that changed after plan preview cannot point them
// at the scanner host or the dashboard listener.
func guardedOriginClient(ctx context.Context, cfg Config, rawURL string) (*http.Client, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return nil, errors.New("invalid request URL")
	}
	addresses, err := resolveAPICheckAddresses(ctx, parsed.Hostname())
	if err != nil {
		return nil, err
	}
	if cfg.ScopeGuard != nil {
		resolved := make([]string, 0, len(addresses))
		for _, address := range addresses {
			resolved = append(resolved, address.String())
		}
		if blocked, reason := cfg.ScopeGuard(rawURL, resolved); blocked {
			return nil, errors.New("execution scope guard refused request: " + reason)
		}
	}
	return apiCheckClientFor(parsed, addresses), nil
}
