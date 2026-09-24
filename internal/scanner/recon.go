package scanner

import (
	"net"
	"net/url"
	"strings"
)

func reconScopeKey(target string) string { return "recon:" + target }

// hostFromTarget extracts the bare host from a URL, host:port, or host.
func hostFromTarget(target string) string {
	t := strings.TrimSpace(target)
	if strings.Contains(t, "://") {
		if u, err := url.Parse(t); err == nil && u.Host != "" {
			t = u.Host
		}
	}
	if h, _, err := net.SplitHostPort(t); err == nil {
		return h
	}
	return t
}

// isBareHostInput reports whether the target is an IP, host:port, or URL —
// i.e. not an apex/subdomain name that subfinder should enumerate.
func isBareHostInput(target string) bool {
	t := strings.TrimSpace(target)
	if strings.Contains(t, "://") {
		return true
	}
	host := hostFromTarget(t)
	if net.ParseIP(host) != nil {
		return true
	}
	// host:port form (a port after the host) is a bare host input.
	if _, _, err := net.SplitHostPort(t); err == nil {
		return true
	}
	return false
}

func candidateHosts(target string) []string {
	h := hostFromTarget(target)
	if h == "" {
		return nil
	}
	return []string{h}
}
