package scopeguard

import (
	"net"
	"testing"
)

// firstLocalInterfaceIP returns a non-loopback IPv4 address bound to one of
// this machine's interfaces, or "" if none is available.
func firstLocalInterfaceIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if v4 := ipnet.IP.To4(); v4 != nil {
				return v4.String()
			}
		}
	}
	return ""
}

// TestAllowLocalTargets covers the self-hosted opt-in (issue #228): when
// AllowLocalTargets is set, loopback/localhost targets become in-scope so a
// locally-hosted demo app can be scanned — EXCEPT the dashboard's own listener,
// which stays blocked on any local address, and the unspecified address, which
// is always blocked.
func TestAllowLocalTargets(t *testing.T) {
	const dashboardPort = 9137
	on := Config{BindAddr: "127.0.0.1", Port: dashboardPort, AllowLocalTargets: true}
	off := Config{BindAddr: "127.0.0.1", Port: dashboardPort}

	cases := []struct {
		name        string
		target      string
		wantWhenOn  bool // blocked?
		wantWhenOff bool // blocked?
	}{
		{"loopback app port", "http://127.0.0.1:3000/", false, true},
		{"localhost app port", "http://localhost:3000/login", false, true},
		{"ipv6 loopback app port", "http://[::1]:8080/", false, true},
		{"loopback no port", "http://127.0.0.1/", false, true},
		// The dashboard's own listener is never scannable, even with the opt-in.
		{"loopback dashboard port", "http://127.0.0.1:9137/", true, true},
		{"localhost dashboard port", "http://localhost:9137/", true, true},
		// Unspecified is always self, opt-in or not.
		{"unspecified", "http://0.0.0.0/", true, true},
		// A real external target is unaffected either way.
		{"external host", "http://example.com/", false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsLocalOrListener(on, tc.target); got != tc.wantWhenOn {
				t.Errorf("AllowLocalTargets=true: IsLocalOrListener(%q) = %v, want blocked=%v",
					tc.target, got, tc.wantWhenOn)
			}
			if got := IsLocalOrListener(off, tc.target); got != tc.wantWhenOff {
				t.Errorf("AllowLocalTargets=false (default): IsLocalOrListener(%q) = %v, want blocked=%v",
					tc.target, got, tc.wantWhenOff)
			}
		})
	}
}

// TestAllowLocalTargets_LocalInterfaceIP verifies that when the opt-in is on, a
// target resolving to one of this machine's own interface IPs is allowed
// (except on the dashboard port), while it stays blocked by default.
func TestAllowLocalTargets_LocalInterfaceIP(t *testing.T) {
	iface := firstLocalInterfaceIP()
	if iface == "" {
		t.Skip("no non-loopback local interface IP available")
	}
	withStubLookupHost(t, func(string) ([]string, error) { return []string{iface}, nil })

	on := Config{BindAddr: "127.0.0.1", Port: 9137, AllowLocalTargets: true}
	off := Config{BindAddr: "127.0.0.1", Port: 9137}

	if IsLocalOrListener(on, "http://demo.local:3000/") {
		t.Errorf("with opt-in, a local-interface target on a non-dashboard port should be allowed")
	}
	if !IsLocalOrListener(off, "http://demo.local:3000/") {
		t.Errorf("by default, a local-interface target must be blocked")
	}
	// Even with the opt-in, the dashboard port on a local interface is blocked.
	if !IsLocalOrListener(on, "http://demo.local:9137/") {
		t.Errorf("dashboard port must stay blocked on a local-interface address even with the opt-in")
	}
}
