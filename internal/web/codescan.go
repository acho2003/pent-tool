package web

import (
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
)

// isBlockedTargetForScan is isBlockedTarget with a per-scan loopback allowlist.
// When allowLoopbackPorts is empty it is byte-identical to isBlockedTarget;
// with a port set, a loopback target on that exact port is permitted. The
// dashboard's own listener port is never allowed.
func (s *Server) isBlockedTargetForScan(target string, allowLoopbackPorts []int) bool {
	return scopeguard.IsLocalOrListener(scopeguard.Config{
		BindAddr:           s.cfg.BindAddr,
		Port:               s.port,
		AllowLoopbackPorts: allowLoopbackPorts,
		AllowLocalTargets:  s.cfg.AllowLocalTargets,
	}, target)
}
