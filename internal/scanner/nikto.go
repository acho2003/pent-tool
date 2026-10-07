package scanner

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const niktoMaxDuration = 10 * time.Minute

type niktoRunner struct{}

func (niktoRunner) Name() string { return "nikto" }
func (niktoRunner) Descriptor() Descriptor {
	return Descriptor{Name: "nikto", Summary: "Optional bounded root-path web server checks", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightLight, Applies: appliesToHost}
}
func (r niktoRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	return executePolicySpec(ctx, r.Name(), req, cfg, buildNikto(req, cfg), emit)
}

func buildNikto(req Request, cfg Config) commandSpec {
	if restricted, reason := requestPolicyRestriction("nikto", req); restricted {
		return commandSpec{notApp: reason, timeout: cfg.NiktoTimeout}
	}
	if strings.TrimSpace(cfg.NiktoPath) == "" {
		return commandSpec{notApp: "Nikto executable is not configured", timeout: cfg.NiktoTimeout}
	}
	target := strings.TrimSpace(req.Target)
	// A network target (IP, CIDR host, or hostname/domain) carries no scheme;
	// probe its default HTTP root. URL targets keep their exact scheme and host.
	if host, ok := nmapTargetSpec(target); ok && !strings.Contains(target, "://") {
		target = "http://" + host + "/"
	}
	u, err := url.Parse(target)
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return commandSpec{notApp: "Nikto requires an HTTP(S) URL or a bare IP, host, or domain without credentials, query, or fragment", timeout: cfg.NiktoTimeout}
	}
	if u.EscapedPath() != "" && u.EscapedPath() != "/" {
		return commandSpec{notApp: "this Nikto adapter is limited to application root URLs because Nikto cannot enforce a nested path boundary", timeout: cfg.NiktoTimeout}
	}
	if req.AppScope != nil {
		root := u.String()
		if allowed, why := req.AppScope.Allows(root); !allowed {
			return commandSpec{notApp: "the Nikto target is outside the approved scope: " + why, timeout: cfg.NiktoTimeout}
		}
		if excluded, why := req.AppScope.Excluded("GET", root); excluded {
			return commandSpec{notApp: "the Nikto target is an excluded route: " + why, timeout: cfg.NiktoTimeout}
		}
	}
	if cfg.ScopeGuard != nil {
		if blocked, reason := cfg.ScopeGuard(u.String(), nil); blocked {
			return commandSpec{notApp: reason, timeout: cfg.NiktoTimeout}
		}
	}
	duration := cfg.NiktoTimeout
	base := filepath.Join(req.ScanDir, "scanner-output", "nikto")
	artifact := filepath.Join(base, "results.json")
	isolatedConfig := filepath.Join(base, "nikto.conf")
	args := []string{"-config", isolatedConfig, "-host", u.String(), "-nointeractive", "-nocheck"}
	if req.Profile == ProfileThorough {
		duration = 0
	} else {
		if duration <= 0 || duration > niktoMaxDuration {
			duration = niktoMaxDuration
		}
		seconds := int(duration / time.Second)
		if seconds < 1 {
			seconds = 1
		}
		// Give Nikto time to flush JSON before the outer process deadline.
		grace := seconds / 10
		if grace > 60 {
			grace = 60
		}
		if grace < 1 && seconds > 1 {
			grace = 1
		}
		niktoSeconds := seconds - grace
		if niktoSeconds < 1 {
			niktoSeconds = 1
		}
		args = append(args, "-maxtime", strconv.Itoa(niktoSeconds)+"s")
		args = append(args, "-timeout", "5")
		args = append(args, "-Pause", "1")
	}
	args = append(args, "-Cgidirs", "none", "-Tuning", "123b", "-Format", "json", "-output", filepath.Join(base, "results"))
	return commandSpec{
		path:     cfg.NiktoPath,
		args:     args,
		artifact: artifact, timeout: duration,
		partialMarker: "Host maximum execution time of",
		prepare: func() error {
			if err := os.MkdirAll(base, 0o700); err != nil {
				return fmt.Errorf("create Nikto output directory: %w", err)
			}
			// Keep outbound RFI tests disabled: they need an external RFIURL.
			settings := "# Xalgorix bounded assessment settings\nCHECKMETHODS=GET\n@@DEFAULT=@@ALL;-@@EXTRAS;tests(report:500)\nDEFAULTHTTPVER=1.1\nUPDATES=no\n"
			if err := os.WriteFile(isolatedConfig, []byte(settings), 0o600); err != nil {
				return fmt.Errorf("write isolated Nikto configuration: %w", err)
			}
			return nil
		},
	}
}
