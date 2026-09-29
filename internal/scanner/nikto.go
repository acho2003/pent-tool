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
	return executeSpec(ctx, r.Name(), req, cfg, buildNikto(req, cfg), emit)
}

func buildNikto(req Request, cfg Config) commandSpec {
	if strings.TrimSpace(cfg.NiktoPath) == "" {
		return commandSpec{notApp: "Nikto executable is not configured", timeout: cfg.NiktoTimeout}
	}
	target := strings.TrimSpace(req.Target)
	u, err := url.Parse(target)
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return commandSpec{notApp: "Nikto requires one explicit HTTP(S) URL without credentials, query, or fragment", timeout: cfg.NiktoTimeout}
	}
	if u.EscapedPath() != "" && u.EscapedPath() != "/" {
		return commandSpec{notApp: "this Nikto adapter is limited to application root URLs because Nikto cannot enforce a nested path boundary", timeout: cfg.NiktoTimeout}
	}
	duration := cfg.NiktoTimeout
	if duration <= 0 || duration > niktoMaxDuration {
		duration = niktoMaxDuration
	}
	seconds := int(duration / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	// Let Nikto reach its own per-host limit and flush JSON before the process
	// deadline. Its one-second request pause can otherwise consume the entire
	// outer budget and leave an empty report.
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
	base := filepath.Join(req.ScanDir, "scanner-output", "nikto")
	artifact := filepath.Join(base, "results.json")
	isolatedConfig := filepath.Join(base, "nikto.conf")
	return commandSpec{
		path:     cfg.NiktoPath,
		args:     []string{"-config", isolatedConfig, "-host", u.String(), "-nointeractive", "-nocheck", "-maxtime", strconv.Itoa(niktoSeconds) + "s", "-timeout", "5", "-Pause", "1", "-Cgidirs", "none", "-Tuning", "123b", "-Format", "json", "-output", filepath.Join(base, "results")},
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
