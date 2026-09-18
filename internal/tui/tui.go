// Package tui provides deterministic terminal output for scanner runs.
package tui

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
	"github.com/xalgord/xalgorix/v4/internal/web"
)

const Banner = `
 ██╗  ██╗ █████╗ ██╗      ██████╗  ██████╗ ██████╗ ██╗██╗  ██╗
 ╚██╗██╔╝██╔══██╗██║     ██╔════╝ ██╔═══██╗██╔══██╗██║╚██╗██╔╝
  ╚███╔╝ ███████║██║     ██║  ███╗██║   ██║██████╔╝██║ ╚███╔╝
  ██╔██╗ ██╔══██║██║     ██║   ██║██║   ██║██╔══██╗██║ ██╔██╗
 ██╔╝ ██╗██║███████╗╚██████╔╝╚██████╔╝██║  ██║██║██╔╝ ██╗
 ╚═╝  ╚═╝╚═╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝`

func SplashText(version string) string {
	return fmt.Sprintf("%s\n\n  Deterministic Scanner Pipeline  v%s\n  Nuclei → ZAP → OpenVAS → Trivy → Vuls\n  Report AI runs only after scanning.\n\n", Banner, version)
}

// RunCLI runs the shared scanner pipeline and report generator. Scanner output
// is the only live content printed between the banner and terminal statuses.
func RunCLI(cfg *config.Config, targets []string, artifactKind string, vulsSSHHost string, scanners []string) {
	fmt.Print(SplashText("0.1.0"))
	artifact := scanner.Artifact{}
	if strings.TrimSpace(cfg.SourceRepo) != "" {
		artifact.Ref = strings.TrimSpace(cfg.SourceRepo)
		artifact.Kind = strings.ToLower(strings.TrimSpace(artifactKind))
		if artifact.Kind == "" {
			artifact.Kind = "repository"
			if !strings.Contains(artifact.Ref, "://") {
				artifact.Kind = "filesystem"
			}
		}
		if len(targets) == 0 {
			targets = []string{"artifact://" + artifact.Kind}
		}
	}
	fmt.Printf("  Targets: %s\n", strings.Join(targets, ", "))
	if len(scanners) > 0 {
		fmt.Printf("  Scanners: %s (deselected scanners are recorded as skipped)\n", strings.Join(scanners, ", "))
	}
	fmt.Println()

	pipeline := scanner.NewPipeline(scanner.Config{
		NucleiPath: cfg.NucleiPath, TrivyPath: cfg.TrivyPath, VulsPath: cfg.VulsPath, VulsSSHConfigPath: cfg.VulsSSHConfigPath,
		ZAPURL: cfg.ZAPURL, ZAPAPIKey: cfg.ZAPAPIKey, GVMHost: cfg.GVMHost, GVMPort: cfg.GVMPort, GVMSocket: cfg.GVMSocket,
		GVMUser: cfg.GVMUsername, GVMPass: cfg.GVMPassword, RateRPS: int(cfg.RateLimitRPS),
		ScanHeaders: append([]string(nil), cfg.ScanHeaders...), MaxOutputBytes: cfg.ScannerMaxOutputBytes,
		NucleiTimeout: time.Duration(cfg.NucleiTimeoutSec) * time.Second, ZAPTimeout: time.Duration(cfg.ZAPTimeoutSec) * time.Second,
		OpenVASTimeout: time.Duration(cfg.OpenVASTimeoutSec) * time.Second, TrivyTimeout: time.Duration(cfg.TrivyTimeoutSec) * time.Second,
		VulsTimeout: time.Duration(cfg.VulsTimeoutSec) * time.Second,
	})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for _, target := range targets {
		dir := filepath.Join(cfg.DataDir, "cli", time.Now().Format("20060102-150405.000000000"), cliTargetLabel(target))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			fmt.Printf("  failed: %v\n", err)
			continue
		}
		runs := pipeline.Run(ctx, scanner.Request{Target: target, Scanners: scanners, ScanDir: dir, Artifact: artifact, VulsSSHHost: vulsSSHHost}, nil, func(event scanner.Event) {
			if event.Type == "scanner_output" {
				fmt.Printf("[%s/%s] %s", event.Scanner, event.Stream, event.Output)
			}
		})
		for _, run := range runs {
			fmt.Printf("  %-9s %s", run.Scanner, run.Status)
			if run.Reason != "" {
				fmt.Printf(" — %s", run.Reason)
			}
			fmt.Println()
		}
		reportPath, err := web.GenerateCLIReport(cfg, target, dir, runs)
		if err != nil {
			fmt.Printf("  Report generation failed: %v\n", err)
		} else {
			fmt.Printf("  Report: %s\n", reportPath)
		}
		fmt.Printf("  Artifacts: %s\n", dir)
		if ctx.Err() != nil {
			break
		}
	}
}

func cliTargetLabel(ref string) string {
	trimmed := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(ref), "/"), ".git")
	base := filepath.Base(trimmed)
	if base == "" || base == "." || base == "/" {
		return "artifact"
	}
	return base
}
