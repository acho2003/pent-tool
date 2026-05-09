package terminal

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

func TestIsBlockedCommand_DangerousAndObfuscatedInputs(t *testing.T) {
	dangerous := "rm -rf /"
	cases := []struct {
		name string
		cmd  string
		want string
	}{
		{"raw destructive", dangerous, "recursive delete"},
		{"base64 destructive", base64.StdEncoding.EncodeToString([]byte(dangerous)), "base64"},
		{"hex destructive", "726d202d7266202f", "hex"},
		{"url destructive", "rm%20-rf%20%2F", "URL"},
		{"blocked noisy scanner", "nikto -h https://example.test", "false positives"},
		{"hex escape obfuscation", `echo \x72\x6d`, "obfuscated"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isBlockedCommand(tc.cmd)
			if got == "" {
				t.Fatalf("command %q was not blocked", tc.cmd)
			}
			if !strings.Contains(strings.ToLower(got), strings.ToLower(tc.want)) {
				t.Fatalf("block reason = %q, want it to contain %q", got, tc.want)
			}
		})
	}
}

func TestIsBlockedCommand_AllowsBenignReconCommands(t *testing.T) {
	for _, cmd := range []string{
		"curl -I https://example.test",
		"nmap -sV -p 443 example.test",
		"python3 -c 'print(123)'",
	} {
		if got := isBlockedCommand(cmd); got != "" {
			t.Fatalf("benign command %q was blocked: %s", cmd, got)
		}
	}
}

func TestCommandHelpers_ClassifyHeavyToolsAndPackages(t *testing.T) {
	if !isHeavyTool("nuclei -u https://example.test") {
		t.Fatal("nuclei should be classified as heavy")
	}
	if !isHeavyTool("httpx -l hosts.txt -silent") {
		t.Fatal("httpx should be classified as heavy")
	}
	if !isHeavyTool("naabu -host example.test") {
		t.Fatal("naabu should be classified as heavy")
	}
	if isHeavyTool("curl -I https://example.test") {
		t.Fatal("curl should not be classified as heavy")
	}
	if computeTimeout("nmap -sV example.test") != heavyCmdTimeout {
		t.Fatal("nmap should get heavy command timeout")
	}
	if computeTimeout("curl -I https://example.test") != defaultCmdTimeout {
		t.Fatal("curl should get default command timeout")
	}
	if heavyCmdTimeout <= defaultCmdTimeout || hardMaxTimeout < 2*time.Hour {
		t.Fatal("timeout tiers are not ordered as expected")
	}

	if got := resolvePackage("dig"); got != "dnsutils" {
		t.Fatalf("resolvePackage(dig) = %q", got)
	}
	if got := resolvePackage("definitely-not-known"); got != "" {
		t.Fatalf("unknown command resolved to package %q", got)
	}
}

func TestExtractCommandAndMissingCommandParsing(t *testing.T) {
	cmds := extractCommands("curl -s https://example.test | jq . && nuclei -u https://example.test")
	joined := strings.Join(cmds, ",")
	for _, want := range []string{"curl", "jq", "nuclei"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("extractCommands missing %q from %v", want, cmds)
		}
	}

	output := "STDERR:\nbash: line 1: fancytool: command not found\n[exit code: 127]"
	if got := extractMissingCommand(output); got != "fancytool" {
		t.Fatalf("extractMissingCommand = %q", got)
	}
	if !isCommandNotFound(output) {
		t.Fatal("command-not-found output was not detected")
	}
}

func TestProcessTrackingIsContextSpecific(t *testing.T) {
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("sleep is not available")
	}

	scA := scanctx.New("term-a", t.TempDir())
	scB := scanctx.New("term-b", t.TempDir())
	scanctx.Activate(scA)
	scanctx.Activate(scB)
	t.Cleanup(func() {
		CleanupContext(scA.ID)
		CleanupContext(scB.ID)
		scanctx.Deactivate(scA.ID)
		scanctx.Deactivate(scB.ID)
	})

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start sleep: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})

	TrackProcessForContext(scA.ID, cmd, cancel, "sleep 30")
	if got := ActiveProcessCountForContext(scA.ID); got != 1 {
		t.Fatalf("context A process count = %d, want 1", got)
	}
	if got := ActiveProcessCountForContext(scB.ID); got != 0 {
		t.Fatalf("context B process count = %d, want 0", got)
	}

	KillAllProcessesForContext(scB.ID)
	if got := ActiveProcessCountForContext(scA.ID); got != 1 {
		t.Fatalf("killing context B affected context A, count=%d", got)
	}

	KillAllProcessesForContext(scA.ID)
	if got := ActiveProcessCountForContext(scA.ID); got != 0 {
		t.Fatalf("context A process count after kill = %d, want 0", got)
	}
}

func TestWorkDirPrefersScanContext(t *testing.T) {
	sc := scanctx.New("term-workdir", t.TempDir())
	scanctx.Activate(sc)
	defer func() {
		CleanupContext(sc.ID)
		scanctx.Deactivate(sc.ID)
	}()

	sc.Terminal.SetWorkDir("/tmp/from-scanctx")
	store := getTermStoreByID(sc.ID)
	store.mu.Lock()
	store.workDir = "/tmp/from-terminal-store"
	store.mu.Unlock()

	if got := GetWorkDirForContext(sc.ID); got != "/tmp/from-scanctx" {
		t.Fatalf("GetWorkDirForContext = %q", got)
	}
}

func TestRunShellScopesHomeAndBlocksCdOutsideWorkspace(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not available")
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	sc := scanctx.New("term-scope", t.TempDir())
	sc.Terminal.SetWorkDir(sc.ScanDir)
	scanctx.Activate(sc)
	defer func() {
		CleanupContext(sc.ID)
		scanctx.Deactivate(sc.ID)
	}()

	out, code := runShellInternal(sc.ID, `printf 'home=%s\npwd=%s\n' "$HOME" "$PWD"; cd /root; printf 'after=%s\n' "$PWD"`)
	if code != 0 {
		t.Fatalf("runShellInternal exit=%d output=%q", code, out)
	}
	if !strings.Contains(out, "home="+sc.ScanDir) {
		t.Fatalf("HOME was not scoped to scan dir: %q", out)
	}
	if !strings.Contains(out, "pwd="+sc.ScanDir) || !strings.Contains(out, "after="+sc.ScanDir) {
		t.Fatalf("command escaped scan dir: %q", out)
	}
	if !strings.Contains(out, "[WORKSPACE GUARD] cd outside scan workspace blocked") {
		t.Fatalf("workspace guard did not report blocked cd: %q", out)
	}
	if _, err := os.Stat(filepath.Join(sc.ScanDir, ".tmp")); err != nil {
		t.Fatalf("workspace temp dir missing: %v", err)
	}
}
