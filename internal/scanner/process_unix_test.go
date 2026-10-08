//go:build unix

package scanner

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// withShortCancelGrace shortens cancelGracePeriod for a test and restores it
// afterward. cancelGracePeriodNS is atomic, so this is race-free even though a
// grace-period goroutine from this test's own cancellation (see
// configureCommandCancellation) may still be sleeping — harmlessly, since it
// only ever tries to kill a process group that has already exited — after
// this test function returns and the next test's override takes effect.
func withShortCancelGrace(t *testing.T, grace time.Duration) {
	t.Helper()
	previous := cancelGracePeriodNS.Swap(int64(grace))
	t.Cleanup(func() { cancelGracePeriodNS.Store(previous) })
}

// TestProcessCancellationHelper is not a real test: it is re-executed as a
// subprocess by the tests below (the same re-exec-self pattern as
// TestWriteJournalProcessHelper), standing in for a native scanner so
// cancellation can be exercised against deterministic, well-defined Go signal
// handling rather than POSIX shell trap/wait semantics, which this package
// found to behave inconsistently across shells for a signal delivered while a
// script is blocked in `wait`.
func TestProcessCancellationHelper(t *testing.T) {
	mode := os.Getenv("XALGORIX_TEST_CANCEL_HELPER")
	if mode == "" {
		t.Skip("subprocess helper")
	}
	switch mode {
	case "cooperative":
		// Stands in for a tool (Wapiti, Nuclei, nmap) that treats SIGINT as
		// "stop and save what you have": it writes its results, then exits
		// cleanly, before anything forces it to stop.
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT)
		<-sigs
		if marker := os.Getenv("XALGORIX_TEST_CANCEL_MARKER"); marker != "" {
			if err := os.WriteFile(marker, []byte("flushed"), 0o600); err != nil {
				os.Exit(1)
			}
		}
		os.Exit(0)
	case "stubborn":
		// Stands in for a tool with no SIGINT handling at all.
		signal.Ignore(syscall.SIGINT)
		for {
			time.Sleep(50 * time.Millisecond)
		}
	}
}

// cancellationHelper starts the subprocess helper above in the given mode and
// applies the real configureCommandCancellation to it, exactly as executeSpec
// does for a native scanner.
func cancellationHelper(t *testing.T, ctx context.Context, mode, marker string) *exec.Cmd {
	t.Helper()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestProcessCancellationHelper$")
	cmd.Env = append(os.Environ(), "XALGORIX_TEST_CANCEL_HELPER="+mode, "XALGORIX_TEST_CANCEL_MARKER="+marker)
	configureCommandCancellation(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return cmd
}

// A tool that handles SIGINT by flushing its results and exiting promptly must
// be allowed to do so: cancellation must not kill it outright (which is what
// a bare SIGKILL did before, giving Dalfox/Wapiti-style tools that buffer a
// single JSON output file no chance to write anything on a mid-run stop).
func TestCancelSendsSIGINTAndLetsACooperativeProcessFlush(t *testing.T) {
	withShortCancelGrace(t, 2*time.Second)
	marker := filepath.Join(t.TempDir(), "flushed")
	ctx, cancel := context.WithCancel(context.Background())
	cmd := cancellationHelper(t, ctx, "cooperative", marker)
	time.Sleep(200 * time.Millisecond) // let the helper install its signal handler
	cancel()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not let the cooperative process exit in time")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("the process was not given the chance to flush before being stopped:", err)
	}
}

// A process that ignores SIGINT entirely must still be force-killed once the
// grace period elapses, so cancellation never hangs forever.
func TestCancelForceKillsAProcessThatIgnoresSIGINT(t *testing.T) {
	withShortCancelGrace(t, 300*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	cmd := cancellationHelper(t, ctx, "stubborn", "")
	time.Sleep(200 * time.Millisecond)
	cancel()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a SIGINT-ignoring process was never force-killed")
	}
}
