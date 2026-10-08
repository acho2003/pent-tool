//go:build unix

package scanner

import (
	"errors"
	"os"
	"os/exec"
	"sync/atomic"
	"syscall"
	"time"
)

// cancelGracePeriodNS holds the grace period (see cancelGracePeriod) as
// nanoseconds in an atomic int64, so a test can shorten it without racing a
// grace-period goroutine from an earlier cancellation that may still be
// sleeping (see configureCommandCancellation) when the test that started it
// has already returned and restored the default.
var cancelGracePeriodNS atomic.Int64

func init() { cancelGracePeriodNS.Store(int64(5 * time.Second)) }

// cancelGracePeriod is how long a stopped scanner may keep running after
// SIGINT — the same signal a terminal's Ctrl-C sends — before it is
// force-killed. Wapiti, Nuclei and nmap all treat SIGINT as "stop and save
// what you have" and flush partial results to their output file; SIGKILL
// gives a tool no chance to do that at all, so a hard-killed run's artifact
// can be missing or truncated, and the pipeline's own fail-closed
// sanitization then discards it rather than let a possibly-unsafe file
// through (see redactArtifact/invalidateUnsafeArtifact in pipeline.go).
func cancelGracePeriod() time.Duration { return time.Duration(cancelGracePeriodNS.Load()) }

// Tools may spawn helpers that inherit output pipes. A per-tool stop must stop
// that isolated process group, rather than leaving helpers scanning afterwards.
func configureCommandCancellation(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		pgid := cmd.Process.Pid
		err := syscall.Kill(-pgid, syscall.SIGINT)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		if err != nil {
			// The group could not be asked to stop at all (not merely "already
			// gone"), so there is nothing to wait for; go straight to a hard kill.
			return killGroup(pgid)
		}
		go func() {
			time.Sleep(cancelGracePeriod())
			_ = killGroup(pgid)
		}()
		return nil
	}
	// WaitDelay is Go's own backstop: if the process (and its I/O) has not
	// finished this long after Cancel was called, Wait force-kills it and
	// returns. Give the grace period above room to work first.
	cmd.WaitDelay = cancelGracePeriod() + 2*time.Second
}

// killGroup sends SIGKILL to the process group led by pgid. A group that is
// already gone (ESRCH) is the success case, not an error worth surfacing: the
// process had already exited, on its own or from the earlier SIGINT.
func killGroup(pgid int) error {
	err := syscall.Kill(-pgid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}
