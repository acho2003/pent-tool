//go:build unix

package scanner

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// Tools may spawn helpers that inherit output pipes. A per-tool stop must stop
// that isolated process group, rather than leaving helpers scanning afterwards.
func configureCommandCancellation(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = time.Second
}
