//go:build !unix

package scanner

import (
	"os/exec"
	"time"
)

func configureCommandCancellation(cmd *exec.Cmd) {
	cmd.WaitDelay = time.Second
}
