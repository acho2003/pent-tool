//go:build windows

package main

import (
	"os"
	"os/exec"
)

// execSyscall on Windows: spawn a child and exit. There is no exec(2)
// equivalent on Windows, so the parent has to terminate after starting
// the child.
func execSyscall(path string, argv, env []string) error {
	cmd := exec.Command(path, argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env
	if err := cmd.Start(); err != nil {
		return err
	}
	os.Exit(0)
	return nil
}
