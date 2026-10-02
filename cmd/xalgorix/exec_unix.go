//go:build !windows

package main

import "syscall"

// execSyscall replaces the current process image with the binary at path.
// It only returns on failure — on success the caller is replaced.
func execSyscall(path string, argv, env []string) error {
	return syscall.Exec(path, argv, env)
}
