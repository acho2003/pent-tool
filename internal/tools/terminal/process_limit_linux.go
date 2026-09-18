//go:build linux

package terminal

import (
	"syscall"
	"unsafe"
)

func setChildMemoryLimit(pid int, bytes int64) error {
	limit := syscall.Rlimit{Cur: uint64(bytes), Max: uint64(bytes)}
	_, _, errno := syscall.RawSyscall6(syscall.SYS_PRLIMIT64, uintptr(pid), uintptr(syscall.RLIMIT_AS), uintptr(unsafe.Pointer(&limit)), 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
