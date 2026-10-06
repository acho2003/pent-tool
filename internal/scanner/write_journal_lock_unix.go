//go:build unix

package scanner

import (
	"golang.org/x/sys/unix"
	"os"
)

func lockWriteJournal(path string) (func(), error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		file.Close()
		return nil, err
	}
	return func() { unix.Flock(fd, unix.LOCK_UN); file.Close() }, nil
}
