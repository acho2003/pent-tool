//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRestrictFileCreationModeMakesNewFilesPrivate(t *testing.T) {
	previous := syscall.Umask(0)
	defer syscall.Umask(previous)
	restrictFileCreationMode()
	dir := t.TempDir()
	file := filepath.Join(dir, "raw-output.json")
	if err := os.WriteFile(file, []byte("{}"), 0o666); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o777); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{file: 0o600, sub: 0o700} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("%s mode = %v (%v), want %v", path, info.Mode().Perm(), err, want)
		}
	}
}
