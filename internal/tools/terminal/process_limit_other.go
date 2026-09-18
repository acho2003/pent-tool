//go:build !linux

package terminal

func setChildMemoryLimit(_ int, _ int64) error { return nil }
