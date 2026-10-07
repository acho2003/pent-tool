//go:build !windows

package main

import "syscall"

// restrictFileCreationMode makes every file and directory the process creates
// private to its owner by default. Scanner children inherit the mask, so native
// tool output written before sanitization is never group- or world-readable.
func restrictFileCreationMode() { syscall.Umask(0o077) }
