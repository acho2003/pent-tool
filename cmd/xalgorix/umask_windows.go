//go:build windows

package main

// restrictFileCreationMode has no equivalent on Windows; file access there is
// governed by directory ACLs.
func restrictFileCreationMode() {}
