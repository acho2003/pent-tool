package main

import (
	"debug/buildinfo"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go-buildinfo BINARY")
		os.Exit(2)
	}
	info, err := buildinfo.ReadFile(os.Args[1])
	if err != nil || info.Main.Version == "" {
		fmt.Fprintln(os.Stderr, "Go build version unavailable")
		os.Exit(1)
	}
	fmt.Printf("%s %s\n", info.Main.Path, info.Main.Version)
}
