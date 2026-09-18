//go:build !windows

package main

// The agent manages IIS, NTFS ACLs, Windows services and the Windows event log.
// None of that exists elsewhere, so the binary refuses to pretend on another
// operating system rather than starting and failing one call at a time.
//
// It still COMPILES everywhere, because everything with no build tag in this
// package is measured on every build.

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "servika-agent runs on Windows only.")
	os.Exit(1)
}
