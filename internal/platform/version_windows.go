//go:build windows

package platform

// THE VERSION AND THE CHANNEL ARE PER PLATFORM.
//
// A shared version constant would make a Linux release move the Windows version
// too, which breaks the one rule that matters here: the two sides update
// independently. These constants must never be tied to each other.
const (
	Version = "0.1.0"
	Channel = "windows/dev"
)
