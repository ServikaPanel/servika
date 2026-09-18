//go:build !windows

package platform

// THE VERSION AND THE CHANNEL ARE PER PLATFORM.
//
// A shared version constant would make a Windows release move the Linux version
// too, which breaks the one rule that matters here: the two sides update
// independently. These constants must never be tied to each other, and this one
// is deliberately NOT the panel's own version either.
const (
	Version = "1.0.0"
	Channel = "linux/stable"
)
