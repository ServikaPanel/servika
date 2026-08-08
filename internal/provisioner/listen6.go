package provisioner

import (
	"strings"

	"servika/internal/config"
)

// The IPv6 listen line.
//
// nginx binds every `listen` at startup, and a kernel booted with
// ipv6.disable=1 refuses an AF_INET6 bind with EAFNOSUPPORT. nginx treats that
// as fatal, so ONE unconditional `listen [::]` line on such a host takes down
// every site on the server, including the panel, which leaves the operator with
// no screen to read the reason on.
//
// The answer comes from config.HasIPv6, which measures kernel support once per
// process. It must not change mid-run: roughly thirty unrelated call sites
// re-render a vhost, and a value that flipped between two of them would leave
// some sites bound to IPv6 and others not inside a single reload.

// hostHasIPv6 is a variable so a test can drive BOTH branches. On a developer
// machine the real answer is always true, so a test that could only observe the
// production value would never exercise the host-without-IPv6 case at all.
var hostHasIPv6 = config.HasIPv6

// ListenIPv6 renders one nginx IPv6 listen line for the given directive tail
// ("80", "443 ssl"), or nothing when this host has no IPv6 stack.
//
// The line carries its own indentation and trailing newline so a caller can
// drop it between two lines and get nothing at all when IPv6 is absent, rather
// than a blank line where a directive used to be.
func ListenIPv6(tail string) string {
	if !hostHasIPv6() {
		return ""
	}
	return "    listen [::]:" + strings.TrimSpace(tail) + ";\n"
}

// vhostFuncs is the function map every rendered nginx template carries.
var vhostFuncs = map[string]any{"listen6": ListenIPv6}
