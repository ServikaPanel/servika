package packages

import (
	"context"
	"os/exec"
)

// runCommand builds the dnf and rpm invocations this package makes. It is a
// package-level variable so a test can answer them with a recorded transcript
// instead of the host's own package manager. It is NOT operator configuration:
// no SERVIKA_* variable and no paths.go entry.
var runCommand = func(ctx context.Context, name string, arguments ...string) *exec.Cmd {
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	return exec.CommandContext(ctx, name, arguments...)
}
