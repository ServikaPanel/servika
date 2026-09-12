package apps

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"servika/internal/appruntime"
)

// reLauncher is the shape a first token must have before it is looked up inside
// the application directory. No slash, so the lookup cannot leave the directory
// it is joined to.
var reLauncher = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// dependencyBinDirs are where a tenant's own dependency install puts runnable
// commands: pip into the virtual environment, npm into the project.
func dependencyBinDirs(runtime, appDir string) []string {
	switch appruntime.Kind(runtime) {
	case appruntime.Python:
		return []string{filepath.Join(appDir, ".venv", "bin")}
	case appruntime.Node:
		return []string{filepath.Join(appDir, "node_modules", ".bin")}
	}
	return nil
}

// runtimeCommand maps a runtime word to the binary that belongs with the
// application's chosen version, so "npm" under Node 22 is that version's npm
// rather than whichever one happens to be first on PATH.
func runtimeCommand(runtime, version, word string) (string, bool) {
	switch appruntime.Kind(runtime) {
	case appruntime.Node:
		switch word {
		case "node":
			return resolveRuntimePath(appruntime.Node, version)
		case "npm", "npx":
			bin := filepath.Join(appruntime.NodeBinDir(version), word)
			if info, err := os.Stat(bin); err == nil && info.Mode().IsRegular() {
				return bin, true
			}
		}
	case appruntime.Python:
		if word == "python" || word == "python3" {
			return resolveRuntimePath(appruntime.Python, version)
		}
	}
	return "", false
}

// ResolveExec turns a validated argv into the ExecStart line.
//
// The first token names the launcher and the panel decides what it means, in
// this order:
//
//  1. a runtime command (node, npm, npx, python, python3) — the interpreter or
//     the package manager that belongs with the chosen version;
//  2. an executable the tenant's own dependency install produced, under
//     .venv/bin or node_modules/.bin — this is how gunicorn, uvicorn, vite and
//     nest are actually started;
//  3. anything else — a script, so the interpreter leads and the whole command
//     becomes its arguments, which is what makes "server.js" work.
//
// Every path returned either came from appruntime's own discovery or from a
// stat inside the application directory with a token that cannot hold a slash.
// The caller's text never becomes a path component.
func ResolveExec(runtime, version, appDir string, argv []string) ([]string, error) {
	if len(argv) == 0 {
		return nil, errors.New("start command is required")
	}
	head, rest := argv[0], argv[1:]

	if path, ok := runtimeCommand(runtime, version, head); ok {
		return append([]string{path}, rest...), nil
	}
	if reLauncher.MatchString(head) {
		for _, dir := range dependencyBinDirs(runtime, appDir) {
			candidate := filepath.Join(dir, head)
			if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
				return append([]string{candidate}, rest...), nil
			}
		}
	}
	// A script or a module flag. The interpreter runs it, and the whole command
	// stays as written so "-m app" and "server.js --port" both survive.
	interpreter, err := ResolveRuntime(runtime, version)
	if err != nil {
		return nil, err
	}
	return append([]string{interpreter}, argv...), nil
}

// DisplayExec renders an ExecStart line for a screen, with the leading path
// trimmed to its base name so a long version directory does not hide the
// command a customer actually wrote.
func DisplayExec(execStart []string) string {
	if len(execStart) == 0 {
		return ""
	}
	shown := append([]string{filepath.Base(execStart[0])}, execStart[1:]...)
	return strings.Join(shown, " ")
}
