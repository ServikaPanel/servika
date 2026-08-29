// Package appruntime discovers the Node.js and Python interpreters installed on
// the host and installs new ones on request.
//
// It is the ONLY place an interpreter path is decided. A caller passes the
// version a customer chose and gets back a path this package found on disk; the
// customer's text never becomes part of a path. That matters because the result
// is written straight into a systemd ExecStart line.
package appruntime

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"servika/internal/config"
)

// Kind is the interpreter family.
type Kind string

const (
	Node   Kind = "node"
	Python Kind = "python"
)

// ValidKind reports whether a value names a runtime this package handles.
func ValidKind(value string) bool {
	return Kind(value) == Node || Kind(value) == Python
}

// SystemVersion is the version name for whatever the host ships. It is not a
// number because the panel does not install it and cannot remove it.
const SystemVersion = "system"

const (
	systemNodeBin = "/usr/bin/node"
	systemNpmBin  = "/usr/bin/npm"
)

// systemPythonBin and systemBinDir are variables, not constants, so a test can
// point the Python discovery at a temporary directory. Production leaves them at
// the host paths.
var (
	systemPythonBin = "/usr/bin/python3"
	systemBinDir    = "/usr/bin"
)

// reNodeVersion accepts a major on its own ("22") or a fuller version
// ("22.11.0"). Anything else never reaches the filesystem.
var reNodeVersion = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,3}){0,2}$`)

// rePythonVersion accepts the two-component form the RPMs are named after
// ("3.12"). RHEL 10 ships alternative interpreters as separate parallel
// packages, so this is a real file name rather than a version manager's label.
var rePythonVersion = regexp.MustCompile(`^3\.[0-9]{1,2}$`)

// Runtime is one interpreter the host can run.
type Runtime struct {
	Kind Kind `json:"kind"`
	// Version is "system", a Node major ("22"), or a Python minor ("3.12").
	Version string `json:"version"`
	// Path is the absolute interpreter binary.
	Path string `json:"path"`
	// System marks the interpreter that came with the operating system. The
	// panel did not install it and refuses to remove it, because PHP tooling,
	// dnf itself and the panel's own ops scripts depend on it.
	System bool `json:"system"`
}

// nodeRoot is where the `n` version manager keeps its installations. It is a
// variable so tests can point it at a temporary directory.
var nodeRoot = config.NodeRoot

// binExists reports whether path is an existing regular file. A directory or a
// dangling symlink is not an interpreter.
func binExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// compareVersion orders two dotted numeric versions by component. Sorting them
// as strings is wrong in a way that only shows up once a host has been running
// a while: "22.9.0" sorts ABOVE "22.11.0", so the newest patch release of a
// major would stop being the one that runs.
func compareVersion(a, b string) int {
	left, right := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(left) || i < len(right); i++ {
		var x, y int
		if i < len(left) {
			x, _ = strconv.Atoi(left[i])
		}
		if i < len(right) {
			y, _ = strconv.Atoi(right[i])
		}
		if x != y {
			return x - y
		}
	}
	return 0
}

// sortNewestFirst orders dotted numeric versions with the highest first.
func sortNewestFirst(versions []string) {
	sort.Slice(versions, func(i, j int) bool {
		return compareVersion(versions[i], versions[j]) > 0
	})
}

// nodeInstallDirs returns the version directory names under the `n` root,
// newest first. A host without `n` simply has none.
func nodeInstallDirs() []string {
	entries, err := os.ReadDir(nodeRoot())
	if err != nil {
		return nil
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() && reNodeVersion.MatchString(entry.Name()) {
			names = append(names, entry.Name())
		}
	}
	sortNewestFirst(names)
	return names
}

// Installed lists the interpreters of one kind, system runtime first.
func Installed(kind Kind) []Runtime {
	switch kind {
	case Node:
		return installedNode()
	case Python:
		return installedPython()
	}
	return nil
}

func installedNode() []Runtime {
	out := make([]Runtime, 0, 4)
	if binExists(systemNodeBin) {
		out = append(out, Runtime{Kind: Node, Version: SystemVersion, Path: systemNodeBin, System: true})
	}
	// One entry per MAJOR: a tenant picks "22", not "22.11.0", and two patch
	// releases of the same major would otherwise read as two choices.
	seen := map[string]bool{}
	for _, name := range nodeInstallDirs() {
		major, _, _ := strings.Cut(name, ".")
		if seen[major] {
			continue
		}
		bin := filepath.Join(nodeRoot(), name, "bin", "node")
		if !binExists(bin) {
			continue
		}
		seen[major] = true
		out = append(out, Runtime{Kind: Node, Version: major, Path: bin})
	}
	return out
}

func installedPython() []Runtime {
	out := make([]Runtime, 0, 4)
	// sysInfo identifies the OS interpreter. On AlmaLinux 10 /usr/bin/python3 is
	// a symlink to /usr/bin/python3.12, so os.Stat follows it to the same file,
	// which is how the versioned name below is recognised as the system one.
	sysInfo, _ := os.Stat(systemPythonBin)
	if binExists(systemPythonBin) {
		out = append(out, Runtime{Kind: Python, Version: SystemVersion, Path: systemPythonBin, System: true})
	}
	entries, err := os.ReadDir(systemBinDir)
	if err != nil {
		return out
	}
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "python") {
			continue
		}
		version := strings.TrimPrefix(name, "python")
		if !rePythonVersion.MatchString(version) {
			continue
		}
		names = append(names, version)
	}
	sortNewestFirst(names)
	for _, version := range names {
		bin := filepath.Join(systemBinDir, "python"+version)
		if !binExists(bin) {
			continue
		}
		// Skip the versioned name of the OS interpreter itself. On AlmaLinux 10
		// the base python3 IS 3.12, so /usr/bin/python3.12 is the same file as
		// /usr/bin/python3, already listed above as the system runtime. Offering
		// it as a separate removable version would let a removal run
		// `dnf remove python3.12`, which pulls out the interpreter dnf, the
		// panel's ops scripts and PHP tooling all depend on. Keyed on os.SameFile
		// rather than a hardcoded "3.12", so it holds whatever minor the host's
		// base python happens to be.
		if info, statErr := os.Stat(bin); statErr == nil && sysInfo != nil && os.SameFile(sysInfo, info) {
			continue
		}
		out = append(out, Runtime{Kind: Python, Version: version, Path: bin})
	}
	return out
}

// Resolve returns the interpreter for a kind and version.
//
// The version is matched against what Installed found rather than pasted into a
// path, so a value that looks like a version but names nothing on this host is
// an error instead of an ExecStart line pointing at a file that does not exist.
// An empty version means the system runtime, which is what a domain created
// before any extra runtime existed will carry.
func Resolve(kind Kind, version string) (string, bool) {
	version = strings.TrimSpace(version)
	if version == "" {
		version = SystemVersion
	}
	for _, runtime := range Installed(kind) {
		if runtime.Version == version {
			return runtime.Path, true
		}
	}
	return "", false
}

// NodeBinDir returns the directory holding node and npm for a version, falling
// back to the system one. It answers the question "which npm" for callers that
// run npm rather than node.
func NodeBinDir(version string) string {
	path, ok := Resolve(Node, version)
	if !ok {
		return systemBinDir
	}
	return filepath.Dir(path)
}

// NpmBin returns the npm that belongs with a Node version. An `n` installation
// carries its own npm, and using the system one against it mixes two package
// managers over one node_modules tree.
func NpmBin(version string) (string, bool) {
	bin := filepath.Join(NodeBinDir(version), "npm")
	if !binExists(bin) {
		// A host with node but no npm is unusual but not impossible; say so
		// rather than handing back a path that will fail at exec time.
		if bin != systemNpmBin && binExists(systemNpmBin) {
			return systemNpmBin, true
		}
		return "", false
	}
	return bin, true
}
