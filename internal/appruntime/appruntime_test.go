package appruntime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stubNodeRoot points the `n` version root at a temporary directory holding the
// given installations, each as <version>/bin/node.
func stubNodeRoot(t *testing.T, versions ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, version := range versions {
		binDir := filepath.Join(root, version, "bin")
		if err := os.MkdirAll(binDir, 0o755); err != nil {
			t.Fatalf("create %s: %v", binDir, err)
		}
		for _, name := range []string{"node", "npm"} {
			if err := os.WriteFile(filepath.Join(binDir, name), []byte("#!/bin/sh\n"), 0o755); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
		}
	}
	previous := nodeRoot
	nodeRoot = func() string { return root }
	t.Cleanup(func() { nodeRoot = previous })
	return root
}

// A tenant picks a MAJOR. Two patch releases of the same major are one choice,
// and the newest of them is the one that runs.
func TestNodeDiscoveryGroupsByMajorAndPrefersTheNewestPatch(t *testing.T) {
	root := stubNodeRoot(t, "22.9.0", "22.11.0", "20.18.1")

	var majors []string
	paths := map[string]string{}
	for _, runtime := range Installed(Node) {
		if runtime.System {
			continue // whatever this machine happens to ship
		}
		majors = append(majors, runtime.Version)
		paths[runtime.Version] = runtime.Path
	}

	if want := []string{"22", "20"}; strings.Join(majors, ",") != strings.Join(want, ",") {
		t.Fatalf("majors = %v, want %v (newest first)", majors, want)
	}
	if got, want := paths["22"], filepath.Join(root, "22.11.0", "bin", "node"); got != want {
		t.Errorf("22 resolved to %q, want %q", got, want)
	}
}

// Version components are numbers, not text. Sorting them as strings puts
// "22.9.0" above "22.11.0", which is the order the Laravel toolkit's own
// resolver used and the reason a host that had been updated a few times stopped
// running the newest patch of the major it was asked for.
func TestVersionsAreOrderedNumericallyNotLexically(t *testing.T) {
	got := []string{"22.9.0", "20.18.1", "22.11.0", "3.9", "3.12"}
	sortNewestFirst(got)
	want := "22.11.0,22.9.0,20.18.1,3.12,3.9"
	if strings.Join(got, ",") != want {
		t.Errorf("order = %v, want %s", got, want)
	}
}

// The result of Resolve is written into a systemd ExecStart line, so it must
// come from the filesystem rather than from the caller's text. A version that
// looks plausible but names nothing installed has to fail.
func TestResolveRefusesAVersionThatIsNotInstalled(t *testing.T) {
	stubNodeRoot(t, "22.11.0")

	if _, ok := Resolve(Node, "18"); ok {
		t.Error("an uninstalled major resolved to a path")
	}
	if path, ok := Resolve(Node, "22"); !ok || !strings.HasSuffix(path, "/22.11.0/bin/node") {
		t.Errorf("22 resolved to %q (ok=%v)", path, ok)
	}
}

// Path traversal cannot reach the filesystem through Resolve: the value is only
// ever compared against discovered versions, never joined into a path.
func TestResolveNeverBuildsAPathFromTheCallersText(t *testing.T) {
	root := stubNodeRoot(t, "22.11.0")
	// A directory the traversal would land in if the value were joined.
	if err := os.MkdirAll(filepath.Join(filepath.Dir(root), "escape", "bin"), 0o755); err != nil {
		t.Fatalf("prepare the escape directory: %v", err)
	}

	for _, hostile := range []string{
		"../escape", "22/../../escape", "/usr/bin", "22; rm -rf /", "22\nExecStart=/bin/sh",
	} {
		if path, ok := Resolve(Node, hostile); ok {
			t.Errorf("Resolve(%q) returned %q", hostile, path)
		}
	}
}

// An empty version is what a row written before any extra runtime existed
// carries, and it must mean the system interpreter rather than nothing.
func TestAnEmptyVersionMeansTheSystemRuntime(t *testing.T) {
	stubNodeRoot(t)
	system, hasSystem := Resolve(Node, SystemVersion)
	empty, hasEmpty := Resolve(Node, "")
	if hasSystem != hasEmpty || system != empty {
		t.Errorf("empty resolved to %q (%v), system to %q (%v)", empty, hasEmpty, system, hasSystem)
	}
}

func TestParseOpRejectsWhatMustNeverReachAScript(t *testing.T) {
	cases := map[string]opReq{
		"unknown runtime":       {Kind: "ruby", Version: "3.3"},
		"the system runtime":    {Kind: "node", Version: "system"},
		"a shell command":       {Kind: "node", Version: "22; rm -rf /"},
		"a quote":               {Kind: "node", Version: "22'"},
		"a newline":             {Kind: "node", Version: "22\n24"},
		"a path":                {Kind: "node", Version: "../22"},
		"an empty version":      {Kind: "node", Version: ""},
		"a python major only":   {Kind: "python", Version: "3"},
		"a python four-part":    {Kind: "python", Version: "3.12.1"},
		"a non-3 python":        {Kind: "python", Version: "2.7"},
		"a node version as py":  {Kind: "python", Version: "22"},
		"a python version node": {Kind: "node", Version: "3.12.1.4"},
	}
	for name, req := range cases {
		if _, _, err := parseOp(req); err == nil {
			t.Errorf("%s was accepted: %+v", name, req)
		}
	}
}

// The opposite direction, so the test above is not merely watching a validator
// that rejects everything.
func TestParseOpAcceptsTheRealForms(t *testing.T) {
	cases := []opReq{
		{Kind: "node", Version: "22"},
		{Kind: "node", Version: "22.11.0"},
		{Kind: "python", Version: "3.12"},
		{Kind: "python", Version: "3.9"},
	}
	for _, req := range cases {
		kind, version, err := parseOp(req)
		if err != nil {
			t.Errorf("%+v was rejected: %v", req, err)
			continue
		}
		if string(kind) != req.Kind || version != req.Version {
			t.Errorf("%+v parsed to %s/%s", req, kind, version)
		}
	}
}

// parseOp is the gate, but the scripts quote as well: a version that somehow
// reached them must still be one shell word.
func TestTheGeneratedScriptsQuoteTheVersion(t *testing.T) {
	scripts := map[string]string{
		"node install":   nodeInstallScript("22'; rm -rf /; '"),
		"node remove":    nodeRemoveScript("22'; rm -rf /; '"),
		"python install": pythonInstallScript("3.12'; rm -rf /; '"),
		"python remove":  pythonRemoveScript("3.12'; rm -rf /; '"),
	}
	for name, script := range scripts {
		if strings.Contains(script, "; rm -rf /; '\n") {
			t.Errorf("%s let an injected command out of its quoting:\n%s", name, script)
		}
		if !strings.Contains(script, `'\''`) {
			t.Errorf("%s did not escape the embedded quote:\n%s", name, script)
		}
	}
}

// A Python install must not be answered with a Node script, and the reverse.
func TestEachRuntimeGetsItsOwnInstaller(t *testing.T) {
	if !strings.Contains(nodeInstallScript("22"), "n install") {
		t.Error("the Node installer does not use n")
	}
	if strings.Contains(nodeInstallScript("22"), "dnf install") {
		t.Error("the Node installer reaches for dnf, which delivers Node as replacing module streams")
	}
	if !strings.Contains(pythonInstallScript("3.12"), "dnf install -y 'python3.12'") {
		t.Error("the Python installer does not name the parallel-installable package")
	}
	if strings.Contains(pythonInstallScript("3.12"), "n install") {
		t.Error("the Python installer reaches for the Node version manager")
	}
}

// The OS interpreter's own versioned name is not offered as a removable runtime.
// On AlmaLinux 10 /usr/bin/python3 is a symlink to /usr/bin/python3.12, so the
// base shows up under its version; removing it would run `dnf remove python3.12`
// and take the interpreter dnf and the panel depend on. A genuinely separate
// interpreter (python3.13) is still listed. Keyed on os.SameFile, so it holds
// whatever minor the host's base python happens to be.
func TestSystemPythonIsNotOfferedUnderItsVersionedName(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "python3.12")
	if err := os.WriteFile(base, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write base: %v", err)
	}
	if err := os.Symlink(base, filepath.Join(dir, "python3")); err != nil {
		t.Fatalf("symlink python3: %v", err)
	}
	extra := filepath.Join(dir, "python3.13")
	if err := os.WriteFile(extra, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write extra: %v", err)
	}

	prevBin, prevDir := systemPythonBin, systemBinDir
	systemPythonBin = filepath.Join(dir, "python3")
	systemBinDir = dir
	t.Cleanup(func() { systemPythonBin, systemBinDir = prevBin, prevDir })

	var system bool
	versions := map[string]bool{}
	for _, runtime := range Installed(Python) {
		if runtime.System {
			system = true
			continue
		}
		versions[runtime.Version] = true
	}
	if !system {
		t.Error("the system Python interpreter was not listed")
	}
	if versions["3.12"] {
		t.Error("the base interpreter was offered as a removable 3.12 runtime")
	}
	if !versions["3.13"] {
		t.Error("the genuinely separate 3.13 interpreter was not listed")
	}
}
