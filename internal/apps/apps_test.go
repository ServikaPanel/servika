package apps

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- start command ----

// A start command becomes an ExecStart line. Anything that could end that line
// and begin a different directive, or that systemd would expand, is refused.
func TestTheStartCommandCannotIntroduceASecondDirective(t *testing.T) {
	hostile := map[string]string{
		"a newline":                             "node server.js\nExecStart=/bin/sh -c id",
		"a carriage return":                     "node server.js\rExecStart=/bin/sh",
		"a NUL":                                 "node server.js\x00",
		"a systemd specifier for the unit name": "node %n.js",
		"a systemd specifier for the home":      "node %h/evil.js",
		"a double quote":                        `node "server one.js"`,
		"a single quote":                        "node 'server one.js'",
		"a backslash":                           `node server\ one.js`,
		"an escape character":                   "node \x1bserver.js",
		"nothing at all":                        "   ",
	}
	for name, command := range hostile {
		if _, err := ParseStartCommand(command); err == nil {
			t.Errorf("%s was accepted: %q", name, command)
		}
	}
}

// The opposite direction, so the refusals above are not merely a parser that
// says no to everything.
func TestTheStartCommandAcceptsWhatPeopleActuallyWrite(t *testing.T) {
	accepted := []string{
		"node server.js",
		"npm run start",
		"gunicorn -w 4 -b 127.0.0.1:8000 app:app",
		"uvicorn app.main:app --host 127.0.0.1",
		"python -m app",
		"server.js",
		"next start -p 3000",
	}
	for _, command := range accepted {
		argv, err := ParseStartCommand(command)
		if err != nil {
			t.Errorf("%q was rejected: %v", command, err)
			continue
		}
		if len(argv) != len(strings.Fields(command)) {
			t.Errorf("%q split into %v", command, argv)
		}
	}
}

// A rendered unit must not carry a value the caller supplied outside the
// ExecStart line, and must not carry the environment at all.
func TestTheRenderedUnitKeepsSecretsOutOfSystemctlShow(t *testing.T) {
	app := App{ID: 7, Name: "api", Port: 30001}
	unit := RenderUnit(app, "c_example", "/home/c_example/api",
		[]string{"/usr/bin/node", "server.js"})

	if strings.Contains(unit, "Environment=") {
		t.Error("the unit carries Environment=, which any local user reads back with systemctl show")
	}
	if !strings.Contains(unit, "EnvironmentFile="+EnvPath(7)) {
		t.Error("the unit does not point at its EnvironmentFile")
	}
	for _, want := range []string{
		"User=c_example", "Slice=servika-c_example.slice",
		"ExecStart=/usr/bin/node server.js",
		"NoNewPrivileges=yes", "ProtectSystem=strict", "Restart=always",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("the unit is missing %q", want)
		}
	}
}

// systemd opens an append: target with O_APPEND|O_CREAT and follows a symlink,
// so a log inside the tenant's own home would let a planted link redirect a
// root-opened descriptor.
func TestTheLogTargetIsNotInsideATenantHome(t *testing.T) {
	path := LogPath(7)
	if strings.HasPrefix(path, "/home/") {
		t.Errorf("the log target is inside a tenant-writable tree: %s", path)
	}
	unit := RenderUnit(App{ID: 7, Name: "api"}, "c_example", "/home/c_example/api",
		[]string{"/usr/bin/node", "server.js"})
	if !strings.Contains(unit, "StandardOutput=append:"+path) {
		t.Errorf("the unit does not append to %s", path)
	}
}

// The restart rate limit only applies from [Unit]. systemd 257 answers
// `Unknown key 'StartLimitIntervalSec' in section [Service], ignoring.` and
// silently accepts StartLimitBurst there, so the [Service] spelling leaves the
// burst counting against the default ten-second window. RestartSec=5 fits two
// starts in that window, the burst of ten is never reached, and an application
// that cannot start restarts every five seconds for good rather than landing in
// failed where the screen would show it.
func TestTheRestartRateLimitIsDeclaredWhereSystemdReadsIt(t *testing.T) {
	unit := RenderUnit(App{ID: 7, Name: "api"}, "c_example", "/home/c_example/api",
		[]string{"/usr/bin/node", "server.js"})

	service := strings.Index(unit, "\n[Service]")
	if service < 0 {
		t.Fatal("the unit has no [Service] section")
	}
	for _, key := range []string{"StartLimitIntervalSec=300", "StartLimitBurst=10"} {
		at := strings.Index(unit, key)
		switch {
		case at < 0:
			t.Errorf("the unit no longer declares %s", key)
		case at > service:
			t.Errorf("%s sits in [Service], where systemd ignores it", key)
		}
	}
}

// ---- environment ----

func TestAnEnvironmentValueCannotDefineASecondVariable(t *testing.T) {
	// systemd reads the EnvironmentFile line by line, so a newline in a value
	// would silently create a variable nobody recorded.
	if ValidEnvValue("secret\nADMIN=1") {
		t.Error("a newline was accepted in an environment value")
	}
	if ValidEnvValue("secret\r\nADMIN=1") {
		t.Error("a carriage return was accepted in an environment value")
	}
	if ValidEnvValue("secret\x00") {
		t.Error("a NUL was accepted in an environment value")
	}
	if !ValidEnvValue("postgres://user:p@ss@127.0.0.1/db?sslmode=disable") {
		t.Error("an ordinary connection string was rejected")
	}
}

func TestReservedNamesNeverReachTheEnvironmentFile(t *testing.T) {
	body := RenderEnvFile(App{ID: 1, Port: 30005}, map[string]string{
		"PORT": "9999", "HOST": "0.0.0.0", "DATABASE_URL": "postgres://x",
	})
	if strings.Contains(body, "PORT=9999") || strings.Contains(body, "HOST=0.0.0.0") {
		t.Errorf("a customer value overrode the panel's own contract:\n%s", body)
	}
	if !strings.Contains(body, "PORT=30005") || !strings.Contains(body, "HOST=127.0.0.1") {
		t.Errorf("the panel's own values are missing:\n%s", body)
	}
	if !strings.Contains(body, "DATABASE_URL=postgres://x") {
		t.Errorf("an ordinary value was dropped:\n%s", body)
	}
}

// The environment file carries every application secret. systemd parses it in
// the manager process as root and hands the result to the child, so the
// service's own user never opens it and needs no access at all.
func TestTheEnvironmentFileIsReadableOnlyByRoot(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SERVIKA_APP_ENV_DIR", dir)
	t.Setenv("SERVIKA_APP_LOG_DIR", dir)

	app := App{ID: 42, Port: 30007}
	if err := WriteEnvFile(app, map[string]string{"DATABASE_URL": "postgres://u:p@h/db"}); err != nil {
		t.Fatalf("write the environment file: %v", err)
	}
	info, err := os.Stat(EnvPath(app.ID))
	if err != nil {
		t.Fatalf("stat the environment file: %v", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("the environment file is %#o; every bit outside the owner must be clear", mode)
	}

	if err := EnsureLogFile(app.ID); err != nil {
		t.Fatalf("create the log: %v", err)
	}
	logInfo, err := os.Stat(LogPath(app.ID))
	if err != nil {
		t.Fatalf("stat the log: %v", err)
	}
	if mode := logInfo.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("the log is %#o; every bit outside the owner must be clear", mode)
	}
}

// A rewrite must not leave a looser mode behind: os.WriteFile keeps the mode a
// file already had, so an environment file created before this rule would stay
// as it was.
func TestRewritingTheEnvironmentFileTightensAnExistingMode(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SERVIKA_APP_ENV_DIR", dir)

	app := App{ID: 43, Port: 30008}
	if err := os.WriteFile(EnvPath(app.ID), []byte("OLD=1\n"), 0o644); err != nil {
		t.Fatalf("plant a loose file: %v", err)
	}
	if err := WriteEnvFile(app, map[string]string{"NEW": "1"}); err != nil {
		t.Fatalf("write the environment file: %v", err)
	}
	info, err := os.Stat(EnvPath(app.ID))
	if err != nil {
		t.Fatalf("stat the environment file: %v", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("the pre-existing mode survived as %#o", mode)
	}
}

// ---- mount path ----

func TestTheMountPathAlwaysEndsInASlash(t *testing.T) {
	// "location ^~ /api" also matches "/apixyz", quietly capturing a sibling
	// path the tenant did not mean to hand over.
	for input, want := range map[string]string{
		"/api": "/api/", "api": "/api/", "/api/": "/api/", "": "/", "/": "/",
		"/a/b": "/a/b/",
	} {
		got, err := NormalizeMount(input)
		if err != nil {
			t.Errorf("%q was rejected: %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("%q normalized to %q, want %q", input, got, want)
		}
	}
}

func TestTheMountPathRefusesWhatWouldLeaveItsLocation(t *testing.T) {
	for _, hostile := range []string{
		"/../etc", "/api/../..", "//evil", "/api;return 301 http://evil/",
		"/api }\nlocation / { proxy_pass http://evil;", "/api$request_uri",
	} {
		if got, err := NormalizeMount(hostile); err == nil {
			t.Errorf("%q was accepted as %q", hostile, got)
		}
	}
}

// ---- application directory ----

func TestTheApplicationDirectoryCannotLeaveTheHome(t *testing.T) {
	for _, hostile := range []string{
		"../c_other/app", "../../etc", "app/../../../etc", "/etc/passwd",
		"app\x00", "app;rm -rf /", "", "   ",
	} {
		if got, err := SafeAppDir("c_example", hostile); err == nil {
			t.Errorf("%q resolved to %q", hostile, got)
		}
	}
}

func TestAnOrdinaryApplicationDirectoryResolves(t *testing.T) {
	got, err := SafeAppDir("c_example", "apps/api")
	if err != nil {
		t.Fatalf("apps/api was rejected: %v", err)
	}
	if got != "/home/c_example/apps/api" {
		t.Errorf("apps/api resolved to %q", got)
	}
}

// A symlink already planted on the way to the directory must be caught even
// though the directory itself does not exist yet.
func TestASymlinkOnTheWayOutIsRefused(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(home, "escape")); err != nil {
		t.Skipf("this filesystem does not support symlinks: %v", err)
	}

	if err := refuseSymlinkEscape(home, filepath.Join(home, "escape", "app")); err == nil {
		t.Error("a directory reached through a symlink out of the home was accepted")
	}
	if err := refuseSymlinkEscape(home, filepath.Join(home, "apps", "api")); err != nil {
		t.Errorf("an ordinary directory that does not exist yet was refused: %v", err)
	}
}

// ---- exec resolution ----

func TestTheLauncherComesFromDiskNotFromTheCommand(t *testing.T) {
	appDir := t.TempDir()
	binDir := filepath.Join(appDir, ".venv", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("create %s: %v", binDir, err)
	}
	gunicorn := filepath.Join(binDir, "gunicorn")
	if err := os.WriteFile(gunicorn, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write gunicorn: %v", err)
	}

	execStart, err := ResolveExec("python", "system", appDir, []string{"gunicorn", "-w", "4", "app:app"})
	if err != nil {
		t.Fatalf("gunicorn was not resolved: %v", err)
	}
	if execStart[0] != gunicorn {
		t.Errorf("ExecStart leads with %q, want the virtual environment's own binary %q", execStart[0], gunicorn)
	}
	if strings.Join(execStart[1:], " ") != "-w 4 app:app" {
		t.Errorf("the arguments changed: %v", execStart[1:])
	}
}

// A first token that names nothing on disk must not become a path. It stays an
// argument, so a bad name fails as "cannot run that script" rather than
// executing something reached by traversal.
func TestAnUnknownLauncherStaysAnArgument(t *testing.T) {
	appDir := t.TempDir()
	binDir := filepath.Join(appDir, ".venv", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("create %s: %v", binDir, err)
	}
	// A binary the traversal would reach if the token were joined blindly.
	outside := filepath.Join(appDir, "evil")
	if err := os.WriteFile(outside, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write the decoy: %v", err)
	}

	for _, token := range []string{"../evil", "..%2fevil", "/bin/sh"} {
		argv := []string{token, "app:app"}
		execStart, err := ResolveExec("python", "system", appDir, argv)
		if err != nil {
			continue // no system python here; the token still never became argv[0]
		}
		if execStart[0] == outside || execStart[0] == token {
			t.Errorf("%q became the launcher: %v", token, execStart)
		}
	}
}

// ---- port allocation ----

func TestThePortRangeSitsBelowTheEphemeralRange(t *testing.T) {
	// Linux defaults net.ipv4.ip_local_port_range to 32768 60999. A range that
	// overlapped it would let an outgoing connection take a port an application
	// is meant to hold, which reads as the application being down.
	const ephemeralStart = 32768
	if PortMax >= ephemeralStart {
		t.Errorf("the application range reaches %d, into the ephemeral range that starts at %d", PortMax, ephemeralStart)
	}
	if PortMin >= PortMax {
		t.Errorf("the range is empty: %d-%d", PortMin, PortMax)
	}
}

func TestADuplicateKeyIsRecognisedSoTheAllocatorMovesOn(t *testing.T) {
	// The UNIQUE constraint is the real authority over port allocation, so the
	// loop has to be able to tell that answer apart from a genuine failure.
	if !isDuplicateKey(errorString("Error 1062 (23000): Duplicate entry '30000' for key 'uq_apps_port'")) {
		t.Error("a duplicate key was not recognised")
	}
	if isDuplicateKey(errorString("Error 2006: MySQL server has gone away")) {
		t.Error("a connection failure was mistaken for a duplicate key")
	}
	if isDuplicateKey(nil) {
		t.Error("a nil error was reported as a duplicate key")
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }
