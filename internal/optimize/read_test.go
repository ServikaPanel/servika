package optimize

import (
	"os"
	"testing"
)

func readTestdata(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(raw)
}

// The parsers run against files captured from a real AlmaLinux 10 host, not
// hand-written fixtures. A fixture written from memory agrees with the parser
// by construction, which is the one thing a parser test must not do.
func TestTheRealNginxConfIsRead(t *testing.T) {
	text := readTestdata(t, "almalinux10-nginx.conf")
	if got := parseNginxDirective(text, "worker_connections"); got != "1024" {
		t.Errorf("worker_connections read as %q, the shipped file says 1024", got)
	}
}

func TestTheRealPoolFileIsRead(t *testing.T) {
	values := parseFPMPool(readTestdata(t, "almalinux10-www.conf"))
	want := map[string]string{
		"pm.max_children":      "50",
		"pm.start_servers":     "5",
		"pm.min_spare_servers": "5",
		"pm.max_spare_servers": "35",
	}
	for name, expected := range want {
		if values[name] != expected {
			t.Errorf("%s read as %q, want %q", name, values[name], expected)
		}
	}
}

// php-fpm comments with ";" and the shipped pool carries commented DEFAULTS
// (";pm.process_idle_timeout = 10s;", ";pm.max_requests = 500"). Reading one as
// a live value tells the operator the pool is set to a number it is not, and
// the screen would then offer to "change" a setting that was never there.
func TestACommentedDefaultIsNotReadAsALiveValue(t *testing.T) {
	values := parseFPMPool(readTestdata(t, "almalinux10-www.conf"))
	for _, name := range []string{"pm.process_idle_timeout", "pm.max_requests", "pm.status_path"} {
		if value, present := values[name]; present {
			t.Errorf("%s is commented out in the shipped pool but was read as %q", name, value)
		}
	}
}

// A directive name is only a match when the next character is whitespace.
// Without that, "worker_connections" also matches a longer directive that
// starts with it, and the wrong number reaches the screen.
func TestALongerDirectiveIsNotMistakenForTheOne(t *testing.T) {
	text := "events {\n    worker_connections_extra 99;\n    worker_connections 2048;\n}\n"
	if got := parseNginxDirective(text, "worker_connections"); got != "2048" {
		t.Errorf("read %q, want 2048", got)
	}
	only := "events {\n    worker_connections_extra 99;\n}\n"
	if got := parseNginxDirective(only, "worker_connections"); got != "" {
		t.Errorf("read %q from a file that does not set the directive", got)
	}
}

// A commented directive is not a value either.
func TestACommentedNginxDirectiveIsSkipped(t *testing.T) {
	text := "events {\n    # worker_connections 99;\n    worker_connections 4096;\n}\n"
	if got := parseNginxDirective(text, "worker_connections"); got != "4096" {
		t.Errorf("read %q, want 4096", got)
	}
}

// /proc/meminfo reports KILOBYTES. Reading the number as megabytes would make
// a 64 GB server look like 64 MB and propose a 128M buffer pool on it.
func TestMemoryIsReadAsKilobytes(t *testing.T) {
	// The first three lines of a real /proc/meminfo, 64 GB host.
	text := "MemTotal:       65805428 kB\nMemFree:         1234567 kB\nMemAvailable:   60000000 kB\n"
	if got := parseMemTotalMB(text); got != 65805428/1024 {
		t.Errorf("read %d MB, want %d", got, 65805428/1024)
	}
}

// An unreadable figure is zero, and Compute refuses to propose anything from
// zeroed facts. Guessing here would put a considered-looking number on a screen
// whose whole purpose is that the operator can trust the numbers on it.
func TestAnUnreadableMeminfoIsZeroRatherThanAGuess(t *testing.T) {
	for _, text := range []string{"", "MemTotal:\n", "MemTotal: banana kB\n", "MemFree: 100 kB\n", "MemTotal: -1 kB\n"} {
		if got := parseMemTotalMB(text); got != 0 {
			t.Errorf("%q produced %d MB", text, got)
		}
	}
}

// The sysctl path is built by substitution, so the name is checked first. No
// entry in specs can fail this today; the guard is what stops a parameter added
// later from turning a table entry into a path traversal.
func TestASysctlNameCannotEscapeProcSys(t *testing.T) {
	if got, err := procSysPath("net.core.somaxconn"); err != nil || got != "/proc/sys/net/core/somaxconn" {
		t.Errorf("got %q, %v", got, err)
	}
	for _, bad := range []string{"", "../../etc/passwd", "fs..file", "net/core", "FS.file-max", "a$b"} {
		if got, err := procSysPath(bad); err == nil {
			t.Errorf("%q was accepted and resolved to %q", bad, got)
		}
	}
}

// Every sysctl parameter this package offers must resolve to a real path, or
// the reader reports a problem for a parameter the screen still lists.
func TestEverySysctlParameterResolves(t *testing.T) {
	for _, item := range specs {
		if item.service != ServiceSysctl {
			continue
		}
		if _, err := procSysPath(item.param); err != nil {
			t.Errorf("%s: %v", item.param, err)
		}
	}
}
