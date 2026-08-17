package panelport

import (
	"os"
	"strings"
	"testing"
)

func panelConf(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("testdata/panel.conf")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	return string(raw)
}

// The port set that must never be taken. Each of these belongs to a service
// this server actually runs, and nginx binding one does not merely fail: the
// real service stops, and the failure surfaces as mail or DNS breaking rather
// than as anything the panel said.
func TestAPortBelongingToAnotherServiceIsRefused(t *testing.T) {
	for _, port := range []int{21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 2222, 3306, 6379} {
		err := ValidatePort(port)
		if got := ReasonOf(err); got != ReasonReservedPort {
			t.Errorf("port %d refused as %q, want %q", port, got, ReasonReservedPort)
		}
	}
}

// The tenant application range is DROPPED at the firewall, so a panel moved
// into it answers on loopback and nowhere else: the operator's browser times
// out with nothing in any log to explain it.
func TestThePanelCannotMoveIntoTheApplicationRange(t *testing.T) {
	for _, port := range []int{30000, 30500, 30999} {
		err := ValidatePort(port)
		if got := ReasonOf(err); got != ReasonAppPort {
			t.Errorf("port %d refused as %q, want %q", port, got, ReasonAppPort)
		}
	}
	// The ports either side of the range are fine, or the bound is wrong.
	for _, port := range []int{29999, 31000} {
		if err := ValidatePort(port); err != nil {
			t.Errorf("port %d is outside the application range but was refused: %v", port, err)
		}
	}
}

// Everything below 1024 belongs to a system service that either exists on this
// server or will when a feature is switched on.
func TestPrivilegedPortsAreRefused(t *testing.T) {
	for _, port := range []int{1, 100, 1023} {
		if got := ReasonOf(ValidatePort(port)); got != ReasonReservedPort {
			t.Errorf("port %d refused as %q", port, got)
		}
	}
	if err := ValidatePort(1024); err != nil {
		t.Errorf("1024 is the first unprivileged port but was refused: %v", err)
	}
}

// Out of range is REFUSED, never clamped. A clamp moves the panel to a port
// the operator never typed, and this is the screen where that means they go
// looking for it on the wrong number.
func TestAnImpossiblePortIsRefusedRatherThanClamped(t *testing.T) {
	for _, port := range []int{-1, 0, 65536, 99999} {
		if got := ReasonOf(ValidatePort(port)); got != ReasonBadPort {
			t.Errorf("port %d refused as %q, want %q", port, got, ReasonBadPort)
		}
	}
}

// A perfectly ordinary port is accepted, or every test above proves nothing.
func TestAnOrdinaryPortIsAccepted(t *testing.T) {
	for _, port := range []int{8080, 8443, 9443, 2087, 10000, 65535} {
		if err := ValidatePort(port); err != nil {
			t.Errorf("port %d was refused: %v", port, err)
		}
	}
}

// The host part of SERVIKA_LISTEN is preserved by every writer. An
// installation bound to loopback must stay bound to loopback: widening it puts
// the panel API on every address the server has without anybody asking.
func TestTheListenHostIsPreserved(t *testing.T) {
	for _, source := range []string{"127.0.0.1:8080", ":8080", "[::1]:8080", "0.0.0.0:8080"} {
		host, port, err := ParseListen(source)
		if err != nil || port != 8080 {
			t.Fatalf("ParseListen(%q) = %q, %d, %v", source, host, port, err)
		}
		text := "SERVIKA_ENV=production\nSERVIKA_LISTEN=" + source + "\nSERVIKA_DB_DSN=x\n"
		written, err := SetEnvListen(text, host, 9090)
		if err != nil {
			t.Fatalf("SetEnvListen: %v", err)
		}
		gotHost, gotPort, err := ParseListen(ReadEnvListen(written))
		if err != nil || gotPort != 9090 || gotHost != host {
			t.Errorf("%q became %q:%d (%v), want %s:9090", source, gotHost, gotPort, err, host)
		}
		// Nothing else moved.
		if !strings.Contains(written, "SERVIKA_DB_DSN=x") || !strings.Contains(written, "SERVIKA_ENV=production") {
			t.Errorf("other settings were lost:\n%s", written)
		}
	}
}

// systemd's EnvironmentFile takes the LAST assignment. Reading the first would
// report a port the panel is not on whenever an old line was left above.
func TestTheLastAssignmentWinsAsSystemdReadsIt(t *testing.T) {
	text := "SERVIKA_LISTEN=127.0.0.1:8080\n# SERVIKA_LISTEN=127.0.0.1:1\nSERVIKA_LISTEN=127.0.0.1:9090\n"
	if got := ReadEnvListen(text); got != "127.0.0.1:9090" {
		t.Errorf("read %q, systemd would use 127.0.0.1:9090", got)
	}
}

// An environment file without the assignment is one this package does not
// understand. Appending would appear to work (systemd takes the last line) and
// then be dropped by the installer's next managed rewrite, so the port would
// come back on its own weeks later.
func TestAMissingAssignmentIsRefusedRatherThanAppended(t *testing.T) {
	_, err := SetEnvListen("SERVIKA_ENV=production\n", "127.0.0.1", 9090)
	if got := ReasonOf(err); got != ReasonNotFound {
		t.Errorf("refused as %q, want %q", got, ReasonNotFound)
	}
}

// The shipped panel vhost is the real file, not a sample. It carries the IPv4
// and IPv6 listen lines as a pair plus four proxy_pass lines to the backend.
func TestTheShippedPanelVhostIsRead(t *testing.T) {
	if got := ReadNginxListenPort(panelConf(t)); got != 8443 {
		t.Errorf("read the panel port as %d, the shipped file says 8443", got)
	}
}

// Rewriting only ONE of the pair is the silent failure this guards: nginx
// starts happily with the panel on the new port over IPv4 and the old one over
// IPv6, and a browser that prefers IPv6 keeps working until the day it does not.
func TestBothAddressFamiliesMoveTogether(t *testing.T) {
	text := panelConf(t)
	moved, err := SetNginxListenPort(text, 9443)
	if err != nil {
		t.Fatal(err)
	}

	var v4, v6 bool
	for line := range strings.SplitSeq(moved, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "listen ") || !strings.Contains(trimmed, "default_server") {
			continue
		}
		if strings.Contains(trimmed, "[::]:9443") {
			v6 = true
		} else if strings.Contains(trimmed, "listen 9443") {
			v4 = true
		}
		if strings.Contains(trimmed, "8443") {
			t.Errorf("a listen line was left on the old port: %q", trimmed)
		}
	}
	if !v4 || !v6 {
		t.Errorf("IPv4 moved: %v, IPv6 moved: %v; both must move together", v4, v6)
	}
	// The "ssl default_server" tail survives, or nginx serves plaintext on the
	// panel port and every browser refuses the connection.
	if !strings.Contains(moved, "ssl default_server") {
		t.Error("the ssl default_server tail was lost")
	}
}

// A file with no default_server listen line is refused rather than appended to.
func TestAVhostWithoutTheListenLineIsRefused(t *testing.T) {
	_, err := SetNginxListenPort("server {\n    listen 443 ssl;\n}\n", 9443)
	if got := ReasonOf(err); got != ReasonNotFound {
		t.Errorf("refused as %q, want %q", got, ReasonNotFound)
	}
}

// The backend port is rewritten by matching the OLD port, never "any loopback
// proxy_pass": the same file proxies to php-fpm, to phpMyAdmin and to the
// panel's own external port, and rewriting those would point the panel at
// itself.
func TestOnlyTheBackendProxyMoves(t *testing.T) {
	text := panelConf(t)
	moved, replaced := SetProxyPort(text, 8080, 9090)
	if replaced == 0 {
		t.Fatal("no proxy_pass line was rewritten")
	}
	if strings.Contains(moved, "127.0.0.1:8080") {
		t.Error("a backend proxy_pass was left on the old port")
	}
	// Every other port in the file is untouched. 8443 is the panel's own
	// external port, which a backend change must not move.
	if strings.Count(moved, "8443") != strings.Count(text, "8443") {
		t.Error("a line naming the external port was rewritten by a backend change")
	}
	if strings.Count(moved, "fastcgi_pass") != strings.Count(text, "fastcgi_pass") {
		t.Error("a fastcgi_pass line was altered")
	}
}

// Nothing is rewritten when the old port does not appear, so a repeated apply
// cannot walk the port along by one each time.
func TestAProxyRewriteIsKeyedOnTheOldPort(t *testing.T) {
	text := panelConf(t)
	_, replaced := SetProxyPort(text, 7777, 9090)
	if replaced != 0 {
		t.Errorf("%d lines were rewritten for a port that is not in the file", replaced)
	}
}

func TestOnlyTheTwoKnownKindsAreAccepted(t *testing.T) {
	for _, kind := range []string{KindBackend, KindExternal} {
		if !ValidKind(kind) {
			t.Errorf("%q is a kind this package moves but was refused", kind)
		}
	}
	for _, kind := range []string{"", "both", "BACKEND", "backend ", "nginx"} {
		if ValidKind(kind) {
			t.Errorf("%q was accepted as a kind", kind)
		}
	}
}

// Every write in this package goes through knownTarget. A rollback reads its
// paths out of a change set that the detached helper also holds on disk, and
// anything on disk outlives the code that wrote it.
func TestOnlyTheManagedFilesCanBeWritten(t *testing.T) {
	for _, path := range []string{envPath(), panelVhostPath(), panelDomainVhostPath()} {
		if !knownTarget(path) {
			t.Errorf("%s is managed by this package but knownTarget refuses it", path)
		}
	}
	for _, path := range []string{
		"", "/etc/passwd", "/etc/nginx/nginx.conf", "/etc/shadow",
		"/etc/servika/env.bak", "/home/c_example/public_html/index.php",
	} {
		if knownTarget(path) {
			t.Errorf("%q is not managed by this package but was accepted", path)
		}
		if err := writeFilePreservingMode(path, "x"); err == nil {
			t.Errorf("writeFilePreservingMode wrote to %q", path)
		}
	}
}

// The helper becomes a root shell script, so every value interpolated into it
// is checked. Nothing can currently fail these; the checks are what stop a
// later addition from turning a path into another shell word.
func TestNothingUnusualReachesTheHelperScript(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "panel.example.com", "10.0.0.5"} {
		if !plainHost(host) {
			t.Errorf("%q is an ordinary host but was refused", host)
		}
	}
	for _, host := range []string{"", "a b", "a;reboot", "$(id)", "a`id`", "a\nb", "a'b"} {
		if plainHost(host) {
			t.Errorf("%q was accepted as a host", host)
		}
	}
	for _, path := range []string{"/etc/servika/env", "/var/lib/servika/x.bak"} {
		if !plainPath(path) {
			t.Errorf("%q is an ordinary path but was refused", path)
		}
	}
	for _, path := range []string{
		"", "etc/servika/env", "/etc/../etc/passwd", "/etc/x;reboot",
		"/etc/$(id)", "/etc/x y", "/etc/x'y",
	} {
		if plainPath(path) {
			t.Errorf("%q was accepted as a path", path)
		}
	}
}
