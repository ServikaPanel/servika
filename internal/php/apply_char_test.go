package php

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ApplyToFilesystem writes one pool file into the directory SHARED by every
// tenant on a PHP version, then tests and reloads that version's master. The
// tests below pin what lands where, what is removed, and what is put back when
// php-fpm refuses the pool.

// setForTest points a package variable somewhere else for one test.
func setForTest[T any](t *testing.T, target *T, value T) {
	t.Helper()
	previous := *target
	*target = value
	t.Cleanup(func() { *target = previous })
}

// ranCommand is one host command the package asked for.
type ranCommand struct {
	name string
	args []string
}

// host records the commands ApplyToFilesystem runs and answers them.
type host struct {
	fail map[string]error
	ran  []ranCommand
}

// install points runCommand at this recorder.
func (h *host) install(t *testing.T) {
	t.Helper()
	setForTest(t, &runCommand, func(name string, args ...string) ([]byte, error) {
		h.ran = append(h.ran, ranCommand{name: name, args: args})
		return []byte("output of " + name), h.fail[name]
	})
}

// commands returns each recorded command as one line.
func (h *host) commands() []string {
	lines := make([]string, 0, len(h.ran))
	for _, command := range h.ran {
		lines = append(lines, strings.Join(append([]string{command.name}, command.args...), " "))
	}
	return lines
}

// versionDirs points the two supported versions at temporary directories and
// returns them, so a pool write is observable without a host.
func versionDirs(t *testing.T) (current, other Version) {
	t.Helper()
	root := t.TempDir()
	current = Version{
		Version: "8.3",
		PoolDir: filepath.Join(root, "php83", "pool"),
		SockDir: filepath.Join(root, "php83", "run"),
		Service: "php-fpm",
	}
	other = Version{
		Version: "8.2",
		PoolDir: filepath.Join(root, "php82", "pool"),
		SockDir: filepath.Join(root, "php82", "run"),
		Service: "php82-php-fpm",
	}
	for _, version := range []Version{current, other} {
		if err := os.MkdirAll(version.PoolDir, 0o755); err != nil {
			t.Fatalf("create the pool directory: %v", err)
		}
	}
	setForTest(t, &InstalledVersions, []Version{current, other})
	return current, other
}

// poolBody reads a written pool file.
func poolBody(t *testing.T, version Version, systemUser string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(version.PoolDir, systemUser+".conf"))
	if err != nil {
		t.Fatalf("read the pool file: %v", err)
	}
	return string(body)
}

func TestAPoolIsWrittenTestedAndTheMasterReloaded(t *testing.T) {
	current, _ := versionDirs(t)
	recorder := &host{fail: map[string]error{}}
	recorder.install(t)
	setForTest(t, &fpmBinaryFor, func(string) string { return "/usr/sbin/php-fpm" })

	socket, err := ApplyToFilesystem("c_acme", "8.3", Defaults())
	if err != nil {
		t.Fatalf("apply the pool: %v", err)
	}

	if want := filepath.Join(current.SockDir, "c_acme.sock"); socket != want {
		t.Errorf("socket = %q, want %q", socket, want)
	}
	body := poolBody(t, current, "c_acme")
	for _, line := range []string{
		"[c_acme]",
		"user = c_acme",
		"listen = " + current.SockDir + "/c_acme.sock",
		"listen.owner = nginx",
		// Measured: the package default strategy is ondemand.
		"pm = ondemand",
	} {
		if !strings.Contains(body, line) {
			t.Errorf("the pool file has no %q:\n%s", line, body)
		}
	}
	want := []string{"/usr/sbin/php-fpm -t", "systemctl reload-or-restart php-fpm"}
	if got := recorder.commands(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("commands = %v, want %v", got, want)
	}
}

// A version switch leaves the tenant's pool behind in the previous version's
// shared directory, where it keeps a socket the vhost no longer points at.
func TestASwitchRemovesThePoolOfEveryOtherVersion(t *testing.T) {
	current, other := versionDirs(t)
	stale := filepath.Join(other.PoolDir, "c_acme.conf")
	if err := os.WriteFile(stale, []byte("[c_acme]\n"), 0o644); err != nil {
		t.Fatalf("write the stale pool: %v", err)
	}
	recorder := &host{fail: map[string]error{}}
	recorder.install(t)
	setForTest(t, &fpmBinaryFor, func(string) string { return "" })

	if _, err := ApplyToFilesystem("c_acme", "8.3", Defaults()); err != nil {
		t.Fatalf("apply the pool: %v", err)
	}

	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the previous version's pool is still there: %v", err)
	}
	want := []string{
		"systemctl reload-or-restart php82-php-fpm",
		"systemctl reload-or-restart php-fpm",
	}
	if got := recorder.commands(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("commands = %v, want %v", got, want)
	}
	if _, err := os.Stat(filepath.Join(current.PoolDir, "c_acme.conf")); err != nil {
		t.Errorf("the new pool was not written: %v", err)
	}
}

// A pool php-fpm refuses fails the test for the WHOLE version, so the previous
// bytes go back before anybody else's domain is created on it.
func TestARefusedPoolIsPutBack(t *testing.T) {
	current, _ := versionDirs(t)
	poolPath := filepath.Join(current.PoolDir, "c_acme.conf")
	if err := os.WriteFile(poolPath, []byte("[c_acme]\n; the pool that worked\n"), 0o644); err != nil {
		t.Fatalf("write the previous pool: %v", err)
	}
	recorder := &host{fail: map[string]error{"/usr/sbin/php-fpm": errors.New("exit status 1")}}
	recorder.install(t)
	setForTest(t, &fpmBinaryFor, func(string) string { return "/usr/sbin/php-fpm" })

	_, err := ApplyToFilesystem("c_acme", "8.3", Defaults())

	if err == nil || !strings.Contains(err.Error(), "php-fpm -t (8.3) failed, pool restored") {
		t.Fatalf("error = %v, want the refusal", err)
	}
	if body := poolBody(t, current, "c_acme"); body != "[c_acme]\n; the pool that worked\n" {
		t.Errorf("the previous pool was not put back:\n%s", body)
	}
	if got := recorder.commands(); len(got) != 1 {
		t.Errorf("commands = %v, want the reload not to have run", got)
	}
}

// With no previous pool there is nothing to put back, so the refused file is
// removed instead of being left for php-fpm -t to fail on again.
func TestARefusedFirstPoolIsRemoved(t *testing.T) {
	current, _ := versionDirs(t)
	recorder := &host{fail: map[string]error{"/usr/sbin/php-fpm": errors.New("exit status 1")}}
	recorder.install(t)
	setForTest(t, &fpmBinaryFor, func(string) string { return "/usr/sbin/php-fpm" })

	if _, err := ApplyToFilesystem("c_acme", "8.3", Defaults()); err == nil {
		t.Fatal("the refused pool was accepted")
	}

	if _, err := os.Stat(filepath.Join(current.PoolDir, "c_acme.conf")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the refused pool is still in the shared directory: %v", err)
	}
}

// A master that will not reload is the same case: the pool that is live is the
// previous one, so that is what the file has to say.
func TestAFailedReloadPutsThePoolBack(t *testing.T) {
	current, _ := versionDirs(t)
	poolPath := filepath.Join(current.PoolDir, "c_acme.conf")
	if err := os.WriteFile(poolPath, []byte("[c_acme]\n; the pool that worked\n"), 0o644); err != nil {
		t.Fatalf("write the previous pool: %v", err)
	}
	recorder := &host{fail: map[string]error{"systemctl": errors.New("exit status 1")}}
	recorder.install(t)
	setForTest(t, &fpmBinaryFor, func(string) string { return "" })

	_, err := ApplyToFilesystem("c_acme", "8.3", Defaults())

	if err == nil || !strings.Contains(err.Error(), "php-fpm reload (php-fpm), pool restored") {
		t.Fatalf("error = %v, want the reload failure", err)
	}
	if body := poolBody(t, current, "c_acme"); body != "[c_acme]\n; the pool that worked\n" {
		t.Errorf("the previous pool was not put back:\n%s", body)
	}
}

func TestAnUnsupportedVersionWritesNothing(t *testing.T) {
	versionDirs(t)
	recorder := &host{fail: map[string]error{}}
	recorder.install(t)

	_, err := ApplyToFilesystem("c_acme", "5.6", Defaults())

	if err == nil || err.Error() != "unsupported PHP version: 5.6" {
		t.Fatalf("error = %v, want the unsupported version", err)
	}
	if got := recorder.commands(); len(got) != 0 {
		t.Errorf("commands = %v, want none", got)
	}
}

// Settings the pool file cannot carry are refused before anything is written.
func TestAPoolIsNotWrittenForSettingsThatAreRefused(t *testing.T) {
	current, _ := versionDirs(t)
	recorder := &host{fail: map[string]error{}}
	recorder.install(t)
	refused := Defaults()
	refused.PMStrategy = "whatever"

	if _, err := ApplyToFilesystem("c_acme", "8.3", refused); err == nil {
		t.Fatal("the refused settings were accepted")
	}

	if _, err := os.Stat(filepath.Join(current.PoolDir, "c_acme.conf")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a pool was written for refused settings: %v", err)
	}
}
