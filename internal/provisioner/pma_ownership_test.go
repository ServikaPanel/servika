package provisioner

import (
	"os"
	"path/filepath"
	"testing"
)

// The pool user decides who may read the phpMyAdmin secrets, so it is read from
// the installed pool rather than assumed. Guessing wrong leaves them readable by
// an account that should not have them, or stops phpMyAdmin from reading its own
// configuration.
func TestThePoolUserIsReadFromTheInstalledPool(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"the shipped pool", "[phpmyadmin]\nuser = apache\ngroup = apache\n", "apache"},
		{"an operator who changed it", "[phpmyadmin]\nuser = www-data\ngroup = www-data\n", "www-data"},
		{"no spaces around the separator", "[phpmyadmin]\nuser=nginx\n", "nginx"},
		{"a commented-out value is not the value", "[phpmyadmin]\n; user = nginx\n#user = root\nuser = apache\n", "apache"},
		{"a pool with no user directive", "[phpmyadmin]\npm = ondemand\n", "apache"},
		{"an empty file", "", "apache"},
		{"listen.owner is not the user", "[phpmyadmin]\nlisten.owner = nginx\n", "apache"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := pmaPoolUserFrom(tc.body); got != tc.want {
				t.Errorf("pool user = %q, want %q", got, tc.want)
			}
		})
	}
}

// config.inc.php carries blowfish_secret, which encrypts the MySQL credentials
// phpMyAdmin puts in the visitor's cookie, and controlpass for an account with
// ALL PRIVILEGES on the phpmyadmin schema. The installer left the tree owned by
// nginx while the pool runs as apache, so the file worked only by being
// world-readable and every c_* tenant could read both.
func TestTheHealTakesThePhpMyAdminSecretsAwayFromEveryOtherAccount(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.inc.php")
	varLib := filepath.Join(root, "varlib")
	sessions := filepath.Join(varLib, "sessions")
	tmp := filepath.Join(varLib, "tmp")

	// Reproduce what the installer leaves behind.
	if err := os.WriteFile(configPath, []byte("<?php $cfg['blowfish_secret'] = 'x';\n"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{varLib, tmp, sessions} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv("SERVIKA_PHPMYADMIN_CONFIG", configPath)
	t.Setenv("SERVIKA_PHPMYADMIN_VAR_LIB", varLib)
	stubPMAAccount(t, func(string, int, int) error { return nil })

	ensurePMAOwnership()

	for _, want := range []struct {
		path string
		mode os.FileMode
		why  string
	}{
		{configPath, 0640, "the blowfish secret and the control-user password are in this file"},
		{varLib, 0755, "the pool writes here"},
		{tmp, 0755, "the pool writes here"},
		{sessions, 0700, "a session file holds the credentials of whoever is signed in"},
	} {
		info, err := os.Stat(want.path)
		if err != nil {
			t.Fatalf("%s: %v", want.path, err)
		}
		if got := info.Mode().Perm(); got != want.mode {
			t.Errorf("%s is %04o, want %04o: %s", want.path, got, want.mode, want.why)
		}
	}
}

// A missing account must not be reported as a repair. Chowning to whatever the
// lookup happened to return would hand the secrets to an arbitrary id.
func TestAnUnknownPoolAccountLeavesThePermissionsAlone(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.inc.php")
	if err := os.WriteFile(configPath, []byte("<?php\n"), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SERVIKA_PHPMYADMIN_CONFIG", configPath)
	t.Setenv("SERVIKA_PHPMYADMIN_VAR_LIB", filepath.Join(root, "varlib"))
	previousLookup, previousChown := pmaLookupAccount, pmaChown
	pmaLookupAccount = func(string) (int, int, error) { return 0, 0, os.ErrNotExist }
	pmaChown = func(string, int, int) error { return nil }
	t.Cleanup(func() { pmaLookupAccount, pmaChown = previousLookup, previousChown })

	ensurePMAOwnership()

	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0644 {
		t.Errorf("the file is %04o; an unresolved account must change nothing, not guess", got)
	}
}

// Tightening the mode while the file still belongs to the wrong account does
// not protect the secret. It stops phpMyAdmin reading its own configuration,
// which is an outage rather than a weaker permission, so the old mode stays.
func TestAFailedChownDoesNotTightenTheMode(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.inc.php")
	if err := os.WriteFile(configPath, []byte("<?php\n"), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SERVIKA_PHPMYADMIN_CONFIG", configPath)
	t.Setenv("SERVIKA_PHPMYADMIN_VAR_LIB", filepath.Join(root, "varlib"))
	stubPMAAccount(t, func(string, int, int) error { return os.ErrPermission })

	ensurePMAOwnership()

	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0644 {
		t.Errorf("the file is %04o; a 0640 the pool account does not own locks phpMyAdmin out", got)
	}
}

// stubPMAAccount supplies the account lookup and the chown, neither of which a
// test can perform for real, and restores both afterwards.
func stubPMAAccount(t *testing.T, chown func(string, int, int) error) {
	t.Helper()
	previousLookup, previousChown := pmaLookupAccount, pmaChown
	pmaLookupAccount = func(string) (int, int, error) { return os.Getuid(), os.Getgid(), nil }
	pmaChown = chown
	t.Cleanup(func() { pmaLookupAccount, pmaChown = previousLookup, previousChown })
}
