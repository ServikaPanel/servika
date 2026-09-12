package phpext

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withRuntimes points the heal at temporary php.d directories and records what
// it reloads, so no test touches the host's own PHP or systemd.
func withRuntimes(t *testing.T, versions ...Version) *[]string {
	t.Helper()
	var reloaded []string
	previousVersions, previousRun, previousTenants := installedVersions, runCommand, reloadTenantMasters
	t.Cleanup(func() {
		installedVersions, runCommand, reloadTenantMasters = previousVersions, previousRun, previousTenants
	})
	installedVersions = func() []Version { return versions }
	runCommand = func(_ string, args ...string) ([]byte, error) {
		reloaded = append(reloaded, strings.Join(args, " "))
		return nil, nil
	}
	reloadTenantMasters = func() { reloaded = append(reloaded, "tenant masters") }
	return &reloaded
}

// Stock PHP ships expose_php on, so every site answered an unauthenticated
// request with X-Powered-By and its exact patch level. nginx's own banner has
// been off since the installer's tuning pass; PHP's was never turned off.
func TestTheBannerIsTurnedOffOnEveryInstalledRuntime(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	reloaded := withRuntimes(t,
		Version{Version: "8.3", IniDir: first, Service: "php83-php-fpm"},
		Version{Version: "8.4", IniDir: second, Service: "php84-php-fpm"},
	)

	HealExposePHP()

	for _, dir := range []string{first, second} {
		body, err := os.ReadFile(filepath.Join(dir, hardeningDropinName))
		if err != nil {
			t.Fatalf("the drop-in was not written to %s: %v", dir, err)
		}
		if !strings.Contains(string(body), "expose_php = Off") {
			t.Errorf("the drop-in does not turn the banner off:\n%s", body)
		}
	}
	want := []string{"reload-or-restart php83-php-fpm", "reload-or-restart php84-php-fpm", "tenant masters"}
	if strings.Join(*reloaded, "|") != strings.Join(want, "|") {
		t.Errorf("reloaded %q, want %q", *reloaded, want)
	}
}

// A boot on a healthy host must not restart a single pool: a reload drops the
// workers' opcode caches, and a heal that runs on every start would do it every
// start.
func TestASecondPassReloadsNothing(t *testing.T) {
	dir := t.TempDir()
	reloaded := withRuntimes(t, Version{Version: "8.3", IniDir: dir, Service: "php83-php-fpm"})
	HealExposePHP()
	*reloaded = nil

	HealExposePHP()

	if len(*reloaded) != 0 {
		t.Errorf("an unchanged drop-in still reloaded %q", *reloaded)
	}
}
