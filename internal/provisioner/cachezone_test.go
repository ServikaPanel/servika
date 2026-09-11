package provisioner

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ensureCacheZone keeps exactly one definition of the shared FastCGI cache zone
// and its log format: it prepares the cache directory, drops a leftover temporary
// file, removes the managed copy when the zone is defined elsewhere, and writes
// the zone and the log format only when they differ. changed tells the caller
// whether nginx needs a reload. These tests pin both the files and that answer.

func TestTheCacheZoneIsWrittenOnceAndThenLeftAlone(t *testing.T) {
	f := withRenderSequence(t)

	changed, err := ensureCacheZone()

	if err != nil || !changed {
		t.Fatalf("ensureCacheZone() = %v, %v; want the first write reported", changed, err)
	}
	assertFileHolds(t, cacheZoneConf(), cacheZoneBody())
	assertFileHolds(t, cacheLogFormatConf(), cacheLogFormatBody())
	assertArgvs(t, f.commands.argvs(), [][]string{
		{"restorecon", "-R", f.cache},
		{"restorecon", cacheZoneConf()},
		{"restorecon", cacheLogFormatConf()},
	})

	if changed, err = ensureCacheZone(); err != nil || changed {
		t.Fatalf("a second ensureCacheZone() = %v, %v; want nothing to change", changed, err)
	}
}

func TestTheCacheZoneStateDecidesWhatIsWritten(t *testing.T) {
	definedElsewhere := func(t *testing.T, _ *renderFixture) {
		writeFixture(t, nginxMainConf, "fastcgi_cache_path /var/cache/x keys_zone = servikacache :10m;\n")
	}
	cases := []struct {
		name    string
		prepare func(t *testing.T, f *renderFixture)
		changed bool
		gone    func() []string
		kept    func() []string
	}{
		{"a leftover temporary zone file is removed", func(t *testing.T, _ *renderFixture) {
			plantFile(t, cacheZoneTempConf())
		}, true, func() []string { return []string{cacheZoneTempConf()} }, func() []string { return []string{cacheZoneConf()} }},
		{"a zone defined in nginx.conf removes the managed copy", func(t *testing.T, f *renderFixture) {
			definedElsewhere(t, f)
			plantFile(t, cacheZoneConf())
		}, true, func() []string { return []string{cacheZoneConf(), cacheLogFormatConf()} }, nil},
		{"a zone defined in another conf.d file with no managed copy changes nothing", func(t *testing.T, f *renderFixture) {
			writeFixture(t, filepath.Join(f.confDir, "custom.conf"), "fastcgi_cache_path /x keys_zone=servikacache:10m;\n")
		}, false, func() []string { return []string{cacheZoneConf()} }, nil},
		{"a current zone still restores a missing log format", func(t *testing.T, _ *renderFixture) {
			writeFixture(t, cacheZoneConf(), cacheZoneBody())
		}, true, nil, func() []string { return []string{cacheLogFormatConf()} }},
		{"a current zone and log format change nothing", func(t *testing.T, _ *renderFixture) {
			writeFixture(t, cacheZoneConf(), cacheZoneBody())
			writeFixture(t, cacheLogFormatConf(), cacheLogFormatBody())
		}, false, nil, nil},
		{"a log format that cannot be written still reports the zone change", func(t *testing.T, f *renderFixture) {
			t.Setenv("SERVIKA_NGINX_CACHE_LOG_CONF", filepath.Join(f.confDir, "missing", "log.conf"))
		}, true, func() []string { return []string{cacheLogFormatConf()} }, func() []string { return []string{cacheZoneConf()} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withRenderSequence(t)
			tc.prepare(t, f)

			changed, err := ensureCacheZone()

			if err != nil || changed != tc.changed {
				t.Fatalf("ensureCacheZone() = %v, %v; want %v", changed, err, tc.changed)
			}
			assertPathsGone(t, pathsOf(tc.gone)...)
			assertPathsKept(t, pathsOf(tc.kept)...)
		})
	}
}

func pathsOf(list func() []string) []string {
	if list == nil {
		return nil
	}
	return list()
}

func TestACacheZoneThatCannotBePreparedIsAnError(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, f *renderFixture)
		reason  string
	}{
		{"the cache directory cannot be created", func(t *testing.T, _ *renderFixture) {
			blocker := filepath.Join(t.TempDir(), "a-file")
			plantFile(t, blocker)
			t.Setenv("SERVIKA_NGINX_CACHE_DIR", filepath.Join(blocker, "cache"))
		}, "create cache directory"},
		{"the cache parent cannot be made traversable", func(t *testing.T, _ *renderFixture) {
			skipAsRoot(t)
			dir, err := os.MkdirTemp("/tmp", "servika-cache-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			t.Setenv("SERVIKA_NGINX_CACHE_DIR", dir)
		}, "set cache parent permissions"},
		{"the cache directory cannot be handed to nginx", func(t *testing.T, _ *renderFixture) {
			chown = func(string, int, int) error { return errors.New("operation not permitted") }
		}, "set cache directory ownership"},
		{"a leftover temporary file cannot be removed", func(t *testing.T, _ *renderFixture) {
			plantDirectory(t, cacheZoneTempConf())
		}, "remove temporary cache zone configuration"},
		{"the managed copy of a zone defined elsewhere cannot be removed", func(t *testing.T, _ *renderFixture) {
			writeFixture(t, nginxMainConf, "keys_zone=servikacache:10m;\n")
			plantDirectory(t, cacheZoneConf())
		}, "remove duplicate managed cache zone configuration"},
		{"the zone cannot be written", func(t *testing.T, f *renderFixture) {
			t.Setenv("SERVIKA_NGINX_CACHE_CONF", filepath.Join(f.confDir, "missing", "zone.conf"))
		}, "write cache zone configuration"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withRenderSequence(t)
			tc.prepare(t, f)

			changed, err := ensureCacheZone()

			if err == nil || !strings.Contains(err.Error(), tc.reason) || changed {
				t.Fatalf("ensureCacheZone() = %v, %v; want an error naming %q", changed, err, tc.reason)
			}
		})
	}
}
