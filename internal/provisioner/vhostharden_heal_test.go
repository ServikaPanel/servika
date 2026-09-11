package provisioner

import (
	"database/sql/driver"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"testing"
)

// healVhostsOnStartup is the only sweep that re-renders every existing tenant's
// PHP-FPM pool and vhost after an update, and its sentinel is written only when
// every domain went through. These tests pin when the sweep runs, which socket
// each vhost is rendered with, and that anything short of a complete pass leaves
// the sentinel unwritten so the next startup tries again.

const domainSweepQuery = "SELECT id, system_user, php_version FROM domains"

type hardeningSweep struct {
	sentinel string
	sockets  string
	units    string
	accounts map[string]*user.User
	script   *sqlScript
	capture  *renderCapture
}

func withHardeningSweep(t *testing.T) *hardeningSweep {
	t.Helper()
	root := t.TempDir()
	s := &hardeningSweep{
		sentinel: filepath.Join(root, "lib", "servika", ".vhost_hardening_v5_done"),
		sockets:  filepath.Join(root, "run"),
		accounts: map[string]*user.User{
			"c_example_com": {Username: "c_example_com", Uid: "1500", Gid: "1500"},
			"c_example_net": {Username: "c_example_net", Uid: "1501", Gid: "1501"},
		},
	}
	withTenantHome(t)
	s.units = withTenantUnits(t)
	setForTest(t, &vhostHardenSentinel, s.sentinel)
	setForTest(t, &phpMap, map[string]phpConfig{
		"8.3": {PoolDir: filepath.Join(root, "php-fpm.d"), SockDir: s.sockets, Service: "php-fpm", FPMBin: "/usr/sbin/php-fpm"},
		"7.4": {PoolDir: filepath.Join(root, "php74"), SockDir: filepath.Join(root, "run74"), Service: "php74-php-fpm", FPMBin: "/opt/remi/php74/root/usr/sbin/php-fpm"},
	})
	withAccounts(t, s.accounts)
	withCommands(t)
	s.capture = withRenderCapture(t)
	s.script = vhostScript(domainDetails("example.com", "c_example_com", "", "", "", "php-fpm", "", 0, 0, "", nil))
	s.script.rows[domainSweepQuery] = [][]driver.Value{{int64(7), "c_example_com", "8.3"}}
	withScript(t, s.script)
	return s
}

func (s *hardeningSweep) renderedSockets() []string {
	var sockets []string
	for _, opts := range s.capture.opts {
		sockets = append(sockets, opts.PHPSocket)
	}
	return sockets
}

func TestTheHardeningSweepDoesNotRunWithoutADatabaseOrAfterItsSentinel(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, s *hardeningSweep)
	}{
		{"there is no database", func(t *testing.T, _ *hardeningSweep) { withoutDatabase(t) }},
		{"the sentinel exists", func(t *testing.T, s *hardeningSweep) { plantFile(t, s.sentinel) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := withHardeningSweep(t)
			tc.prepare(t, s)

			healVhostsOnStartup()

			if len(s.capture.opts) != 0 {
				t.Errorf("rendered %+v, want no sweep", s.capture.opts)
			}
		})
	}
}

// A tenant on the shared master gets its pool rewritten and is rendered with the
// pool's socket; a tenant with its own master keeps its own socket and no shared
// pool is written for it.
func TestTheHardeningSweepRewritesEveryPoolAndVhostThenWritesItsSentinel(t *testing.T) {
	s := withHardeningSweep(t)
	writeFixture(t, filepath.Join(s.units, tenantUnitName("c_example_net")), "[Service]\n")
	s.script.rows[domainSweepQuery] = [][]driver.Value{{int64(7), "c_example_com", "8.3"}, {int64(8), "c_example_net", "8.3"}}

	healVhostsOnStartup()

	if got, want := s.renderedSockets(), []string{filepath.Join(s.sockets, "c_example_com.sock"), tenantSocket("c_example_net")}; !slices.Equal(got, want) {
		t.Errorf("rendered with sockets %v, want %v", got, want)
	}
	if data, err := os.ReadFile(s.sentinel); err != nil || string(data) != "done\n" {
		t.Errorf("the sentinel holds %q, %v; want done", data, err)
	}
	assertPathsKept(t, filepath.Join(phpMap["8.3"].PoolDir, "c_example_com.conf"))
	assertPathsGone(t, filepath.Join(phpMap["8.3"].PoolDir, "c_example_net.conf"))
}

func TestAHardeningSweepThatDoesNotFinishLeavesNoSentinel(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(s *hardeningSweep)
		sockets []string
	}{
		{"the domain list cannot be read", func(s *hardeningSweep) {
			s.script.fail[domainSweepQuery] = errors.New(lostConnectionTo)
		}, nil},
		{"a domain row cannot be read", func(s *hardeningSweep) {
			s.script.rows[domainSweepQuery] = [][]driver.Value{{nil, "c_example_com", "8.3"}}
		}, nil},
		{"the domain list is cut short", func(s *hardeningSweep) {
			s.script.endWith = map[string]error{domainSweepQuery: errors.New(lostConnectionTo)}
		}, nil},
		{"a pool cannot be rewritten", func(s *hardeningSweep) {
			delete(s.accounts, "c_example_com")
		}, []string{"/run/php-fpm/c_example_com.sock"}},
		{"a pool cannot be rewritten on a version that is not installed", func(s *hardeningSweep) {
			delete(s.accounts, "c_example_com")
			s.script.rows[domainSweepQuery] = [][]driver.Value{{int64(7), "c_example_com", "7.4"}}
		}, []string{"/run/php-fpm/c_example_com.sock"}},
		{"a vhost cannot be rendered", func(s *hardeningSweep) {
			s.capture.err = errors.New("nginx -t failed")
		}, []string{""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := withHardeningSweep(t)
			tc.prepare(s)
			if tc.sockets != nil && tc.sockets[0] == "" {
				tc.sockets = []string{filepath.Join(s.sockets, "c_example_com.sock")}
			}

			healVhostsOnStartup()

			assertPathsGone(t, s.sentinel)
			if got := s.renderedSockets(); !slices.Equal(got, tc.sockets) {
				t.Errorf("rendered with sockets %v, want %v", got, tc.sockets)
			}
		})
	}
}

func TestASweepSentinelThatCannotBeWrittenOnlyCostsAnotherSweep(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, s *hardeningSweep)
	}{
		{"its directory cannot be created", func(t *testing.T, s *hardeningSweep) {
			blocker := filepath.Join(t.TempDir(), "a-file")
			plantFile(t, blocker)
			s.sentinel = filepath.Join(blocker, "servika", ".vhost_hardening_v5_done")
			vhostHardenSentinel = s.sentinel
		}},
		{"the sentinel file cannot be written", func(t *testing.T, s *hardeningSweep) {
			if os.Geteuid() == 0 {
				t.Skip("root writes into a read-only directory")
			}
			dir := filepath.Dir(s.sentinel)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, 0o555); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := withHardeningSweep(t)
			tc.prepare(t, s)

			healVhostsOnStartup()

			if len(s.capture.opts) != 1 {
				t.Errorf("rendered %d times, want the one domain", len(s.capture.opts))
			}
			// Under a file the path reports "not a directory" rather than "not
			// found", so the check is only that nothing can be read there.
			if _, err := os.Stat(s.sentinel); err == nil {
				t.Error("the sentinel was written")
			}
		})
	}
}
