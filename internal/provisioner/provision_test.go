package provisioner

import (
	"database/sql/driver"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// Provision allocates a system user nobody else answers to, creates the Linux
// account and its home, hands the tree to the tenant, writes and validates the
// PHP-FPM pool and renders the first vhost. These tests run it against a
// temporary home root, a scripted database, a fake account table and recorded
// commands, and pin what it creates, what it runs and where each failure stops it.

const systemUserTakenQuery = "SELECT 1 FROM domains WHERE system_user=?"

// provisionFixture answers useradd by adding the account to accounts unless
// createsAccount is false, and fails a command whose name is a key of fail with
// that output.
type provisionFixture struct {
	homes          string
	pools          string
	sockets        string
	accounts       map[string]*user.User
	createsAccount bool
	fail           map[string]string
	chowned        []string
	script         *sqlScript
	capture        *renderCapture
	commands       *commandRecorder
}

func withProvisioning(t *testing.T) *provisionFixture {
	t.Helper()
	root := t.TempDir()
	f := &provisionFixture{
		homes:          withTenantHome(t),
		pools:          filepath.Join(root, "php-fpm.d"),
		sockets:        filepath.Join(root, "run"),
		accounts:       map[string]*user.User{"nginx": {Username: "nginx", Uid: "990", Gid: "990"}},
		createsAccount: true,
		fail:           map[string]string{},
		script:         &sqlScript{rows: map[string][][]driver.Value{systemUserTakenQuery: {}}},
	}
	withTenantUnits(t)
	withScript(t, f.script)
	setForTest(t, &phpMap, map[string]phpConfig{
		"8.3": {PoolDir: f.pools, SockDir: f.sockets, Service: "php-fpm", FPMBin: "/usr/sbin/php-fpm"},
	})
	withAccounts(t, f.accounts)
	setForTest(t, &lookPath, func(string) (string, error) { return "", exec.ErrNotFound })
	setForTest(t, &nginxAccount, "nginx")
	setForTest(t, &chown, func(path string, _, _ int) error {
		f.chowned = append(f.chowned, path)
		return nil
	})
	f.capture = withRenderCapture(t)
	f.commands = withCommandScript(t, f.respond)
	return f
}

func (f *provisionFixture) respond(argv []string) (string, int) {
	if argv[0] == "useradd" && f.createsAccount {
		name := argv[len(argv)-1]
		f.accounts[name] = &user.User{Username: name, Uid: "1500", Gid: "1500"}
	}
	if output, failing := f.fail[argv[0]]; failing {
		return output, 1
	}
	return "", 0
}

func TestAnInvalidDomainIsNotProvisioned(t *testing.T) {
	f := withProvisioning(t)

	if _, err := Provision("bad name", "8.3"); err == nil {
		t.Fatal("Provision() accepted an invalid domain")
	}
	if len(f.commands.argvs()) != 0 {
		t.Errorf("an invalid domain ran %q", f.commands.argvs())
	}
}

// Without the database the allocator cannot tell a free name from a taken one,
// and falling back to the bare slug is what handed two tenants one identity.
func TestProvisioningNeedsThePanelDatabase(t *testing.T) {
	withProvisioning(t)
	withoutDatabase(t)

	if _, err := Provision("example.com", "8.3"); err == nil || !strings.Contains(err.Error(), "the panel database is not wired up") {
		t.Fatalf("Provision() error = %v, want the missing database refusal", err)
	}
}

func TestAProvisionedDomainGetsAnAccountAHomeAPoolAndAVhost(t *testing.T) {
	f := withProvisioning(t)
	home := filepath.Join(f.homes, "c_example_com")

	result, err := Provision("example.com", "7.0")

	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	socket := filepath.Join(f.sockets, "c_example_com.sock")
	want := &Result{SystemUser: "c_example_com", WebRoot: PublicHTML("c_example_com"), FTPHost: "example.com", PHPVersion: "8.3", PHPSocket: socket}
	if !reflect.DeepEqual(result, want) {
		t.Errorf("Provision() = %+v, want %+v", result, want)
	}
	wantCommands := [][]string{
		{"useradd", "-m", "-d", home, "-s", "/usr/sbin/nologin", "c_example_com"},
		{"chown", "-R", "-h", "-P", "1500:990", filepath.Join(home, "public_html")},
		{"restorecon", "-R", home},
		{"/usr/sbin/php-fpm", "-t"},
		{"systemctl", "reload-or-restart", "php-fpm"},
	}
	if got := f.commands.argvs(); !reflect.DeepEqual(got, wantCommands) {
		t.Errorf("ran %q\nwant %q", got, wantCommands)
	}
	wantVhost := VhostOpts{DomainName: "example.com", WebRoot: PublicHTML("c_example_com"), PHPSocket: socket, PHPVersion: "8.3"}
	if len(f.capture.opts) != 1 || f.capture.opts[0] != wantVhost || f.capture.users[0] != "c_example_com" {
		t.Errorf("rendered %+v for %v, want %+v", f.capture.opts, f.capture.users, wantVhost)
	}
	assertProvisionedHome(t, f, home)
}

// assertProvisionedHome checks the tree Provision leaves behind: the five
// directories, the welcome page, the pool and ownership of what it created.
func assertProvisionedHome(t *testing.T, f *provisionFixture, home string) {
	t.Helper()
	for _, dir := range []string{"public_html", "logs", "tmp", "ssl", ".cron"} {
		if info, err := os.Stat(filepath.Join(home, dir)); err != nil || !info.IsDir() {
			t.Errorf("%s was not created: %v", dir, err)
		}
	}
	index := filepath.Join(home, "public_html", "index.html")
	if data, err := os.ReadFile(index); err != nil || string(data) != welcomeHTML("example.com") {
		t.Errorf("index.html holds %d bytes, %v; want the welcome page", len(data), err)
	}
	if data, err := os.ReadFile(filepath.Join(f.pools, "c_example_com.conf")); err != nil || !strings.Contains(string(data), "[c_example_com]") {
		t.Errorf("the pool holds %q, %v; want the tenant's pool", data, err)
	}
	if !slices.Contains(f.chowned, home) || !slices.Contains(f.chowned, index) {
		t.Errorf("handed %v to the tenant, want the home and the welcome page among them", f.chowned)
	}
}

// A candidate the host or the panel already answers to is skipped, so the new
// domain gets the next suffix instead of a second tenant's identity.
func TestATakenSystemUserMovesToTheNextSuffix(t *testing.T) {
	f := withProvisioning(t)
	f.accounts["c_example_com"] = &user.User{Username: "c_example_com", Uid: "1400", Gid: "1400"}

	result, err := Provision("example.com", "8.3")

	if err != nil || result.SystemUser != "c_example_com_2" {
		t.Fatalf("Provision() = %+v, %v; want c_example_com_2", result, err)
	}
	if !f.commands.ran("useradd", "-m", "-d", filepath.Join(f.homes, "c_example_com_2")) {
		t.Errorf("the account was not created under the suffixed name, ran %q", f.commands.argvs())
	}
}

// A home left behind by an earlier attempt is taken over: a file already in
// public_html is made readable to the web server rather than kept private.
func TestAFileAlreadyInTheDocumentRootBecomesReadable(t *testing.T) {
	f := withProvisioning(t)
	leftover := filepath.Join(f.homes, "c_example_com", "public_html", "index.php")
	plantFile(t, leftover)

	if _, err := Provision("example.com", "8.3"); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}

	if info, err := os.Stat(leftover); err != nil || info.Mode().Perm() != 0o644 {
		t.Errorf("the leftover file has mode %v, %v; want 0644", info.Mode().Perm(), err)
	}
}

// The directories are created best effort: a home that cannot be created does
// not stop the pool and the vhost, and Provision reports success.
func TestAHomeThatCannotBeCreatedDoesNotStopProvisioning(t *testing.T) {
	f := withProvisioning(t)
	plantFile(t, filepath.Join(f.homes, "c_example_com"))

	result, err := Provision("example.com", "8.3")

	if err != nil || result.SystemUser != "c_example_com" || len(f.capture.opts) != 1 {
		t.Fatalf("Provision() = %+v, %v with %d renders; want success", result, err, len(f.capture.opts))
	}
}

func TestUseraddReportingAnExistingAccountIsNotAFailure(t *testing.T) {
	f := withProvisioning(t)
	f.fail["useradd"] = "useradd: user 'c_example_com' already exists"

	if _, err := Provision("example.com", "8.3"); err != nil {
		t.Fatalf("Provision() error = %v, want the existing account accepted", err)
	}
}

func TestProvisioningStopsWhereItFails(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(f *provisionFixture)
		reason  string
	}{
		{"the system user cannot be allocated", func(f *provisionFixture) {
			f.script.fail = map[string]error{systemUserTakenQuery: errors.New(lostConnectionTo)}
		}, "allocate system user: " + lostConnectionTo},
		{"useradd fails", func(f *provisionFixture) {
			f.createsAccount = false
			f.fail["useradd"] = "useradd: cannot lock /etc/passwd"
		}, "useradd: useradd: cannot lock /etc/passwd"},
		{"the account never appears", func(f *provisionFixture) {
			f.createsAccount = false
		}, `php pool skipped: system user "c_example_com" does not exist`},
		{"php-fpm rejects the pool", func(f *provisionFixture) {
			f.fail["/usr/sbin/php-fpm"] = "ERROR: unable to parse"
		}, "php-fpm -t (8.3) failed, pool restored: ERROR: unable to parse"},
		{"php-fpm cannot be reloaded", func(f *provisionFixture) {
			f.fail["systemctl"] = "Job for php-fpm.service failed"
		}, "php-fpm (php-fpm) reload: Job for php-fpm.service failed"},
		{"the vhost cannot be rendered", func(f *provisionFixture) {
			f.capture.err = errors.New("nginx -t failed")
		}, "nginx -t failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withProvisioning(t)
			tc.prepare(f)

			result, err := Provision("example.com", "8.3")

			if err == nil || !strings.Contains(err.Error(), tc.reason) || result != nil {
				t.Fatalf("Provision() = %+v, %v; want no result and an error naming %q", result, err, tc.reason)
			}
		})
	}
}
