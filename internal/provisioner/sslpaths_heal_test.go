package provisioner

import (
	"database/sql/driver"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
)

// HealSSLCertPathsOnStartup moves a certificate that still lives in a tenant home
// into root-owned storage, re-renders the vhost from the new paths, repoints the
// database and only then removes the home copy. A row that fails any check is
// skipped with its home copy intact. These tests pin the move and every point at
// which a row is left where it is.

const homeCertificateQuery = "cert_path LIKE '/home/%'"

type certPathsFixture struct {
	homes    string
	certs    string
	homeCert string
	homeKey  string
	accounts map[string]*user.User
	script   *sqlScript
	capture  *renderCapture
}

func withCertPathHeal(t *testing.T) *certPathsFixture {
	t.Helper()
	uid := strconv.Itoa(os.Getuid())
	f := &certPathsFixture{
		homes:    withTenantHome(t),
		certs:    certRoot(t),
		accounts: map[string]*user.User{"c_example_com": {Username: "c_example_com", Uid: uid, Gid: uid}},
	}
	f.homeCert = filepath.Join(f.homes, "c_example_com", "ssl", "example.com.crt")
	f.homeKey = filepath.Join(f.homes, "c_example_com", "ssl", "example.com.key")
	plantFile(t, f.homeCert)
	plantFile(t, f.homeKey)
	withTenantUnits(t)
	setForTest(t, &chown, func(string, int, int) error { return nil })
	setForTest(t, &fileChown, func(*os.File, int, int) error { return nil })
	withAccounts(t, f.accounts)
	withCommands(t)
	f.capture = withRenderCapture(t)
	f.script = vhostScript(domainDetails("example.com", "c_example_com", f.homeCert, f.homeKey, "custom", "php-fpm", "", 0, 0, "", nil))
	f.script.rows[homeCertificateQuery] = [][]driver.Value{f.row("example.com", "c_example_com", "8.3", f.homeCert, f.homeKey)}
	withScript(t, f.script)
	return f
}

func (f *certPathsFixture) row(domain, systemUser, phpVersion, certPath, keyPath string) []driver.Value {
	return []driver.Value{int64(7), domain, systemUser, phpVersion, certPath, keyPath}
}

func (f *certPathsFixture) systemPaths() (string, string) {
	dir := filepath.Join(f.certs, "example.com")
	return filepath.Join(dir, "example.com.crt"), filepath.Join(dir, "example.com.key")
}

func TestAHomeCertificateMovesIntoSystemStorage(t *testing.T) {
	f := withCertPathHeal(t)

	HealSSLCertPathsOnStartup()

	newCert, newKey := f.systemPaths()
	assertImportedFile(t, newCert, []byte("planted\n"), 0o644)
	assertImportedFile(t, newKey, []byte("planted\n"), 0o600)
	if len(f.capture.opts) != 1 || f.capture.opts[0].CertPath != newCert || f.capture.opts[0].KeyPath != newKey {
		t.Errorf("rendered %+v, want one render from the moved paths", f.capture.opts)
	}
	if want := []driver.Value{newCert, newKey, int64(7)}; len(f.script.execs) != 1 || !reflect.DeepEqual(f.script.execs[0].args, want) {
		t.Errorf("database writes = %+v, want the row repointed to %v", f.script.execs, want)
	}
	assertPathsGone(t, f.homeCert, f.homeKey)
}

func TestACertificateThatCannotBeMovedStaysInTheHome(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, f *certPathsFixture)
		renders int
	}{
		{"the row cannot be read", func(_ *testing.T, f *certPathsFixture) {
			row := f.row("example.com", "c_example_com", "8.3", f.homeCert, f.homeKey)
			row[0] = nil
			f.script.rows[homeCertificateQuery] = [][]driver.Value{row}
		}, 0},
		{"the domain is not valid", func(_ *testing.T, f *certPathsFixture) {
			f.script.rows[homeCertificateQuery] = [][]driver.Value{f.row("bad name", "c_example_com", "8.3", f.homeCert, f.homeKey)}
		}, 0},
		{"the tenant is not valid", func(_ *testing.T, f *certPathsFixture) {
			f.script.rows[homeCertificateQuery] = [][]driver.Value{f.row("example.com", "root", "8.3", f.homeCert, f.homeKey)}
		}, 0},
		{"the stored paths are not the tenant's own", func(_ *testing.T, f *certPathsFixture) {
			elsewhere := filepath.Join(f.homes, "c_example_com", "public_html", "example.com.crt")
			f.script.rows[homeCertificateQuery] = [][]driver.Value{f.row("example.com", "c_example_com", "8.3", elsewhere, f.homeKey)}
		}, 0},
		{"the tenant account is unknown", func(_ *testing.T, f *certPathsFixture) {
			delete(f.accounts, "c_example_com")
		}, 0},
		{"the certificate directory cannot be created", func(t *testing.T, _ *certPathsFixture) {
			blocker := filepath.Join(t.TempDir(), "a-file")
			plantFile(t, blocker)
			t.Setenv("SERVIKA_CERT_ROOT", filepath.Join(blocker, "certs"))
		}, 0},
		{"the certificate does not belong to the tenant", func(_ *testing.T, f *certPathsFixture) {
			other := strconv.Itoa(os.Getuid() + 1)
			f.accounts["c_example_com"] = &user.User{Username: "c_example_com", Uid: other, Gid: other}
		}, 0},
		{"the key is missing", func(t *testing.T, f *certPathsFixture) {
			if err := os.Remove(f.homeKey); err != nil {
				t.Fatal(err)
			}
		}, 0},
		{"the PHP socket cannot be resolved", func(_ *testing.T, f *certPathsFixture) {
			f.script.rows[homeCertificateQuery] = [][]driver.Value{f.row("example.com", "c_example_com", "7.4", f.homeCert, f.homeKey)}
		}, 0},
		{"the vhost cannot be rendered", func(_ *testing.T, f *certPathsFixture) {
			f.capture.err = errors.New("nginx -t failed")
		}, 1},
		{"the database cannot be repointed", func(_ *testing.T, f *certPathsFixture) {
			f.script.fail[certRepointQuery] = errors.New(lostConnectionTo)
		}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withCertPathHeal(t)
			tc.prepare(t, f)

			HealSSLCertPathsOnStartup()

			assertPathsKept(t, f.homeCert)
			if len(f.capture.opts) != tc.renders {
				t.Errorf("rendered %d times, want %d", len(f.capture.opts), tc.renders)
			}
		})
	}
}

// A certificate list that ends in a lost connection still moves the rows that
// arrived before it.
func TestACertificateListCutShortStillMovesWhatArrived(t *testing.T) {
	f := withCertPathHeal(t)
	f.script.endWith = map[string]error{homeCertificateQuery: errors.New(lostConnectionTo)}

	HealSSLCertPathsOnStartup()

	assertPathsGone(t, f.homeCert, f.homeKey)
}

func TestNoCertificateMovesWithoutTheCertificateList(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, f *certPathsFixture)
	}{
		{"the query fails", func(_ *testing.T, f *certPathsFixture) {
			f.script.fail[homeCertificateQuery] = errors.New(lostConnectionTo)
		}},
		{"there is no database", func(t *testing.T, _ *certPathsFixture) { withoutDatabase(t) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withCertPathHeal(t)
			tc.prepare(t, f)

			HealSSLCertPathsOnStartup()

			assertPathsKept(t, f.homeCert, f.homeKey)
			if len(f.capture.opts) != 0 {
				t.Errorf("rendered %+v without a certificate list", f.capture.opts)
			}
		})
	}
}
