package subdomain

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// SetPHP rewrites the server block and only then updates the row, so nginx and
// the database cannot disagree about which pool the subdomain runs on. None of
// that host exists in a test, so seams.go carries the command runner, the two
// roots and the provisioner calls.

// setForTest replaces a package variable for one test.
func setForTest[T any](t *testing.T, target *T, value T) {
	t.Helper()
	previous := *target
	*target = value
	t.Cleanup(func() { *target = previous })
}

// hostTree points the tenant home and the nginx directory at temporary copies
// and returns both.
func hostTree(t *testing.T) (home, conf string) {
	t.Helper()
	root := t.TempDir()
	home = filepath.Join(root, "home")
	conf = filepath.Join(root, "conf.d")
	for _, dir := range []string{home, conf} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("create %s: %v", dir, err)
		}
	}
	setForTest(t, &tenantHomeRoot, home)
	setForTest(t, &nginxConfDir, conf)
	return home, conf
}

// commandHost answers the command seam and records what was run.
type commandHost struct {
	fail map[string]error
	out  map[string]string
	ran  []string
}

func (c *commandHost) install(t *testing.T) {
	t.Helper()
	answer := func(name string, args ...string) (string, error) {
		key := strings.Join(append([]string{name}, args...), " ")
		c.ran = append(c.ran, key)
		return c.out[key], c.fail[key]
	}
	setForTest(t, &runCommand, func(name string, args ...string) error {
		_, err := answer(name, args...)
		return err
	})
	setForTest(t, &commandOutput, func(name string, args ...string) ([]byte, error) {
		out, err := answer(name, args...)
		return []byte(out), err
	})
}

// noHostCalls installs the provisioner seams a test that never reaches the host
// still needs, so a refusal cannot pass by accident.
func noHostCalls(t *testing.T) {
	t.Helper()
	setForTest(t, &tenantFPMActive, func(string) bool { return false })
	setForTest(t, &protectedBlocks, func(*sql.DB, int64, int64, string) string { return "" })
	setForTest(t, &writeZone, func(context.Context, *sql.DB, int64) error { return nil })
}

// subdomainRequest carries both route parameters and a JSON body.
func subdomainRequest(t *testing.T, method string, domainID, subdomainID int64, body string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, "/domains/1/subdomain/2/php", strings.NewReader(body))
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("id", strconv.FormatInt(domainID, 10))
	routeCtx.URLParams.Add("sid", strconv.FormatInt(subdomainID, 10))
	return request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeCtx))
}

// oneSubdomain scripts the parent domain and the subdomain lookup both SetPHP
// and Delete open with.
func oneSubdomain(script *sqlScript, systemUser, domainName, parentPHP, name string) {
	parentDomain(script, systemUser, domainName, parentPHP)
	script.rows["FROM subdomains WHERE id=? AND domain_id=?"] = [][]driver.Value{
		{name, name + "." + domainName},
	}
}

// setPHP runs the handler and returns the recorder.
func setPHP(t *testing.T, handlers *Handlers, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	handlers.SetPHP(recorder, subdomainRequest(t, http.MethodPut, 4, 9, body))
	return recorder
}

// assertRefusal checks the status and the message a refusal answers with.
func assertRefusal(t *testing.T, recorder *httptest.ResponseRecorder, status int, message string) {
	t.Helper()
	if recorder.Code != status {
		t.Fatalf("status = %d, want %d (body %s)", recorder.Code, status, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), message) {
		t.Errorf("body = %s, want it to carry %q", recorder.Body, message)
	}
}

func TestSetPHPWritesTheVhostBeforeTheRow(t *testing.T) {
	_, conf := hostTree(t)
	noHostCalls(t)
	host := &commandHost{}
	host.install(t)
	setForTest(t, &applySubdomainFPM, func(*sql.DB, int64, int64, string, string, string) (string, error) {
		return "/run/php-fpm/c_acme-8.2.sock", nil
	})
	script := newScript()
	oneSubdomain(script, "c_acme", "acme.test", "8.3", "shop")
	handlers := &Handlers{DB: scriptDB(t, script)}

	recorder := setPHP(t, handlers, `{"php_version":"8.2"}`)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	written := readFileAt(t, filepath.Join(conf, "sub_c_acme_shop.conf"))
	if !strings.Contains(written, "/run/php-fpm/c_acme-8.2.sock") {
		t.Errorf("the server block does not carry the new socket:\n%s", written)
	}
	if !strings.Contains(written, "server_name shop.acme.test;") {
		t.Errorf("the server block is not the subdomain's:\n%s", written)
	}
	// Validated and reloaded, in that order, before the row is touched.
	if len(host.ran) < 2 || host.ran[len(host.ran)-2] != "nginx -t" ||
		host.ran[len(host.ran)-1] != "systemctl reload nginx" {
		t.Errorf("commands = %v, want the validation then the reload", host.ran)
	}
	args := execArgs(t, script, "UPDATE subdomains SET php_version=?")
	if args[0] != "8.2" || args[1] != int64(9) || args[2] != int64(4) {
		t.Errorf("update args = %v, want the version, the subdomain and its domain", args)
	}
}

// A configuration nginx refuses leaves the file as it was and the row alone: a
// site must not be left on a server block nginx will reject at the next reload.
func TestSetPHPPutsTheServerBlockBackWhenNginxRefuses(t *testing.T) {
	_, conf := hostTree(t)
	noHostCalls(t)
	const before = "# the block that was serving\n"
	path := filepath.Join(conf, "sub_c_acme_shop.conf")
	writeFileAt(t, path, before)
	host := &commandHost{fail: map[string]error{"nginx -t": errors.New("exit status 1")}}
	host.install(t)
	setForTest(t, &applySubdomainFPM, func(*sql.DB, int64, int64, string, string, string) (string, error) {
		return "/run/php-fpm/c_acme-8.2.sock", nil
	})
	script := newScript()
	oneSubdomain(script, "c_acme", "acme.test", "8.3", "shop")
	handlers := &Handlers{DB: scriptDB(t, script)}

	recorder := setPHP(t, handlers, `{"php_version":"8.2"}`)

	assertRefusal(t, recorder, http.StatusInternalServerError, "nginx rejected the configuration")
	if body := readFileAt(t, path); body != before {
		t.Errorf("file =\n%s\nwant it back as it was", body)
	}
	if len(script.execs) != 0 {
		t.Errorf("the row was updated anyway: %v", script.execs)
	}
}

// A certificate pair on disk means the site is served over HTTPS, and switching
// PHP must not drop it back to plain HTTP.
func TestSetPHPKeepsAnExistingCertificate(t *testing.T) {
	home, conf := hostTree(t)
	noHostCalls(t)
	host := &commandHost{}
	host.install(t)
	setForTest(t, &applySubdomainFPM, func(*sql.DB, int64, int64, string, string, string) (string, error) {
		return "/run/php-fpm/c_acme-8.2.sock", nil
	})
	sslDir := filepath.Join(home, "c_acme", "ssl")
	if err := os.MkdirAll(sslDir, 0o750); err != nil {
		t.Fatalf("create the certificate directory: %v", err)
	}
	writeFileAt(t, filepath.Join(sslDir, "shop.acme.test.crt"), "certificate")
	writeFileAt(t, filepath.Join(sslDir, "shop.acme.test.key"), "key")
	script := newScript()
	oneSubdomain(script, "c_acme", "acme.test", "8.3", "shop")
	handlers := &Handlers{DB: scriptDB(t, script)}

	recorder := setPHP(t, handlers, `{"php_version":"8.2"}`)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	written := readFileAt(t, filepath.Join(conf, "sub_c_acme_shop.conf"))
	if !strings.Contains(written, "listen 443 ssl") {
		t.Errorf("the HTTPS server block was dropped:\n%s", written)
	}
	if !strings.Contains(written, filepath.Join(sslDir, "shop.acme.test.crt")) {
		t.Errorf("the certificate is not the subdomain's:\n%s", written)
	}
}

// A pool the server cannot install is a refusal, and nothing is written.
func TestSetPHPRefusesAVersionThePoolCannotTake(t *testing.T) {
	_, conf := hostTree(t)
	noHostCalls(t)
	host := &commandHost{}
	host.install(t)
	setForTest(t, &applySubdomainFPM, func(*sql.DB, int64, int64, string, string, string) (string, error) {
		return "", errors.New("no such pool")
	})
	script := newScript()
	oneSubdomain(script, "c_acme", "acme.test", "8.3", "shop")
	handlers := &Handlers{DB: scriptDB(t, script)}

	recorder := setPHP(t, handlers, `{"php_version":"9.9"}`)

	assertRefusal(t, recorder, http.StatusBadRequest, "PHP version is not installed on the server")
	if entries, _ := os.ReadDir(conf); len(entries) != 0 {
		t.Errorf("a server block was written anyway: %v", entries)
	}
	if len(host.ran) != 0 {
		t.Errorf("commands = %v, want none", host.ran)
	}
}

// A tenant on its own FPM unit has ONE socket whatever version is asked for, so
// the answer is the refusal rather than a record the server does not serve.
func TestSetPHPRefusesAVersionTheTenantPoolCannotServe(t *testing.T) {
	hostTree(t)
	noHostCalls(t)
	setForTest(t, &tenantFPMActive, func(string) bool { return true })
	host := &commandHost{}
	host.install(t)
	script := newScript()
	oneSubdomain(script, "c_acme", "acme.test", "8.3", "shop")
	handlers := &Handlers{DB: scriptDB(t, script)}

	recorder := setPHP(t, handlers, `{"php_version":"8.2"}`)

	assertRefusal(t, recorder, http.StatusConflict, reasonPHPVersionLocked)
	if len(host.ran) != 0 {
		t.Errorf("commands = %v, want none", host.ran)
	}
}

// The row is the last step, and a failure there is reported rather than
// answered with a success the database does not carry.
func TestSetPHPReportsARowItCouldNotUpdate(t *testing.T) {
	hostTree(t)
	noHostCalls(t)
	host := &commandHost{}
	host.install(t)
	setForTest(t, &applySubdomainFPM, func(*sql.DB, int64, int64, string, string, string) (string, error) {
		return "/run/php-fpm/c_acme-8.2.sock", nil
	})
	script := newScript()
	oneSubdomain(script, "c_acme", "acme.test", "8.3", "shop")
	script.fail["UPDATE subdomains SET php_version=? WHERE id=? AND domain_id=?"] = errors.New("read only")
	handlers := &Handlers{DB: scriptDB(t, script)}

	assertRefusal(t, setPHP(t, handlers, `{"php_version":"8.2"}`),
		http.StatusInternalServerError, "could not update the record")
}

func TestSetPHPRefusesWhatItCannotResolve(t *testing.T) {
	cases := []struct {
		name    string
		script  func(*sqlScript)
		body    string
		status  int
		message string
	}{
		{
			name:    "a domain that is not there",
			script:  func(s *sqlScript) { s.rows["FROM domains WHERE id=?"] = nil },
			body:    `{"php_version":"8.2"}`,
			status:  http.StatusNotFound,
			message: "domain not found",
		},
		{
			name:    "a domain with no tenant account",
			script:  func(s *sqlScript) { parentDomain(s, "root", "acme.test", "8.3") },
			body:    `{"php_version":"8.2"}`,
			status:  http.StatusBadRequest,
			message: "invalid system user",
		},
		{
			name:    "a body that is not JSON",
			script:  func(s *sqlScript) { parentDomain(s, "c_acme", "acme.test", "8.3") },
			body:    `{`,
			status:  http.StatusBadRequest,
			message: "invalid request body",
		},
		{
			name: "a subdomain of another domain",
			script: func(s *sqlScript) {
				parentDomain(s, "c_acme", "acme.test", "8.3")
				s.rows["FROM subdomains WHERE id=? AND domain_id=?"] = nil
			},
			body:    `{"php_version":"8.2"}`,
			status:  http.StatusNotFound,
			message: "subdomain not found",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			hostTree(t)
			noHostCalls(t)
			host := &commandHost{}
			host.install(t)
			script := newScript()
			testCase.script(script)
			handlers := &Handlers{DB: scriptDB(t, script)}

			assertRefusal(t, setPHP(t, handlers, testCase.body), testCase.status, testCase.message)
			if len(host.ran) != 0 {
				t.Errorf("commands = %v, want none", host.ran)
			}
		})
	}
}

// execArgs returns the arguments of the one statement carrying fragment.
func execArgs(t *testing.T, script *sqlScript, fragment string) []driver.Value {
	t.Helper()
	for _, exec := range script.execs {
		if strings.Contains(exec.query, fragment) {
			return exec.args
		}
	}
	t.Fatalf("no statement carried %q: %v", fragment, script.execs)
	return nil
}

func readFileAt(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path) // #nosec G304 -- a path this test created.
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(body)
}

func writeFileAt(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
