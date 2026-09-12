package subdomain

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Create and Delete write and remove a document root through the safeio
// primitives, which resolve every component with openat2 and exist on Linux
// only. These cases therefore build against Linux; the plan runs them in a
// golang container.

// createRequest posts a subdomain body to the parent domain.
func createRequest(t *testing.T, domainID int64, body string) *http.Request {
	t.Helper()
	return subdomainRequest(t, http.MethodPost, domainID, 0, body)
}

// tenantAccount scripts the parent domain, the empty banned-domain list every
// create reads, and the tenant home the document root is created in.
func tenantAccount(t *testing.T, script *sqlScript, systemUser, domainName string) string {
	t.Helper()
	parentDomain(script, systemUser, domainName, "8.3")
	script.rows["FROM banned_domains"] = nil
	home := filepath.Join(tenantHomeRoot, systemUser)
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatalf("create the tenant home: %v", err)
	}
	return home
}

// hostForCreate installs every seam a create reaches past its refusals.
func hostForCreate(t *testing.T, socket string) *commandHost {
	t.Helper()
	noHostCalls(t)
	host := &commandHost{}
	host.install(t)
	setForTest(t, &phpSocketFor, func(string, string) (string, error) { return socket, nil })
	setForTest(t, &applySubdomainFPM, func(*sql.DB, int64, int64, string, string, string) (string, error) {
		return socket, nil
	})
	setForTest(t, &reRenderSubdomain, func(*sql.DB, int64) error { return nil })
	return host
}

func TestCreateBuildsTheDocumentRootAndPublishesTheServerBlock(t *testing.T) {
	home, conf := hostTree(t)
	script := newScript()
	tenantAccount(t, script, "c_acme", "acme.test")
	host := hostForCreate(t, "/run/php-fpm/c_acme-8.3.sock")
	handlers := &Handlers{DB: scriptDB(t, script), IPv4: "203.0.113.7"}

	recorder := httptest.NewRecorder()
	handlers.Create(recorder, createRequest(t, 4, `{"subdomain":"Shop "}`))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	// The name is lowercased and trimmed before it becomes a host name.
	docroot := filepath.Join(home, "c_acme", "subdomains", "shop.acme.test")
	assertCreateAnswer(t, recorder, "shop.acme.test", docroot)
	assertLandingPage(t, docroot, "shop.acme.test")

	assertServerBlock(t, filepath.Join(conf, "sub_c_acme_shop.conf"),
		"server_name shop.acme.test;", "/run/php-fpm/c_acme-8.3.sock")
	if !ranCommand(host, "nginx -t") || !ranCommand(host, "systemctl reload nginx") {
		t.Errorf("commands = %v, want the validation and the reload", host.ran)
	}
	args := execArgs(t, script, "INSERT INTO subdomains")
	if args[1] != "shop" || args[2] != "shop.acme.test" || args[3] != "8.3" {
		t.Errorf("insert args = %v, want the name, the fqdn and the parent version", args)
	}
	// The A record follows the subdomain into the parent zone.
	dnsArgs := execArgs(t, script, "INSERT INTO dns_records")
	if dnsArgs[1] != "shop" || dnsArgs[2] != "A" || dnsArgs[3] != "203.0.113.7" {
		t.Errorf("dns args = %v, want the subdomain A record", dnsArgs)
	}
}

// assertServerBlock checks that the published file carries each fragment.
func assertServerBlock(t *testing.T, path string, fragments ...string) {
	t.Helper()
	written := readFileAt(t, path)
	for _, fragment := range fragments {
		if !strings.Contains(written, fragment) {
			t.Errorf("the server block does not carry %q:\n%s", fragment, written)
		}
	}
}

// assertCreateAnswer checks the two values the interface builds its next
// request from.
func assertCreateAnswer(t *testing.T, recorder *httptest.ResponseRecorder, fqdn, docroot string) {
	t.Helper()
	var answer struct {
		OK      bool   `json:"ok"`
		FQDN    string `json:"fqdn"`
		DocRoot string `json:"docroot"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatalf("decode the answer: %v", err)
	}
	if answer.FQDN != fqdn {
		t.Errorf("fqdn = %q, want %q", answer.FQDN, fqdn)
	}
	if answer.DocRoot != docroot {
		t.Errorf("docroot = %q, want %q", answer.DocRoot, docroot)
	}
}

// assertLandingPage checks that the document root exists and carries the
// subdomain's own welcome page.
func assertLandingPage(t *testing.T, docroot, fqdn string) {
	t.Helper()
	if info, err := os.Stat(docroot); err != nil || !info.IsDir() {
		t.Fatalf("the document root was not created: %v", err)
	}
	if body := readFileAt(t, filepath.Join(docroot, "index.html")); !strings.Contains(body, fqdn) {
		t.Errorf("the landing page is not the subdomain's:\n%s", body)
	}
}

// A panel with no address of its own writes no A record, rather than one
// pointing nowhere.
func TestCreateWithoutAnAddressWritesNoRecord(t *testing.T) {
	hostTree(t)
	script := newScript()
	tenantAccount(t, script, "c_acme", "acme.test")
	hostForCreate(t, "/run/php-fpm/c_acme-8.3.sock")
	handlers := &Handlers{DB: scriptDB(t, script)}

	recorder := httptest.NewRecorder()
	handlers.Create(recorder, createRequest(t, 4, `{"subdomain":"shop"}`))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	for _, statement := range script.execs {
		if strings.Contains(statement.query, "dns_records") {
			t.Errorf("a DNS record was written with no address: %v", statement)
		}
	}
}

// nginx refusing the new block leaves nothing behind: the file is removed and
// the row is never written, so the tenant can create the same name again.
func TestCreateRemovesTheServerBlockNginxRefused(t *testing.T) {
	_, conf := hostTree(t)
	script := newScript()
	tenantAccount(t, script, "c_acme", "acme.test")
	host := hostForCreate(t, "/run/php-fpm/c_acme-8.3.sock")
	host.fail = map[string]error{"nginx -t": errors.New("exit status 1")}
	handlers := &Handlers{DB: scriptDB(t, script)}

	recorder := httptest.NewRecorder()
	handlers.Create(recorder, createRequest(t, 4, `{"subdomain":"shop"}`))

	assertRefusal(t, recorder, http.StatusInternalServerError, "operation failed")
	if _, err := os.Stat(filepath.Join(conf, "sub_c_acme_shop.conf")); !os.IsNotExist(err) {
		t.Errorf("the refused server block is still there: %v", err)
	}
	if len(script.execs) != 0 {
		t.Errorf("a row was written for a refused subdomain: %v", script.execs)
	}
}

// A block nginx validated but would not load is removed rather than reported
// as a working subdomain: it is valid on disk and not live, which is the state
// nothing later contradicts.
func TestCreateRemovesTheServerBlockNginxWouldNotLoad(t *testing.T) {
	_, conf := hostTree(t)
	script := newScript()
	tenantAccount(t, script, "c_acme", "acme.test")
	host := hostForCreate(t, "/run/php-fpm/c_acme-8.3.sock")
	host.fail = map[string]error{"systemctl reload nginx": errors.New("exit status 1")}
	handlers := &Handlers{DB: scriptDB(t, script)}

	recorder := httptest.NewRecorder()
	handlers.Create(recorder, createRequest(t, 4, `{"subdomain":"shop"}`))

	assertRefusal(t, recorder, http.StatusInternalServerError, "nginx reload failed")
	if _, err := os.Stat(filepath.Join(conf, "sub_c_acme_shop.conf")); !os.IsNotExist(err) {
		t.Errorf("the server block that never went live is still there: %v", err)
	}
	if len(script.execs) != 0 {
		t.Errorf("a row was written for a subdomain that is not live: %v", script.execs)
	}
}

// A row that cannot be written takes the published server block back out, or
// nginx would serve a subdomain the panel does not know about.
func TestCreateWithdrawsTheServerBlockWhenTheRowFails(t *testing.T) {
	_, conf := hostTree(t)
	script := newScript()
	tenantAccount(t, script, "c_acme", "acme.test")
	script.fail["INSERT INTO subdomains"] = errors.New("duplicate key")
	host := hostForCreate(t, "/run/php-fpm/c_acme-8.3.sock")
	handlers := &Handlers{DB: scriptDB(t, script)}

	recorder := httptest.NewRecorder()
	handlers.Create(recorder, createRequest(t, 4, `{"subdomain":"shop"}`))

	assertRefusal(t, recorder, http.StatusInternalServerError, "could not add record")
	if _, err := os.Stat(filepath.Join(conf, "sub_c_acme_shop.conf")); !os.IsNotExist(err) {
		t.Errorf("the server block outlived the failed insert: %v", err)
	}
	if !ranCommand(host, "systemctl reload nginx") {
		t.Errorf("nginx was not reloaded after the withdrawal: %v", host.ran)
	}
}

func TestCreateRefusesWhatItMustNotBuild(t *testing.T) {
	cases := []struct {
		name    string
		script  func(*testing.T, *sqlScript)
		body    string
		status  int
		message string
	}{
		{
			name:    "a domain that is not there",
			script:  func(_ *testing.T, s *sqlScript) { s.rows["FROM domains WHERE id=?"] = nil },
			body:    `{"subdomain":"shop"}`,
			status:  http.StatusNotFound,
			message: "domain not found",
		},
		{
			name: "a domain with no tenant account",
			script: func(t *testing.T, s *sqlScript) {
				tenantAccount(t, s, "root", "acme.test")
			},
			body:    `{"subdomain":"shop"}`,
			status:  http.StatusBadRequest,
			message: "invalid user",
		},
		{
			name:    "a body that is not JSON",
			script:  func(t *testing.T, s *sqlScript) { tenantAccount(t, s, "c_acme", "acme.test") },
			body:    `{`,
			status:  http.StatusBadRequest,
			message: "invalid request body",
		},
		{
			name:    "a name that is not a label",
			script:  func(t *testing.T, s *sqlScript) { tenantAccount(t, s, "c_acme", "acme.test") },
			body:    `{"subdomain":"shop.evil"}`,
			status:  http.StatusBadRequest,
			message: "invalid subdomain",
		},
		{
			name:    "a name that starts with a hyphen",
			script:  func(t *testing.T, s *sqlScript) { tenantAccount(t, s, "c_acme", "acme.test") },
			body:    `{"subdomain":"-shop"}`,
			status:  http.StatusBadRequest,
			message: "invalid subdomain",
		},
		{
			name: "a name another subdomain already carries",
			script: func(t *testing.T, s *sqlScript) {
				tenantAccount(t, s, "c_acme", "acme.test")
				s.rows["FROM subdomains WHERE fqdn=?"] = [][]driver.Value{{int64(1)}}
			},
			body:    `{"subdomain":"shop"}`,
			status:  http.StatusConflict,
			message: "already in use",
		},
		{
			name: "a name a domain already carries",
			script: func(t *testing.T, s *sqlScript) {
				tenantAccount(t, s, "c_acme", "acme.test")
				s.rows["FROM subdomains WHERE fqdn=?"] = [][]driver.Value{{int64(0)}}
				s.rows["FROM domains WHERE domain_name=?"] = [][]driver.Value{{int64(1)}}
			},
			body:    `{"subdomain":"shop"}`,
			status:  http.StatusConflict,
			message: "already in use",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			hostTree(t)
			host := hostForCreate(t, "/run/php-fpm/c_acme-8.3.sock")
			script := newScript()
			testCase.script(t, script)
			handlers := &Handlers{DB: scriptDB(t, script)}

			recorder := httptest.NewRecorder()
			handlers.Create(recorder, createRequest(t, 4, testCase.body))

			assertRefusal(t, recorder, testCase.status, testCase.message)
			if len(host.ran) != 0 {
				t.Errorf("commands = %v, want none", host.ran)
			}
			if len(script.execs) != 0 {
				t.Errorf("a row was written for a refusal: %v", script.execs)
			}
		})
	}
}

// A PHP version the server does not carry is refused before anything is built.
func TestCreateRefusesAVersionTheServerDoesNotCarry(t *testing.T) {
	home, _ := hostTree(t)
	script := newScript()
	tenantAccount(t, script, "c_acme", "acme.test")
	hostForCreate(t, "")
	setForTest(t, &phpSocketFor, func(string, string) (string, error) {
		return "", errors.New("no such pool")
	})
	handlers := &Handlers{DB: scriptDB(t, script)}

	recorder := httptest.NewRecorder()
	handlers.Create(recorder, createRequest(t, 4, `{"subdomain":"shop","php_version":"9.9"}`))

	assertRefusal(t, recorder, http.StatusBadRequest, "PHP version is not installed on the server: 9.9")
	if _, err := os.Stat(filepath.Join(home, "c_acme", "subdomains")); !os.IsNotExist(err) {
		t.Errorf("a document root was built for a refused version: %v", err)
	}
}

// A tenant on its own FPM unit serves every subdomain from one socket, so a
// version other than the parent's is refused rather than recorded.
func TestCreateRefusesAVersionTheTenantPoolCannotServe(t *testing.T) {
	home, _ := hostTree(t)
	script := newScript()
	tenantAccount(t, script, "c_acme", "acme.test")
	hostForCreate(t, "/run/php-fpm/c_acme.sock")
	setForTest(t, &tenantFPMActive, func(string) bool { return true })
	handlers := &Handlers{DB: scriptDB(t, script)}

	recorder := httptest.NewRecorder()
	handlers.Create(recorder, createRequest(t, 4, `{"subdomain":"shop","php_version":"8.2"}`))

	assertRefusal(t, recorder, http.StatusConflict, reasonPHPVersionLocked)
	if _, err := os.Stat(filepath.Join(home, "c_acme", "subdomains")); !os.IsNotExist(err) {
		t.Errorf("a document root was built for a refused version: %v", err)
	}
}

// A document root that cannot be created stops the create: openat2 refuses a
// tenant home that is not there, and a subdomain with no root serves nothing.
func TestCreateReportsADocumentRootItCannotBuild(t *testing.T) {
	hostTree(t)
	script := newScript()
	// No tenant home is created, so the safeio call has nothing to resolve
	// beneath.
	parentDomain(script, "c_acme", "acme.test", "8.3")
	script.rows["FROM banned_domains"] = nil
	host := hostForCreate(t, "/run/php-fpm/c_acme-8.3.sock")
	handlers := &Handlers{DB: scriptDB(t, script)}

	recorder := httptest.NewRecorder()
	handlers.Create(recorder, createRequest(t, 4, `{"subdomain":"shop"}`))

	assertRefusal(t, recorder, http.StatusInternalServerError, "could not create document root")
	if len(host.ran) != 0 {
		t.Errorf("commands = %v, want none", host.ran)
	}
	if len(script.execs) != 0 {
		t.Errorf("a row was written with no document root: %v", script.execs)
	}
}

// The dedicated pool is installed after the insert, and a failure there is NOT
// fatal: the subdomain already serves PHP through the parent pool, so the loss
// of its own pool is logged and the create still succeeds.
func TestCreateKeepsTheSubdomainWhenItsOwnPoolFails(t *testing.T) {
	hostTree(t)
	script := newScript()
	script.insertID = 12
	tenantAccount(t, script, "c_acme", "acme.test")
	hostForCreate(t, "/run/php-fpm/c_acme-8.3.sock")
	setForTest(t, &applySubdomainFPM, func(*sql.DB, int64, int64, string, string, string) (string, error) {
		return "", errors.New("the pool would not start")
	})
	handlers := &Handlers{DB: scriptDB(t, script)}

	recorder := httptest.NewRecorder()
	handlers.Create(recorder, createRequest(t, 4, `{"subdomain":"shop"}`))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	execArgs(t, script, "INSERT INTO subdomains")
}

// The re-render that follows the pool is the same: a failure leaves the
// subdomain on the parent socket rather than deleting a working site.
func TestCreateKeepsTheSubdomainWhenTheReRenderFails(t *testing.T) {
	hostTree(t)
	script := newScript()
	script.insertID = 12
	tenantAccount(t, script, "c_acme", "acme.test")
	hostForCreate(t, "/run/php-fpm/c_acme-8.3.sock")
	setForTest(t, &reRenderSubdomain, func(*sql.DB, int64) error {
		return errors.New("nginx refused the re-render")
	})
	handlers := &Handlers{DB: scriptDB(t, script)}

	recorder := httptest.NewRecorder()
	handlers.Create(recorder, createRequest(t, 4, `{"subdomain":"shop"}`))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	execArgs(t, script, "INSERT INTO subdomains")
}

// Delete takes the record out first, so a database failure aborts before the
// filesystem is touched and no row is left pointing at a removed vhost.
func TestDeleteRemovesTheRecordThenEverythingItBuilt(t *testing.T) {
	home, conf := hostTree(t)
	noHostCalls(t)
	host := &commandHost{}
	host.install(t)
	var removedFPM string
	setForTest(t, &removeSubdomainFPM, func(systemUser string, _ int64) { removedFPM = systemUser })
	var zoneWritten bool
	setForTest(t, &writeZone, func(context.Context, *sql.DB, int64) error {
		zoneWritten = true
		return nil
	})
	script := newScript()
	oneSubdomain(script, "c_acme", "acme.test", "8.3", "shop")

	docroot := filepath.Join(home, "c_acme", "subdomains", "shop.acme.test")
	if err := os.MkdirAll(docroot, 0o750); err != nil {
		t.Fatalf("create the document root: %v", err)
	}
	writeFileAt(t, filepath.Join(docroot, "index.html"), "the site")
	sslDir := filepath.Join(home, "c_acme", "ssl")
	if err := os.MkdirAll(sslDir, 0o750); err != nil {
		t.Fatalf("create the certificate directory: %v", err)
	}
	writeFileAt(t, filepath.Join(sslDir, "shop.acme.test.crt"), "certificate")
	writeFileAt(t, filepath.Join(sslDir, "shop.acme.test.key"), "key")
	confFile := filepath.Join(conf, "sub_c_acme_shop.conf")
	writeFileAt(t, confFile, "server {}")

	recorder := httptest.NewRecorder()
	handlers := &Handlers{DB: scriptDB(t, script)}
	handlers.Delete(recorder, subdomainRequest(t, http.MethodDelete, 4, 9, ""))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	for _, fragment := range []string{
		"DELETE FROM subdomains", "DELETE FROM php_settings",
		"DELETE FROM nginx_settings", "DELETE FROM dns_records",
	} {
		execArgs(t, script, fragment)
	}
	if removedFPM != "c_acme" {
		t.Errorf("the pool of %q was removed, want the tenant's", removedFPM)
	}
	for _, path := range []string{
		confFile, docroot,
		filepath.Join(sslDir, "shop.acme.test.crt"),
		filepath.Join(sslDir, "shop.acme.test.key"),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s outlived the subdomain: %v", path, err)
		}
	}
	if !zoneWritten {
		t.Error("the parent zone was not rewritten")
	}
}

// A record that cannot be deleted stops the whole removal: the document root
// stays, because a row pointing at nothing is worse than a subdomain that is
// still there.
func TestDeleteTouchesNothingWhenTheRecordSurvives(t *testing.T) {
	home, conf := hostTree(t)
	noHostCalls(t)
	host := &commandHost{}
	host.install(t)
	script := newScript()
	oneSubdomain(script, "c_acme", "acme.test", "8.3", "shop")
	script.fail["DELETE FROM subdomains WHERE id=? AND domain_id=?"] = errors.New("read only")

	docroot := filepath.Join(home, "c_acme", "subdomains", "shop.acme.test")
	if err := os.MkdirAll(docroot, 0o750); err != nil {
		t.Fatalf("create the document root: %v", err)
	}
	confFile := filepath.Join(conf, "sub_c_acme_shop.conf")
	writeFileAt(t, confFile, "server {}")

	recorder := httptest.NewRecorder()
	handlers := &Handlers{DB: scriptDB(t, script)}
	handlers.Delete(recorder, subdomainRequest(t, http.MethodDelete, 4, 9, ""))

	assertRefusal(t, recorder, http.StatusInternalServerError, "could not delete subdomain")
	if _, err := os.Stat(docroot); err != nil {
		t.Errorf("the document root was removed anyway: %v", err)
	}
	if _, err := os.Stat(confFile); err != nil {
		t.Errorf("the server block was removed anyway: %v", err)
	}
	if len(host.ran) != 0 {
		t.Errorf("commands = %v, want none", host.ran)
	}
}

// Once the record is gone the removal continues through every failure: the
// subdomain no longer exists, and stopping halfway would leave a document root
// and a zone nobody can reach through the panel.
func TestDeleteFinishesThroughEveryFailureAfterTheRecord(t *testing.T) {
	home, conf := hostTree(t)
	noHostCalls(t)
	host := &commandHost{}
	host.install(t)
	setForTest(t, &removeSubdomainFPM, func(string, int64) {})
	setForTest(t, &writeZone, func(context.Context, *sql.DB, int64) error {
		return errors.New("named refused the zone")
	})
	script := newScript()
	oneSubdomain(script, "c_acme", "acme.test", "8.3", "shop")
	for _, statement := range []string{
		"DELETE FROM php_settings WHERE domain_id=? AND subdomain_id=?",
		"DELETE FROM nginx_settings WHERE domain_id=? AND subdomain_id=?",
		"DELETE FROM dns_records WHERE domain_id=? AND name=? AND type='A'",
	} {
		script.fail[statement] = errors.New("read only")
	}
	// Nothing was ever built, so every removal below also has nothing to remove.
	if err := os.MkdirAll(filepath.Join(home, "c_acme"), 0o750); err != nil {
		t.Fatalf("create the tenant home: %v", err)
	}
	confFile := filepath.Join(conf, "sub_c_acme_shop.conf")
	writeFileAt(t, confFile, "server {}")

	recorder := httptest.NewRecorder()
	handlers := &Handlers{DB: scriptDB(t, script)}
	handlers.Delete(recorder, subdomainRequest(t, http.MethodDelete, 4, 9, ""))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	if _, err := os.Stat(confFile); !os.IsNotExist(err) {
		t.Errorf("the server block outlived the subdomain: %v", err)
	}
}

func TestDeleteRefusesWhatItCannotResolve(t *testing.T) {
	cases := []struct {
		name    string
		script  func(*sqlScript)
		status  int
		message string
	}{
		{
			name:    "a domain that is not there",
			script:  func(s *sqlScript) { s.rows["FROM domains WHERE id=?"] = nil },
			status:  http.StatusNotFound,
			message: "domain not found",
		},
		{
			name:    "a domain with no tenant account",
			script:  func(s *sqlScript) { parentDomain(s, "root", "acme.test", "8.3") },
			status:  http.StatusBadRequest,
			message: "invalid user",
		},
		{
			name: "a subdomain of another domain",
			script: func(s *sqlScript) {
				parentDomain(s, "c_acme", "acme.test", "8.3")
				s.rows["FROM subdomains WHERE id=? AND domain_id=?"] = nil
			},
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

			recorder := httptest.NewRecorder()
			handlers := &Handlers{DB: scriptDB(t, script)}
			handlers.Delete(recorder, subdomainRequest(t, http.MethodDelete, 4, 9, ""))

			assertRefusal(t, recorder, testCase.status, testCase.message)
			if len(script.execs) != 0 {
				t.Errorf("a row was deleted for a refusal: %v", script.execs)
			}
			if len(host.ran) != 0 {
				t.Errorf("commands = %v, want none", host.ran)
			}
		})
	}
}

// ranCommand reports whether the host was asked to run a command.
func ranCommand(host *commandHost, command string) bool {
	for _, ran := range host.ran {
		if ran == command {
			return true
		}
	}
	return false
}
