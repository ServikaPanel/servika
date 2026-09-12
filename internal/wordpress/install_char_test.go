package wordpress

import (
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

// installResponse is the body a completed install returns.
type installResponse struct {
	OK            bool   `json:"ok"`
	SiteURL       string `json:"site_url"`
	AdminURL      string `json:"admin_url"`
	AdminUser     string `json:"admin_user"`
	AdminPassword string `json:"admin_password"`
	Version       string `json:"version"`
	DBName        string `json:"db_name"`
}

// installBody is the request body the install endpoint takes.
const installBody = `{"sub_dir":"blog","site_title":"Site","admin_user":"admin","admin_email":"a@b.co"}`

// runInstall drives the install endpoint against a scripted database.
func runInstall(t *testing.T, s *sqlScript, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := &Handlers{DB: scriptDB(t, s)}
	recorder := httptest.NewRecorder()
	h.Install(recorder, wpRequest(http.MethodPost, "/domains/1/wordpress", body))
	return recorder
}

func TestInstallRefusesARequestItCannotAct(t *testing.T) {
	tenantRoot(t)
	recordWP(t, nil)
	recordHost(t)

	refusals := []struct {
		name     string
		user     string
		body     string
		status   int
		fragment string
	}{
		{"an unknown domain", "", installBody, http.StatusNotFound, "domain not found"},
		{"a domain with no tenant user", "root", installBody, http.StatusBadRequest, "invalid user"},
		{"a body that is not JSON", "c_test", "{", http.StatusBadRequest, "invalid request body"},
		{"an empty site title", "c_test", `{"site_title":"","admin_user":"admin","admin_email":"a@b.co"}`,
			http.StatusBadRequest, "site title is required"},
		{"a site title over the limit", "c_test",
			`{"site_title":"` + strings.Repeat("x", 121) + `","admin_user":"admin","admin_email":"a@b.co"}`,
			http.StatusBadRequest, "site title is required"},
		{"an administrator name with a space", "c_test",
			`{"site_title":"Site","admin_user":"ad min","admin_email":"a@b.co"}`,
			http.StatusBadRequest, "invalid administrator username"},
		{"an address with no domain part", "c_test",
			`{"site_title":"Site","admin_user":"admin","admin_email":"a@b"}`,
			http.StatusBadRequest, "invalid email address"},
		{"a subdirectory with an upper-case letter", "c_test",
			`{"sub_dir":"Blog","site_title":"Site","admin_user":"admin","admin_email":"a@b.co"}`,
			http.StatusBadRequest, "invalid subdirectory"},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			s := newScript()
			if tc.user != "" {
				s = domainScript(tc.user)
			} else {
				s.rows[domainLookup] = [][]driver.Value{}
			}
			assertStatus(t, runInstall(t, s, tc.body), tc.status, tc.fragment)
		})
	}
}

func TestInstallRefusesADirectoryItWouldOverwrite(t *testing.T) {
	root := tenantRoot(t)
	recordWP(t, nil)
	recordHost(t)
	if err := os.MkdirAll(filepath.Join(root, "blog"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "blog", "index.php"), []byte("<?php"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "blog", "app.php"), []byte("<?php"), 0o600); err != nil {
		t.Fatal(err)
	}

	assertStatus(t, runInstall(t, adminDomain(domainScript("c_test")), installBody),
		http.StatusConflict, "Target directory already contains content")
}

func TestInstallRefusesASecondInstallIntoTheSameDirectory(t *testing.T) {
	root := tenantRoot(t)
	recordWP(t, nil)
	recordHost(t)
	target := filepath.Join(root, "blog")
	wpInstallLock.Store(target, true)
	t.Cleanup(func() { wpInstallLock.Delete(target) })

	assertStatus(t, runInstall(t, adminDomain(domainScript("c_test")), installBody),
		http.StatusConflict, "already in progress")
}

// The subdirectory is created before anything else is done, and a document
// root that is a file rather than a directory stops the install there.
func TestInstallReportsATargetDirectoryItCouldNotCreate(t *testing.T) {
	root := tenantRoot(t)
	recordWP(t, nil)
	host := recordHost(t)
	if err := os.WriteFile(filepath.Join(root, "blog"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	assertStatus(t, runInstall(t, adminDomain(domainScript("c_test")), installBody),
		http.StatusInternalServerError, "could not create target directory")
	if len(host.created) != 0 {
		t.Fatalf("a database was created for a directory that does not exist: %v", host.created)
	}
}

func TestInstallReportsThePlanDatabaseLimit(t *testing.T) {
	tenantRoot(t)
	recordWP(t, nil)
	host := recordHost(t)
	s := domainScript("c_test")
	s.rows[customerLookup] = [][]driver.Value{{int64(7)}}
	s.rows[planLookup] = [][]driver.Value{{int64(3)}}
	s.rows[maxDBLookup] = [][]driver.Value{{int64(2)}}
	s.rows[dbCountLookup] = [][]driver.Value{{int64(2)}}

	assertStatus(t, runInstall(t, s, installBody), http.StatusForbidden, "maximum 2 databases")
	if len(host.created) != 0 {
		t.Fatalf("a database was created past the plan limit: %v", host.created)
	}
}

func TestInstallReportsADatabaseItCouldNotCreate(t *testing.T) {
	tenantRoot(t)
	recordWP(t, nil)
	host := recordHost(t)
	host.createErr = errors.New("mysql is down")

	assertStatus(t, runInstall(t, adminDomain(domainScript("c_test")), installBody),
		http.StatusInternalServerError, "operation failed")
}

// Every stage failure must take the database and the directory back out, so a
// second attempt is not blocked by what the first one left behind.
func TestInstallUndoesWhatItBuiltWhenAStageFails(t *testing.T) {
	stages := []struct {
		name     string
		answers  map[string]wpAnswer
		fragment string
	}{
		{"the core download fails", map[string]wpAnswer{
			"core download": {out: "Error: could not reach wordpress.org", err: errors.New("exit 1")}},
			"WordPress download failed: Error: could not reach wordpress.org"},
		{"wp-config creation fails", map[string]wpAnswer{
			"config create": {out: "Error: cannot write wp-config.php", err: errors.New("exit 1")}},
			"wp-config creation failed: Error: cannot write wp-config.php"},
		{"the database password did not reach wp-config.php", map[string]wpAnswer{
			"config get": {out: ""}},
			"the database password was not stored in wp-config.php"},
		{"the install command fails", map[string]wpAnswer{
			"core install": {out: "Error: database connection refused", err: errors.New("exit 1")}},
			"WordPress installation failed: Error: database connection refused"},
		{"the administrator password does not work", map[string]wpAnswer{
			"eval check-password": {out: "MISMATCH"}},
			"the administrator account was not created with the generated password"},
	}
	for _, tc := range stages {
		t.Run(tc.name, func(t *testing.T) {
			root := tenantRoot(t)
			recordWP(t, tc.answers)
			host := recordHost(t)

			assertStatus(t, runInstall(t, adminDomain(domainScript("c_test")), installBody),
				http.StatusInternalServerError, tc.fragment)
			if len(host.dropped) != 1 || !strings.HasPrefix(host.dropped[0], "wp_") {
				t.Errorf("dropped = %v, want the install's own database", host.dropped)
			}
			if want := filepath.Join(root, "blog"); len(host.removed) != 1 || host.removed[0] != want {
				t.Errorf("removed = %v, want %q", host.removed, want)
			}
		})
	}
}

// A failure in the document root itself must NOT delete the root: only a
// subdirectory this request created is removed.
func TestInstallLeavesTheDocumentRootInPlaceWhenItFails(t *testing.T) {
	tenantRoot(t)
	recordWP(t, map[string]wpAnswer{
		"core download": {out: "Error: no space left", err: errors.New("exit 1")}})
	host := recordHost(t)
	body := `{"site_title":"Site","admin_user":"admin","admin_email":"a@b.co"}`

	assertStatus(t, runInstall(t, adminDomain(domainScript("c_test")), body),
		http.StatusInternalServerError, "WordPress download failed")
	if len(host.removed) != 0 {
		t.Fatalf("the document root was removed: %v", host.removed)
	}
}

// The error body carries the last 600 characters of wp-cli's output, so a long
// failure does not push a whole log into the response.
func TestInstallTruncatesALongFailureToItsTail(t *testing.T) {
	tenantRoot(t)
	recordWP(t, map[string]wpAnswer{
		"core download": {out: strings.Repeat("a", 700) + "TAIL", err: errors.New("exit 1")}})
	recordHost(t)

	recorder := runInstall(t, adminDomain(domainScript("c_test")), installBody)
	body := recorder.Body.String()
	if !strings.Contains(body, "TAIL") {
		t.Fatalf("the tail of the output is missing: %s", body)
	}
	if strings.Count(body, "a") > 620 {
		t.Fatalf("the whole output was returned: %d characters", len(body))
	}
}

func TestInstallRunsTheWholeSequenceAndReportsTheCredentials(t *testing.T) {
	root := tenantRoot(t)
	rec := recordWP(t, map[string]wpAnswer{"core version": {out: "7.1\n"}})
	host := recordHost(t)

	recorder := runInstall(t, adminDomain(domainScript("c_test")), installBody)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", recorder.Code, recorder.Body.String())
	}
	var got installResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode the response: %v", err)
	}
	assertInstallResponse(t, got, rec)
	if len(host.created) != 1 || host.created[0] != got.DBName {
		t.Errorf("created = %v, want the reported database", host.created)
	}
	if len(host.dropped) != 0 || len(host.removed) != 0 {
		t.Errorf("a successful install rolled something back: dropped=%v removed=%v", host.dropped, host.removed)
	}

	target := filepath.Join(root, "blog")
	if _, err := os.Stat(target); err != nil {
		t.Errorf("the target directory was not created: %v", err)
	}
	assertInstallSequence(t, rec, target, got.DBName)
	if argv := host.argvOf("chown"); !equalStrings(argv, []string{"chown", "-R", "c_test:c_test", target}) {
		t.Errorf("chown argv = %v", argv)
	}
	if argv := host.argvOf("restorecon"); !equalStrings(argv, []string{"restorecon", "-R", target}) {
		t.Errorf("restorecon argv = %v", argv)
	}
}

// assertInstallResponse checks the body a completed install returns.
func assertInstallResponse(t *testing.T, got installResponse, rec *wpRecorder) {
	t.Helper()
	if !got.OK || got.SiteURL != "http://example.com/blog" || got.AdminURL != "http://example.com/blog/wp-admin" {
		t.Errorf("response = %+v, want the site under the subdirectory", got)
	}
	if got.AdminUser != "admin" || got.Version != "7.1" {
		t.Errorf("response = %+v, want the requested administrator and the installed version", got)
	}
	if got.AdminPassword != rec.adminPass {
		t.Errorf("admin_password = %q, want the password that went in on stdin (%q)", got.AdminPassword, rec.adminPass)
	}
	if !strings.HasPrefix(got.DBName, "wp_") || len(got.DBName) != 11 {
		t.Errorf("db_name = %q, want wp_ and eight hexadecimal characters", got.DBName)
	}
}

// assertInstallSequence checks the wp-cli calls an install makes, in order.
func assertInstallSequence(t *testing.T, rec *wpRecorder, target, dbName string) {
	t.Helper()
	wantOrder := []string{"core download", "config create", "config get", "core install",
		"eval check-password", "core version"}
	if got := rec.keys(); !equalStrings(got, wantOrder) {
		t.Errorf("wp-cli calls = %v, want %v", got, wantOrder)
	}
	assertArgvHolds(t, rec.argvFor("core download"), "core", "download", "--path="+target, "--locale=en_US")
	assertArgvHolds(t, rec.argvFor("config create"), "--dbname="+dbName, "--dbuser=wpu_"+dbName[3:],
		"--dbhost=localhost", "--skip-check", "--quiet", "--prompt=dbpass")
	assertArgvHolds(t, rec.argvFor("core install"), "--url=http://example.com/blog", "--title=Site",
		"--admin_user=admin", "--admin_email=a@b.co", "--skip-email", "--quiet", "--prompt=admin_password")
}

// The generated secrets must not reach argv, where every other account on the
// host can read them out of /proc/<pid>/cmdline.
func TestInstallKeepsEverySecretOffTheCommandLine(t *testing.T) {
	tenantRoot(t)
	rec := recordWP(t, nil)
	recordHost(t)

	if code := runInstall(t, adminDomain(domainScript("c_test")), installBody).Code; code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	for _, call := range rec.calls {
		for _, arg := range call.args {
			if rec.dbPass != "" && strings.Contains(arg, rec.dbPass) {
				t.Fatalf("the database password is in argv: %q", arg)
			}
			if rec.adminPass != "" && strings.Contains(arg, rec.adminPass) {
				t.Fatalf("the administrator password is in argv: %q", arg)
			}
		}
	}
}
