package laravel

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	statusQuery      = "SELECT COALESCE(last_deploy_status,'') FROM cp_laravel_apps WHERE domain_id=?"
	baseRowInsert    = "INSERT INTO cp_laravel_apps(domain_id, app_root"
	installingUpdate = "SET last_deploy_status='installing'"
	statusUpdate     = "SET last_deploy_status=? WHERE domain_id=?"
	webRootUpdate    = "UPDATE domains SET web_root=?"
)

// hostCommands records the commands a handler runs on the host and fails the
// ones a test names by binary.
type hostCommands struct {
	lines []string
	fail  map[string]bool
}

func (h *hostCommands) command(name string, args ...string) *exec.Cmd {
	h.lines = append(h.lines, strings.Join(append([]string{name}, args...), " "))
	if h.fail[name] {
		return exec.Command("false")
	}
	return exec.Command("true")
}

// detachCall is one job handed to systemd-run.
type detachCall struct {
	systemUser string
	cwd        string
	unit       string
	logPath    string
	argv       []string
}

// hostFakes replaces every seam an install or deploy reaches on a real host.
type hostFakes struct {
	commands  hostCommands
	detached  []detachCall
	docroots  []string
	detachErr error
	gitURLErr error
	execOK    bool
	scriptDir string
}

// install puts the fakes in place for one test and returns them.
func (f *hostFakes) install(t *testing.T) *hostFakes {
	t.Helper()
	f.scriptDir = t.TempDir()
	setForTest(t, &runScriptDir, f.scriptDir)
	setForTest(t, &laravelCommand, f.commands.command)
	setForTest(t, &tenantExec, func(_ context.Context, _, _, _ string, _ ...string) (string, bool) {
		return "output", f.execOK
	})
	setForTest(t, &runDetached, func(systemUser, cwd, unit, logPath string, argv ...string) error {
		f.detached = append(f.detached, detachCall{systemUser: systemUser, cwd: cwd, unit: unit, logPath: logPath, argv: argv})
		return f.detachErr
	})
	setForTest(t, &checkGitURL, func(string) error { return f.gitURLErr })
	setForTest(t, &absoluteWebRoot, func(systemUser, subdirectory string) (string, error) {
		return "/home/" + systemUser + "/" + subdirectory, nil
	})
	setForTest(t, &rerenderVhost, func(_ *sql.DB, id int64) error {
		f.docroots = append(f.docroots, "vhost for domain "+string(rune('0'+id)))
		return nil
	})
	return f
}

// installScript answers the two reads an install makes before it writes.
func installScript() *sqlScript {
	s := newScript()
	s.rows[domainLookup] = [][]driver.Value{{"c_test", "8.3"}}
	s.rows[statusQuery] = [][]driver.Value{{"ready"}}
	return s
}

func serveInstall(t *testing.T, script *sqlScript, body string) *httptest.ResponseRecorder {
	t.Helper()
	handlers := &Handlers{DB: scriptDB(t, script)}
	recorder := httptest.NewRecorder()
	handlers.Install(recorder, laravelRequest(http.MethodPost, "/api/v1/domains/7/laravel/install", body))
	return recorder
}

func TestInstallRefusesBeforeItTouchesTheHost(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		script  func(s *sqlScript)
		fail    map[string]bool
		gitURL  error
		status  int
		want    string
		wantRun bool
	}{
		{name: "a domain that is not there", body: `{"mode":"scaffold"}`,
			script: func(s *sqlScript) { s.rows[domainLookup] = nil },
			status: http.StatusNotFound, want: "domain not found"},
		{name: "an install that is already running", body: `{"mode":"scaffold"}`,
			script: func(s *sqlScript) { s.rows[statusQuery] = [][]driver.Value{{"installing"}} },
			status: http.StatusConflict, want: "already running"},
		{name: "a deploy that is already running", body: `{"mode":"scaffold"}`,
			script: func(s *sqlScript) { s.rows[statusQuery] = [][]driver.Value{{"running"}} },
			status: http.StatusConflict, want: "already running"},
		{name: "a body that is not JSON", body: "{",
			status: http.StatusBadRequest, want: "invalid request body"},
		{name: "a mode the panel does not offer", body: `{"mode":"rsync"}`,
			status: http.StatusBadRequest, want: "invalid mode"},
		{name: "an application directory outside public_html", body: `{"mode":"scaffold","app_root":"etc"}`,
			status: http.StatusBadRequest, want: "invalid application directory"},
		{name: "a directory the tenant cannot create", body: `{"mode":"scaffold"}`,
			fail: map[string]bool{"runuser": true}, wantRun: true,
			status: http.StatusInternalServerError, want: "directory creation failed"},
		{name: "a record that cannot be written", body: `{"mode":"scaffold"}`,
			script:  func(s *sqlScript) { s.fail[baseRowInsert] = errScripted },
			wantRun: true, status: http.StatusInternalServerError, want: "could not initialize Laravel app record"},
		{name: "a repository URL with a shell character", body: `{"mode":"remote","repo_url":"https://h/x.git;id"}`,
			wantRun: true, status: http.StatusBadRequest, want: "invalid repository URL"},
		{name: "a repository host the guard refuses",
			body: `{"mode":"remote","repo_url":"https://127.0.0.1/x.git"}`, gitURL: errScripted,
			wantRun: true, status: http.StatusBadRequest, want: "the repository host is not allowed"},
		{name: "a branch name with a space",
			body:    `{"mode":"remote","repo_url":"https://github.com/laravel/laravel.git","branch":"my branch"}`,
			wantRun: true, status: http.StatusBadRequest, want: "invalid branch name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tenantHome(t)
			fakes := (&hostFakes{gitURLErr: tc.gitURL}).install(t)
			fakes.commands.fail = tc.fail
			script := installScript()
			if tc.script != nil {
				tc.script(script)
			}
			assertResponse(t, serveInstall(t, script, tc.body), tc.status, tc.want)
			if len(fakes.detached) != 0 {
				t.Errorf("a refused install started %d jobs", len(fakes.detached))
			}
		})
	}
}

// The local mode only creates an empty repository, and it records the outcome
// on the row the screen polls.
func TestInstallLocalRecordsWhatGitDid(t *testing.T) {
	for _, tc := range []struct {
		name   string
		gitOK  bool
		status string
	}{
		{name: "a repository git created", gitOK: true, status: "ready"},
		{name: "a repository git refused", status: "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tenantHome(t)
			fakes := (&hostFakes{execOK: tc.gitOK}).install(t)
			script := installScript()
			assertResponse(t, serveInstall(t, script, `{"mode":"local"}`), http.StatusOK, `"async":false`)
			assertLastWrite(t, script, statusUpdate, tc.status)
			if len(fakes.detached) != 0 {
				t.Errorf("the local mode started a detached job: %+v", fakes.detached)
			}
		})
	}
}

// assertLastWrite checks the first argument of the last statement holding
// fragment.
func assertLastWrite(t *testing.T, script *sqlScript, fragment string, want driver.Value) {
	t.Helper()
	script.mu.Lock()
	defer script.mu.Unlock()
	var last []driver.Value
	found := false
	for _, statement := range script.execs {
		if strings.Contains(statement.query, fragment) {
			last, found = statement.args, true
		}
	}
	if !found {
		t.Errorf("no statement held %q", fragment)
		return
	}
	if got := last[0]; got != want {
		t.Errorf("%q wrote %v, want %v", fragment, got, want)
	}
}

// An application that already carries a public directory gets the docroot moved
// onto it, because serving the project root exposes .env and vendor.
func TestInstallLocalMovesTheDocrootOntoPublic(t *testing.T) {
	_, publicHTML := tenantHome(t)
	if err := os.MkdirAll(filepath.Join(publicHTML, "public"), 0o750); err != nil {
		t.Fatal(err)
	}
	fakes := (&hostFakes{execOK: true}).install(t)
	script := installScript()
	assertResponse(t, serveInstall(t, script, `{"mode":"local"}`), http.StatusOK, `"ok":true`)
	assertLastWrite(t, script, webRootUpdate, "/home/c_test/public")
	if len(fakes.docroots) != 1 {
		t.Errorf("the vhost was rendered %d times, want once", len(fakes.docroots))
	}
}

// A docroot the panel cannot move is logged rather than failing an install that
// already created the repository the customer asked for.
func TestInstallLocalKeepsGoingWhenTheDocrootCannotMove(t *testing.T) {
	_, publicHTML := tenantHome(t)
	if err := os.MkdirAll(filepath.Join(publicHTML, "public"), 0o750); err != nil {
		t.Fatal(err)
	}
	fakes := (&hostFakes{execOK: true}).install(t)
	setForTest(t, &absoluteWebRoot, func(string, string) (string, error) { return "", errScripted })
	assertResponse(t, serveInstall(t, installScript(), `{"mode":"local"}`), http.StatusOK, `"ok":true`)
	if len(fakes.docroots) != 0 {
		t.Errorf("the vhost was rendered %d times, want none", len(fakes.docroots))
	}
}

// The remote and scaffold modes hand a script to systemd rather than running it
// in the request, and the script is what the tenant's shell will read.
func TestInstallStartsTheDetachedJobWithItsScript(t *testing.T) {
	for _, tc := range []struct {
		name     string
		body     string
		fragment string
	}{
		{name: "a repository to clone",
			body:     `{"mode":"remote","repo_url":"https://github.com/laravel/laravel.git","branch":"main"}`,
			fragment: "/usr/bin/git clone --depth 1 --branch 'main' -- 'https://github.com/laravel/laravel.git'"},
		{name: "a skeleton to create", body: `{"mode":"scaffold"}`,
			fragment: "create-project --no-interaction --prefer-dist"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tenantHome(t)
			fakes := (&hostFakes{}).install(t)
			assertResponse(t, serveInstall(t, installScript(), tc.body), http.StatusOK, `"unit":"servika-laravel-install-7"`)
			assertDetached(t, fakes, "servika-laravel-install-7", tc.fragment)
		})
	}
}

// assertDetached checks the one job a test started and the script it wrote.
func assertDetached(t *testing.T, fakes *hostFakes, unit, fragment string) {
	t.Helper()
	if len(fakes.detached) != 1 {
		t.Fatalf("%d jobs started, want one: %+v", len(fakes.detached), fakes.detached)
	}
	job := fakes.detached[0]
	if job.unit != unit || job.systemUser != "c_test" {
		t.Errorf("job = %+v, want unit %q for c_test", job, unit)
	}
	body, err := os.ReadFile(job.argv[len(job.argv)-1]) // #nosec G304 -- the script this test just wrote.
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), fragment) {
		t.Errorf("script =\n%s\nwant it to hold %q", body, fragment)
	}
}

// A job systemd refuses is reported rather than left as a started install.
func TestInstallReportsAJobSystemdRefused(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{name: "a skeleton", body: `{"mode":"scaffold"}`},
		// No branch is named, so the clone takes the default one.
		{name: "a clone", body: `{"mode":"remote","repo_url":"https://github.com/laravel/laravel.git"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tenantHome(t)
			(&hostFakes{detachErr: errScripted}).install(t)
			assertResponse(t, serveInstall(t, installScript(), tc.body),
				http.StatusInternalServerError, "install start failed")
		})
	}
}

func TestFinalizeInstallOnlyMovesAStoppedJob(t *testing.T) {
	cases := []struct {
		name       string
		unitState  string
		recStatus  string
		withArtisa bool
		script     func(s *sqlScript)
		want       string
		writes     int
	}{
		{name: "a unit that is still running", unitState: "active", recStatus: "installing",
			want: "installing"},
		{name: "a record that is not installing", unitState: "inactive", recStatus: "ready", want: "ready"},
		{name: "an install that produced no artisan", unitState: "inactive", recStatus: "installing",
			want: "failed", writes: 1},
		{name: "an install that produced an application", unitState: "inactive", recStatus: "installing",
			withArtisa: true, want: "ready", writes: 1},
		{name: "a row that cannot be written", unitState: "failed", recStatus: "installing",
			script: func(s *sqlScript) { s.fail[statusUpdate] = errScripted }, want: "installing", writes: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, publicHTML := tenantHome(t)
			if tc.withArtisa {
				writeArtisan(t, publicHTML)
				// A finished install with a public directory also moves the
				// docroot onto it.
				if err := os.MkdirAll(filepath.Join(publicHTML, "public"), 0o750); err != nil {
					t.Fatal(err)
				}
			}
			(&hostFakes{}).install(t)
			setForTest(t, &readUnitStatus, func(string) string { return tc.unitState })
			script := installScript()
			if tc.script != nil {
				tc.script(script)
			}
			handlers := &Handlers{DB: scriptDB(t, script)}
			rec := handlers.finalizeInstall(context.Background(), 7, "c_test",
				record{AppRoot: "public_html", LastDeployStatus: tc.recStatus})
			if rec.LastDeployStatus != tc.want {
				t.Errorf("status = %q, want %q", rec.LastDeployStatus, tc.want)
			}
			assertWriteCount(t, script, statusUpdate, tc.writes)
		})
	}
}

// A docroot the panel cannot move at the end of an install is logged; the
// install itself is finished and its status is already written.
func TestFinalizeInstallLogsADocrootItCannotMove(t *testing.T) {
	_, publicHTML := tenantHome(t)
	writeArtisan(t, publicHTML)
	if err := os.MkdirAll(filepath.Join(publicHTML, "public"), 0o750); err != nil {
		t.Fatal(err)
	}
	fakes := (&hostFakes{}).install(t)
	setForTest(t, &readUnitStatus, func(string) string { return "inactive" })
	setForTest(t, &absoluteWebRoot, func(string, string) (string, error) { return "", errScripted })
	handlers := &Handlers{DB: scriptDB(t, installScript())}
	rec := handlers.finalizeInstall(context.Background(), 7, "c_test",
		record{AppRoot: "public_html", LastDeployStatus: "installing"})
	if rec.LastDeployStatus != "ready" {
		t.Errorf("status = %q, want ready", rec.LastDeployStatus)
	}
	if len(fakes.docroots) != 0 {
		t.Errorf("the vhost was rendered %d times, want none", len(fakes.docroots))
	}
}

// writeArtisan makes the directory look like an installed Laravel application.
func writeArtisan(t *testing.T, publicHTML string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(publicHTML, "artisan"), []byte("#!/usr/bin/env php\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The winner of the conditional update is the one that cleans up, so the unit
// is reset and the generated script leaves the host.
func TestFinalizeInstallCleansUpAfterTheJobItFinished(t *testing.T) {
	_, publicHTML := tenantHome(t)
	writeArtisan(t, publicHTML)
	fakes := (&hostFakes{}).install(t)
	setForTest(t, &readUnitStatus, func(string) string { return "inactive" })
	scriptPath := filepath.Join(fakes.scriptDir, "servika-laravel-install-7.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/bash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	handlers := &Handlers{DB: scriptDB(t, installScript())}
	handlers.finalizeInstall(context.Background(), 7, "c_test",
		record{AppRoot: "public_html", LastDeployStatus: "installing"})
	if want := "systemctl reset-failed servika-laravel-install-7.service"; !strings.Contains(strings.Join(fakes.commands.lines, "\n"), want) {
		t.Errorf("commands = %q, want %q", fakes.commands.lines, want)
	}
	if _, err := os.Stat(scriptPath); !os.IsNotExist(err) {
		t.Errorf("the generated script is still there: %v", err)
	}
}
