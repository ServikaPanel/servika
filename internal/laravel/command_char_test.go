package laravel

import (
	"context"
	"database/sql/driver"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

const (
	domainLookup      = "SELECT system_user, COALESCE(php_version,'8.3') FROM domains WHERE id=?"
	appRecord         = "SELECT app_root, deploy_mode"
	maintenanceUpdate = "UPDATE cp_laravel_apps SET maintenance=?"
)

// laravelRequest builds a request whose chi route carries domain 7.
func laravelRequest(method, target, body string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("id", "7")
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, routeCtx))
}

func assertResponse(t *testing.T, recorder *httptest.ResponseRecorder, status int, fragment string) {
	t.Helper()
	if recorder.Code != status {
		t.Errorf("status = %d, want %d (body %s)", recorder.Code, status, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), fragment) {
		t.Errorf("body = %s, want it to hold %q", recorder.Body.String(), fragment)
	}
}

// execCall is one command the handler ran as the tenant.
type execCall struct {
	systemUser string
	dir        string
	bin        string
	args       []string
	env        []string
}

// tenantRunner stands in for the two tenant execution seams and records what
// each handler would have run.
type tenantRunner struct {
	calls  []execCall
	output string
	ok     bool
}

func (r *tenantRunner) exec(_ context.Context, systemUser, cwd, bin string, args ...string) (string, bool) {
	r.calls = append(r.calls, execCall{systemUser: systemUser, dir: cwd, bin: bin, args: args})
	return r.output, r.ok
}

func (r *tenantRunner) execEnv(_ context.Context, systemUser, cwd string, env []string, bin string, args ...string) (string, bool) {
	r.calls = append(r.calls, execCall{systemUser: systemUser, dir: cwd, bin: bin, args: args, env: env})
	return r.output, r.ok
}

// install replaces both execution seams for one test.
func (r *tenantRunner) install(t *testing.T) *tenantRunner {
	t.Helper()
	r.output, r.ok = "done", true
	setForTest(t, &tenantExec, r.exec)
	setForTest(t, &tenantExecWithEnv, r.execEnv)
	return r
}

// commandScript answers the two lookups a command handler makes for domain 7.
func commandScript() *sqlScript {
	s := newScript()
	s.rows[domainLookup] = [][]driver.Value{{"c_test", "8.3"}}
	s.rows[appRecord] = [][]driver.Value{
		{"public_html", "remote", "8.3", "", int64(0), int64(0), "", "ready"},
	}
	return s
}

// commandCase is one request against a command handler.
type commandCase struct {
	name     string
	body     string
	script   func(s *sqlScript)
	status   int
	want     string
	wantArgs []string
}

// runCommand serves one request and returns the recorder with the runner.
func runCommand(t *testing.T, tc commandCase, serve func(*Handlers, http.ResponseWriter, *http.Request)) {
	t.Helper()
	script := commandScript()
	if tc.script != nil {
		tc.script(script)
	}
	runner := (&tenantRunner{}).install(t)
	handlers := &Handlers{DB: scriptDB(t, script)}
	recorder := httptest.NewRecorder()
	serve(handlers, recorder, laravelRequest(http.MethodPost, "/api/v1/domains/7/laravel", tc.body))
	assertResponse(t, recorder, tc.status, tc.want)
	assertRanWith(t, runner, tc.wantArgs)
}

// assertRanWith checks the arguments of the single tenant command a case
// expects, or that no command ran at all.
func assertRanWith(t *testing.T, runner *tenantRunner, want []string) {
	t.Helper()
	if want == nil {
		if len(runner.calls) != 0 {
			t.Errorf("%d commands ran, want none: %+v", len(runner.calls), runner.calls)
		}
		return
	}
	if len(runner.calls) != 1 {
		t.Fatalf("%d commands ran, want one: %+v", len(runner.calls), runner.calls)
	}
	if !reflect.DeepEqual(runner.calls[0].args, want) {
		t.Errorf("arguments = %q, want %q", runner.calls[0].args, want)
	}
}

// outsidePublicHTML answers with a record whose application directory the
// tenant may not run anything in.
func outsidePublicHTML(s *sqlScript) {
	s.rows[appRecord] = [][]driver.Value{{"etc", "remote", "8.3", "", int64(0), int64(0), "", "ready"}}
}

func TestArtisanOnlyRunsACommandFromItsOwnList(t *testing.T) {
	cases := []commandCase{
		{name: "a domain that is not there", body: `{"command":"migrate"}`,
			script: func(s *sqlScript) { s.rows[domainLookup] = nil },
			status: http.StatusNotFound, want: "domain not found"},
		{name: "a body that is not JSON", body: "{", status: http.StatusBadRequest, want: "invalid request body"},
		{name: "an empty command", body: `{"command":"   "}`,
			status: http.StatusBadRequest, want: "command is required"},
		{name: "a command that is not offered", body: `{"command":"tinker"}`,
			status: http.StatusBadRequest, want: "artisan command is not allowed"},
		{name: "an argument the shell would read", body: `{"command":"migrate --path=$(id)"}`,
			status: http.StatusBadRequest, want: "invalid argument"},
		{name: "an application directory outside public_html", body: `{"command":"migrate"}`,
			script: outsidePublicHTML, status: http.StatusBadRequest, want: "invalid application directory"},
		{name: "a command with an argument", body: `{"command":"migrate --force"}`,
			status: http.StatusOK, want: `"command":"artisan migrate --force"`,
			wantArgs: []string{"artisan", "migrate", "--no-interaction", "--force"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tenantHome(t)
			runCommand(t, tc, (*Handlers).Artisan)
		})
	}
}

// Taking the site down and bringing it up is the one artisan command that also
// changes a row, and only when the file on disk does not already say so.
func TestArtisanRecordsMaintenanceOnlyWhenItChanges(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command string
		writes  int
	}{
		{name: "taking the site down", command: "down", writes: 1},
		{name: "bringing a site up that is not down", command: "up"},
		{name: "a command that is not about maintenance", command: "migrate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tenantHome(t)
			script := commandScript()
			(&tenantRunner{}).install(t)
			handlers := &Handlers{DB: scriptDB(t, script)}
			recorder := httptest.NewRecorder()
			handlers.Artisan(recorder, laravelRequest(http.MethodPost, "/x", `{"command":"`+tc.command+`"}`))
			assertResponse(t, recorder, http.StatusOK, `"ok":true`)
			assertWriteCount(t, script, maintenanceUpdate, tc.writes)
		})
	}
}

// assertWriteCount counts the recorded statements holding fragment.
func assertWriteCount(t *testing.T, script *sqlScript, fragment string, want int) {
	t.Helper()
	script.mu.Lock()
	defer script.mu.Unlock()
	got := 0
	for _, statement := range script.execs {
		if strings.Contains(statement.query, fragment) {
			got++
		}
	}
	if got != want {
		t.Errorf("%d statements held %q, want %d", got, fragment, want)
	}
}

func TestComposerRefusesWhatItCannotRun(t *testing.T) {
	composerAt := func(t *testing.T, exists bool) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "composer.phar")
		if exists {
			if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		setForTest(t, &composerBinPath, func() string { return path })
	}
	cases := []struct {
		commandCase
		installed bool
	}{
		{installed: false, commandCase: commandCase{name: "a host with no composer", body: `{"command":"install"}`,
			status: http.StatusServiceUnavailable, want: "composer is not installed"}},
		{installed: true, commandCase: commandCase{name: "a domain that is not there", body: `{"command":"install"}`,
			script: func(s *sqlScript) { s.rows[domainLookup] = nil },
			status: http.StatusNotFound, want: "domain not found"}},
		{installed: true, commandCase: commandCase{name: "a body that is not JSON", body: "{",
			status: http.StatusBadRequest, want: "invalid request body"}},
		{installed: true, commandCase: commandCase{name: "a command that is not offered", body: `{"command":"exec"}`,
			status: http.StatusBadRequest, want: "composer command is not allowed"}},
		{installed: true, commandCase: commandCase{name: "a package name that is not one",
			body:   `{"command":"require","package":"laravel/horizon; id"}`,
			status: http.StatusBadRequest, want: "invalid package name"}},
		{installed: true, commandCase: commandCase{name: "an application directory outside public_html",
			body:   `{"command":"install"}`,
			script: outsidePublicHTML,
			status: http.StatusBadRequest, want: "invalid application directory"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tenantHome(t)
			composerAt(t, tc.installed)
			runCommand(t, tc.commandCase, (*Handlers).Composer)
		})
	}
}

// The composer argument list is what reaches the tenant shell, so each command
// shape is pinned as it is built.
func TestComposerBuildsTheArgumentListItRuns(t *testing.T) {
	composer := filepath.Join(t.TempDir(), "composer.phar")
	if err := os.WriteFile(composer, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		body string
		tail []string
	}{
		{name: "an install", body: `{"command":"install"}`, tail: []string{"--prefer-dist"}},
		{name: "an update", body: `{"command":"update"}`, tail: []string{"--prefer-dist"}},
		{name: "a package to add", body: `{"command":"require","package":"laravel/horizon"}`,
			tail: []string{"laravel/horizon"}},
		{name: "a dump", body: `{"command":"dump-autoload"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, publicHTML := tenantHome(t)
			setForTest(t, &composerBinPath, func() string { return composer })
			runner := (&tenantRunner{}).install(t)
			handlers := &Handlers{DB: scriptDB(t, commandScript())}
			recorder := httptest.NewRecorder()
			handlers.Composer(recorder, laravelRequest(http.MethodPost, "/x", tc.body))
			assertResponse(t, recorder, http.StatusOK, `"ok":true`)
			want := append([]string{composer, commandOf(tc.body), "--no-interaction", "--no-ansi", "-d", publicHTML}, tc.tail...)
			assertRanWith(t, runner, want)
		})
	}
}

// commandOf reads the command name out of a request body, so a case states it
// once.
func commandOf(body string) string {
	_, rest, _ := strings.Cut(body, `"command":"`)
	name, _, _ := strings.Cut(rest, `"`)
	return name
}

func TestNpmRefusesWhatItCannotRun(t *testing.T) {
	cases := []struct {
		commandCase
		installed bool
	}{
		{installed: true, commandCase: commandCase{name: "a domain that is not there", body: `{"command":"install"}`,
			script: func(s *sqlScript) { s.rows[domainLookup] = nil },
			status: http.StatusNotFound, want: "domain not found"}},
		{installed: true, commandCase: commandCase{name: "a body that is not JSON", body: "{",
			status: http.StatusBadRequest, want: "invalid request body"}},
		{installed: true, commandCase: commandCase{name: "a command that is not offered", body: `{"command":"publish"}`,
			status: http.StatusBadRequest, want: "npm command is not allowed"}},
		{installed: true, commandCase: commandCase{name: "a node version that is not one",
			body:   `{"command":"install","node_version":"22; id"}`,
			status: http.StatusBadRequest, want: "invalid node version"}},
		{installed: false, commandCase: commandCase{name: "a host with no npm", body: `{"command":"install"}`,
			status: http.StatusServiceUnavailable, want: "node or npm is not installed"}},
		{installed: true, commandCase: commandCase{name: "a script name that is not one",
			body:   `{"command":"run","script":"build; id"}`,
			status: http.StatusBadRequest, want: "invalid script name"}},
		{installed: true, commandCase: commandCase{name: "an application directory outside public_html",
			body:   `{"command":"install"}`,
			script: outsidePublicHTML,
			status: http.StatusBadRequest, want: "invalid application directory"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tenantHome(t)
			nodeBinAt(t, tc.installed)
			runCommand(t, tc.commandCase, (*Handlers).Npm)
		})
	}
}

// nodeBinAt points the node seam at a temporary directory, with or without the
// npm binary in it.
func nodeBinAt(t *testing.T, installed bool) string {
	t.Helper()
	binDir := t.TempDir()
	if installed {
		if err := os.WriteFile(filepath.Join(binDir, "npm"), []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	setForTest(t, &nodeBinDirFor, func(string) string { return binDir })
	return binDir
}

// npm runs with the chosen node directory in front of the system PATH, or a
// build runs against whichever node the host happens to answer with first.
func TestNpmRunsAgainstTheChosenNodeDirectory(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		args func(appDir string) []string
	}{
		{name: "an install", body: `{"command":"install"}`,
			args: func(appDir string) []string {
				return []string{"install", "--prefix", appDir, "--no-fund", "--no-audit"}
			}},
		{name: "an install that skips the package scripts", body: `{"command":"install","ignore_scripts":true}`,
			args: func(appDir string) []string {
				return []string{"install", "--prefix", appDir, "--no-fund", "--no-audit", "--ignore-scripts"}
			}},
		{name: "a script", body: `{"command":"run","script":"build"}`,
			args: func(appDir string) []string { return []string{"run", "build", "--prefix", appDir} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, publicHTML := tenantHome(t)
			binDir := nodeBinAt(t, true)
			runner := (&tenantRunner{}).install(t)
			handlers := &Handlers{DB: scriptDB(t, commandScript())}
			recorder := httptest.NewRecorder()
			handlers.Npm(recorder, laravelRequest(http.MethodPost, "/x", tc.body))
			assertResponse(t, recorder, http.StatusOK, `"node_dir":"`+binDir+`"`)
			assertRanWith(t, runner, tc.args(publicHTML))
			assertPathLeadsWith(t, runner, binDir)
		})
	}
}

// assertPathLeadsWith checks the recorded environment puts binDir first on PATH.
func assertPathLeadsWith(t *testing.T, runner *tenantRunner, binDir string) {
	t.Helper()
	if len(runner.calls) == 0 {
		t.Fatal("no command ran")
	}
	want := "PATH=" + binDir + ":" + systemPath
	if !strings.Contains(strings.Join(runner.calls[0].env, "\n"), want) {
		t.Errorf("environment = %q, want it to hold %q", runner.calls[0].env, want)
	}
}
