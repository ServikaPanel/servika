package laravel

import (
	"database/sql/driver"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const runningUpdate = "SET last_deploy_status='running'"

// deployScriptDB answers the reads a deploy makes for domain 7.
func deployScriptDB() *sqlScript {
	s := newScript()
	s.rows[domainLookup] = [][]driver.Value{{"c_test", "8.3"}}
	s.rows[statusQuery] = [][]driver.Value{{"ready"}}
	s.rows[appRecord] = [][]driver.Value{
		{"public_html", "remote", "8.3", "", int64(0), int64(0), "", "ready"},
	}
	return s
}

func serveDeploy(t *testing.T, script *sqlScript, body string) *httptest.ResponseRecorder {
	t.Helper()
	handlers := &Handlers{DB: scriptDB(t, script)}
	recorder := httptest.NewRecorder()
	handlers.Deploy(recorder, laravelRequest(http.MethodPost, "/api/v1/domains/7/laravel/deploy", body))
	return recorder
}

func TestDeployRefusesBeforeItStartsAJob(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		script  func(s *sqlScript)
		noWrite bool
		status  int
		want    string
	}{
		{name: "a domain that is not there", body: "{}",
			script: func(s *sqlScript) { s.rows[domainLookup] = nil },
			status: http.StatusNotFound, want: "domain not found"},
		{name: "an install that is already running", body: "{}",
			script: func(s *sqlScript) { s.rows[statusQuery] = [][]driver.Value{{"installing"}} },
			status: http.StatusConflict, want: "already running"},
		{name: "a deploy that is already running", body: "{}",
			script: func(s *sqlScript) { s.rows[statusQuery] = [][]driver.Value{{"running"}} },
			status: http.StatusConflict, want: "already running"},
		{name: "a body that is not JSON", body: "{",
			status: http.StatusBadRequest, want: "invalid request body"},
		{name: "a node version that is not one", body: `{"node_version":"22; id"}`,
			status: http.StatusBadRequest, want: "invalid node version"},
		{name: "an application directory outside public_html", body: "{}",
			script: func(s *sqlScript) {
				s.rows[appRecord] = [][]driver.Value{{"etc", "remote", "8.3", "", int64(0), int64(0), "", "ready"}}
			},
			status: http.StatusBadRequest, want: "invalid application directory"},
		{name: "a script that cannot be written", body: "{}", noWrite: true,
			status: http.StatusInternalServerError, want: "deploy script write failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tenantHome(t)
			fakes := (&hostFakes{}).install(t)
			nodeBinAt(t, true)
			if tc.noWrite {
				setForTest(t, &runScriptDir, filepath.Join(fakes.scriptDir, "missing"))
			}
			script := deployScriptDB()
			if tc.script != nil {
				tc.script(script)
			}
			assertResponse(t, serveDeploy(t, script, tc.body), tc.status, tc.want)
			if len(fakes.detached) != 0 {
				t.Errorf("a refused deploy started %d jobs", len(fakes.detached))
			}
		})
	}
}

// A job systemd refuses leaves the row alone, so the screen does not show a
// deploy that never started.
func TestDeployReportsAJobSystemdRefused(t *testing.T) {
	tenantHome(t)
	(&hostFakes{detachErr: errScripted}).install(t)
	nodeBinAt(t, true)
	script := deployScriptDB()
	assertResponse(t, serveDeploy(t, script, "{}"), http.StatusInternalServerError, "deploy start failed")
	assertWriteCount(t, script, runningUpdate, 0)
}

// The deploy script is what the tenant's shell reads, so each optional step is
// pinned as it is written.
func TestDeployWritesTheScriptItStarts(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		present []string
		absent  []string
	}{
		{name: "the steps every deploy runs", body: "{}",
			present: []string{"artisan down || true", "install --no-interaction --prefer-dist --no-dev",
				"artisan config:cache", "artisan up || true", "== DEPLOY COMPLETE =="},
			absent: []string{"artisan migrate --force", "npm ci"}},
		{name: "a deploy that migrates", body: `{"migrate":true}`,
			present: []string{"artisan migrate --force"}, absent: []string{"npm ci"}},
		{name: "a deploy that builds the assets", body: `{"npm_build":true}`,
			present: []string{"npm ci --prefix", "npm run build --prefix"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tenantHome(t)
			fakes := (&hostFakes{}).install(t)
			nodeBinAt(t, true)
			script := deployScriptDB()
			assertResponse(t, serveDeploy(t, script, tc.body), http.StatusOK, `"unit":"servika-laravel-deploy-7"`)
			assertDeployStarted(t, fakes, script)
			assertScriptHolds(t, filepath.Join(fakes.scriptDir, "servika-laravel-deploy-7.sh"), tc.present, tc.absent)
		})
	}
}

// assertDeployStarted checks the job, the unit reset and the row the screen
// polls.
func assertDeployStarted(t *testing.T, fakes *hostFakes, script *sqlScript) {
	t.Helper()
	if len(fakes.detached) != 1 || fakes.detached[0].unit != "servika-laravel-deploy-7" {
		t.Fatalf("jobs = %+v, want one deploy job", fakes.detached)
	}
	want := "systemctl reset-failed servika-laravel-deploy-7.service"
	if !strings.Contains(strings.Join(fakes.commands.lines, "\n"), want) {
		t.Errorf("commands = %q, want %q", fakes.commands.lines, want)
	}
	assertWriteCount(t, script, runningUpdate, 1)
}

func assertScriptHolds(t *testing.T, path string, present, absent []string) {
	t.Helper()
	body, err := os.ReadFile(path) // #nosec G304 -- the script this test just wrote.
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range present {
		if !strings.Contains(string(body), want) {
			t.Errorf("script lacks %q:\n%s", want, body)
		}
	}
	for _, unwanted := range absent {
		if strings.Contains(string(body), unwanted) {
			t.Errorf("script holds %q it should not:\n%s", unwanted, body)
		}
	}
}
