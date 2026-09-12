package php

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"servika/internal/auth"
	"servika/internal/middleware"
)

// A settings save reaches the host through one of two paths: the tenant's own
// PHP-FPM master, or the pool file in the version's shared directory. The tests
// below pin which one runs, what each is handed, and what a failure answers.

// settingsHost records the host side of a save.
type settingsHost struct {
	shims       []string
	tenantOwn   bool
	tenantFail  error
	poolFail    error
	vhostFail   error
	appliedPool Settings
	poolFor     []string
	vhostFor    []string
}

// install points the provisioner seams at this recorder.
func (s *settingsHost) install(t *testing.T) {
	t.Helper()
	setForTest(t, &writeDebugShim, func(_ *sql.DB, systemUser string, _ int64) {
		s.shims = append(s.shims, systemUser)
	})
	setForTest(t, &tenantFPMActive, func(string) bool { return s.tenantOwn })
	setForTest(t, &enableTenantFPMGuarded, func(_ *sql.DB, _ int64, systemUser, version string) (string, error) {
		s.poolFor = append(s.poolFor, "tenant "+systemUser+" "+version)
		return "/run/php-fpm-" + systemUser + "/" + systemUser + ".sock", s.tenantFail
	})
	setForTest(t, &applyPool, func(systemUser, version string, settings Settings) (string, error) {
		s.poolFor = append(s.poolFor, "shared "+systemUser+" "+version)
		s.appliedPool = settings
		return "/run/php-fpm/" + systemUser + ".sock", s.poolFail
	})
	setForTest(t, &applyVhostForDomain, func(_ *sql.DB, id int64, socket, version string) error {
		s.vhostFor = append(s.vhostFor, socket+" "+version)
		return s.vhostFail
	})
}

// domainScope scripts the domain row a settings save resolves.
func domainScope(script *sqlScript, systemUser, version string) {
	script.rows["SELECT domain_name, system_user, php_version FROM domains"] = [][]driver.Value{
		{"example.com", systemUser, version},
	}
}

// putSettings sends a save as the administrator, whose isolation fields are
// taken from the request rather than from the stored row.
func putSettings(t *testing.T, handlers *Handlers, body string) *httptest.ResponseRecorder {
	t.Helper()
	route := chi.NewRouteContext()
	route.URLParams.Add("id", "7")
	r := httptest.NewRequest(http.MethodPut, "/domains/7/php-settings", strings.NewReader(body))
	ctx := auth.WithClaims(r.Context(), &auth.Claims{UserID: 1, Username: "root", Role: middleware.RoleAdmin})
	ctx = context.WithValue(ctx, chi.RouteCtxKey, route)

	recorder := httptest.NewRecorder()
	handlers.PutSettings(recorder, r.WithContext(ctx))
	return recorder
}

// validSettings is a body the sanitizer accepts.
const validSettings = `{"settings":{"memory_limit":"256M","post_max_size":"64M","upload_max_filesize":"64M",` +
	`"pm_strategy":"ondemand","pm_max_children":8,"pm_max_requests":500,"pm_start_servers":2,` +
	`"pm_min_spare_servers":1,"pm_max_spare_servers":3,"error_reporting":"E_ALL"}}`

// savedAnswer decodes the answer of a successful save.
func savedAnswer(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	var answer map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatalf("decode the answer: %v", err)
	}
	return answer
}

// assertRefusal checks the status and the reason of a refused save.
func assertRefusal(t *testing.T, recorder *httptest.ResponseRecorder, status int, message string) {
	t.Helper()
	if recorder.Code != status {
		t.Fatalf("status = %d, want %d (body %s)", recorder.Code, status, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), message) {
		t.Errorf("body = %s, want %q", recorder.Body, message)
	}
}

// A domain without its own master is served by the pool file in the version's
// shared directory, and the vhost is pointed at the socket that pool listens on.
func TestASaveWritesTheSharedPoolAndPointsTheVhostAtIt(t *testing.T) {
	script := newScript()
	domainScope(script, "c_acme", "8.3")
	recorder := &settingsHost{}
	recorder.install(t)

	answer := savedAnswer(t, putSettings(t, &Handlers{DB: scriptDB(t, script)}, validSettings))

	if answer["php_version"] != "8.3" || answer["socket"] != "/run/php-fpm/c_acme.sock" {
		t.Errorf("answer = %+v", answer)
	}
	assertCalls(t, "pool", recorder.poolFor, "shared c_acme 8.3")
	assertCalls(t, "vhost", recorder.vhostFor, "/run/php-fpm/c_acme.sock 8.3")
	assertCalls(t, "debug shim", recorder.shims, "c_acme")
	if recorder.appliedPool.MemoryLimit != "256M" {
		t.Errorf("the pool was rendered from %+v", recorder.appliedPool)
	}
	if !ranStatement(script, "INSERT INTO php_settings") {
		t.Errorf("the settings were not saved: %v", script.steps)
	}
}

// assertCalls checks that one host step ran exactly once, with what it was
// handed.
func assertCalls(t *testing.T, what string, got []string, want string) {
	t.Helper()
	if len(got) != 1 || got[0] != want {
		t.Errorf("%s calls = %v, want [%s]", what, got, want)
	}
}

// A domain that already runs its own master is served by that master, and the
// shared pool file is not touched at all.
func TestASaveOnAnOwnMasterLeavesTheSharedPoolAlone(t *testing.T) {
	script := newScript()
	domainScope(script, "c_acme", "8.3")
	recorder := &settingsHost{tenantOwn: true}
	recorder.install(t)

	answer := savedAnswer(t, putSettings(t, &Handlers{DB: scriptDB(t, script)}, validSettings))

	if answer["socket"] != "/run/php-fpm-c_acme/c_acme.sock" {
		t.Errorf("answer = %+v", answer)
	}
	assertCalls(t, "pool", recorder.poolFor, "tenant c_acme 8.3")
	if len(recorder.vhostFor) != 0 {
		t.Errorf("vhost calls = %v, want none", recorder.vhostFor)
	}
}

// A version the panel does not offer is refused before anything is saved: the
// pool directory it names does not exist and the vhost would point nowhere.
func TestASaveRefusesAVersionThatIsNotInstalled(t *testing.T) {
	script := newScript()
	domainScope(script, "c_acme", "8.3")
	recorder := &settingsHost{}
	recorder.install(t)

	answer := putSettings(t, &Handlers{DB: scriptDB(t, script)},
		`{"php_version":"5.6","settings":{"memory_limit":"256M","post_max_size":"64M","upload_max_filesize":"64M","pm_strategy":"ondemand","pm_max_children":8}}`)

	assertRefusal(t, answer, http.StatusBadRequest, "unsupported PHP version")
	if len(recorder.poolFor) != 0 {
		t.Errorf("pool calls = %v, want none", recorder.poolFor)
	}
	if ranStatement(script, "INSERT INTO php_settings") {
		t.Errorf("a refused version still saved settings: %v", script.steps)
	}
}

// A version change is written to the domain row only after the pool and the
// vhost are in place, so the row never claims a version nginx is not serving.
func TestAnAcceptedVersionChangeIsWrittenToTheDomainRow(t *testing.T) {
	script := newScript()
	domainScope(script, "c_acme", "8.3")
	recorder := &settingsHost{}
	recorder.install(t)

	body := strings.Replace(validSettings, `{"settings"`, `{"php_version":"8.2","settings"`, 1)
	answer := savedAnswer(t, putSettings(t, &Handlers{DB: scriptDB(t, script)}, body))

	if answer["php_version"] != "8.2" {
		t.Errorf("answer = %+v", answer)
	}
	assertCalls(t, "pool", recorder.poolFor, "shared c_acme 8.2")
	if !ranStatement(script, "UPDATE domains SET php_version=?") {
		t.Errorf("the domain row was not updated: %v", script.steps)
	}
}

// The version is left alone when it was not asked to change, so a settings save
// cannot rewrite the domain row by accident.
func TestASaveWithoutAVersionLeavesTheDomainRowAlone(t *testing.T) {
	script := newScript()
	domainScope(script, "c_acme", "8.3")
	(&settingsHost{}).install(t)

	savedAnswer(t, putSettings(t, &Handlers{DB: scriptDB(t, script)}, validSettings))

	if ranStatement(script, "UPDATE domains SET php_version=?") {
		t.Errorf("the domain row was updated anyway: %v", script.steps)
	}
}

func TestASaveReportsTheStepThatFailed(t *testing.T) {
	cases := []struct {
		name    string
		host    settingsHost
		script  func(*sqlScript)
		body    string
		status  int
		message string
	}{
		{
			name:    "the shared pool",
			host:    settingsHost{poolFail: errors.New("php-fpm -t failed")},
			status:  http.StatusInternalServerError,
			message: "failed to apply PHP pool configuration",
		},
		{
			name:    "the vhost",
			host:    settingsHost{vhostFail: errors.New("nginx -t failed")},
			status:  http.StatusInternalServerError,
			message: "failed to apply nginx virtual host",
		},
		{
			name:    "the tenant master",
			host:    settingsHost{tenantOwn: true, tenantFail: errors.New("the master died")},
			status:  http.StatusInternalServerError,
			message: "failed to apply tenant PHP-FPM configuration",
		},
		{
			name:    "the settings row",
			script:  func(s *sqlScript) { s.fail["INSERT INTO php_settings"] = errors.New("disk full") },
			status:  http.StatusInternalServerError,
			message: "failed to save PHP settings",
		},
		{
			name:    "the domain lookup",
			script:  func(s *sqlScript) { s.rows["SELECT domain_name, system_user, php_version FROM domains"] = nil },
			status:  http.StatusNotFound,
			message: "domain not found",
		},
		{
			name:    "the request body",
			body:    `{"settings":`,
			status:  http.StatusBadRequest,
			message: "invalid request body",
		},
		{
			name:    "the process manager group",
			body:    `{"settings":{"memory_limit":"256M","post_max_size":"64M","upload_max_filesize":"64M","pm_strategy":"dynamic","pm_max_children":2,"pm_start_servers":9,"pm_min_spare_servers":1,"pm_max_spare_servers":1}}`,
			status:  http.StatusBadRequest,
			message: reasonPMInconsistent,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			script := newScript()
			domainScope(script, "c_acme", "8.3")
			if testCase.script != nil {
				testCase.script(script)
			}
			host := testCase.host
			host.install(t)
			body := testCase.body
			if body == "" {
				body = validSettings
			}

			assertRefusal(t, putSettings(t, &Handlers{DB: scriptDB(t, script)}, body),
				testCase.status, testCase.message)
		})
	}
}

// ranStatement reports whether the script saw a statement carrying fragment.
func ranStatement(script *sqlScript, fragment string) bool {
	script.mu.Lock()
	defer script.mu.Unlock()
	for _, step := range script.steps {
		if strings.Contains(step, fragment) {
			return true
		}
	}
	return false
}
