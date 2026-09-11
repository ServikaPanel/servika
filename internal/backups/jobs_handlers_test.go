package backups

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"servika/internal/auth"
	"servika/internal/middleware"

	"github.com/go-chi/chi/v5"
)

const (
	scopedDomainsQuery = "SELECT d.id, d.system_user, d.domain_name FROM domains d"
	startJobInsert     = "INSERT INTO backup_jobs(type, operation, status, total, restore_mode, started_by)"
	finishJobUpdate    = "UPDATE backup_jobs SET status=?, active_domain='', finished_at=NOW() WHERE id=?"
	detailUpdate       = "UPDATE backup_jobs SET completed=?, succeeded=?, failed=?, detail=? WHERE id=?"
)

// adminRequest is a request from the root admin with the route parameters set.
func adminRequest(method, target, body string, params ...string) *http.Request {
	r := domainRequest(method, target, body, params...)
	return r.WithContext(auth.WithClaims(r.Context(), &auth.Claims{UserID: 1, Username: "root", Role: middleware.RoleAdmin}))
}

func TestStartBackupJobRefusesWhatItCannotStart(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		script  *sqlScript
		status  int
		message string
	}{
		{"a malformed body", `{"domain_ids":"all"}`, &sqlScript{}, http.StatusBadRequest, "invalid request body"},
		{"the domains cannot be listed", "", &sqlScript{fail: map[string]error{scopedDomainsQuery: errors.New("lost")}},
			http.StatusInternalServerError, "could not list domains"},
		{"no domain in scope", `{"domain_ids":[4]}`, &sqlScript{rows: map[string][][]driver.Value{scopedDomainsQuery: {}}},
			http.StatusBadRequest, "no domain is available to back up"},
		{"the job row cannot be written", "", &sqlScript{
			rows: map[string][][]driver.Value{scopedDomainsQuery: {{int64(5), "c_example", "example.com"}}},
			fail: map[string]error{startJobInsert: errors.New("read-only")},
		}, http.StatusInternalServerError, "could not start the backup job"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			(&Handlers{DB: scriptDB(t, c.script)}).StartBackupJob(w, adminRequest(http.MethodPost, "/admin/backups/jobs", c.body))
			assertRefusal(t, w, c.status, c.message)
		})
	}
}

// backupJobScript is a bulk backup over the given domains with no destination and
// nothing to prune.
func backupJobScript(insertID int64, domains ...[]driver.Value) *sqlScript {
	return &sqlScript{insertID: insertID, rows: map[string][][]driver.Value{
		scopedDomainsQuery:  domains,
		ownedListQuery:      {},
		scheduledPruneQuery: {},
		domainNameQuery:     {{"example.com"}},
		destinationQuery:    {},
		settingsQuery:       {},
	}}
}

func assertCreated(t *testing.T, w *httptest.ResponseRecorder, jobID, total int) {
	t.Helper()
	want := map[string]any{"ok": true, "job_id": float64(jobID), "total": float64(total)}
	if w.Code != http.StatusCreated || !reflect.DeepEqual(responseBody(t, w), want) {
		t.Fatalf("answered %d %s, want 201 %v", w.Code, w.Body.String(), want)
	}
}

// A bulk backup counts each domain, alerts on the one that failed, trims both,
// and closes the job with the tallies.
func TestStartBackupJobBacksUpEveryDomainInScope(t *testing.T) {
	t.Setenv("SERVIKA_BACKUP_ROOT", t.TempDir())
	script := backupJobScript(41,
		[]driver.Value{int64(5), "c_example", "example.com"},
		[]driver.Value{int64(6), "c_broken", "broken.com"},
		[]driver.Value{int64(7), "bad user", "x.com"})
	archiveCommands(t, map[string]string{"c_example_main": completeDump, "c_broken_main": "FAIL"}, 0)

	w := httptest.NewRecorder()
	(&Handlers{DB: scriptDB(t, script)}).StartBackupJob(w, adminRequest(http.MethodPost, "/admin/backups/jobs", `{"domain_ids":[5,6,7]}`))

	assertCreated(t, w, 41, 2)
	script.waitForExec(t, finishJobUpdate)
	size := int64(len(localArchiveBytes))
	assertExecs(t, script, finishJobUpdate, []driver.Value{"partial", int64(41)})
	assertExecs(t, script, startJobInsert, []driver.Value{"backup", int64(2), "", "root"})
	assertExecs(t, script, countsUpdate,
		[]driver.Value{int64(1), int64(1), int64(0), size, int64(41)},
		[]driver.Value{int64(2), int64(1), int64(1), size, int64(41)})
	// The domains are taken in the order the query answers, which the scripted
	// database leaves as written; the invalid system user is never started.
	assertExecs(t, script, activeUpdate, []driver.Value{"example.com", int64(41)}, []driver.Value{"broken.com", int64(41)})
	assertAlerts(t, script, alert{key: "backup.backupFailed", domain: int64(6)})
	if rows := script.execsContaining("INSERT INTO backups("); len(rows) != 1 {
		t.Errorf("backup rows = %+v", rows)
	}
	if prunes := script.queriesContaining("type='full'"); prunes != 2 {
		t.Errorf("manual retention ran %d times, want both domains", prunes)
	}
}

// A stop between domains leaves the rest unstarted and closes the job as
// stopped rather than done.
func TestStartBackupJobStopsBetweenDomains(t *testing.T) {
	t.Setenv("SERVIKA_BACKUP_ROOT", t.TempDir())
	script := backupJobScript(42,
		[]driver.Value{int64(5), "c_example", "example.com"},
		[]driver.Value{int64(6), "c_second", "second.com"})
	script.onExec = func(query string) {
		if strings.Contains(query, countsUpdate) {
			stopJob(42)
		}
	}
	archiveCommands(t, map[string]string{"c_example_main": completeDump, "c_second_main": completeDump}, 0)

	w := httptest.NewRecorder()
	(&Handlers{DB: scriptDB(t, script)}).StartBackupJob(w, adminRequest(http.MethodPost, "/admin/backups/jobs", ""))

	script.waitForExec(t, finishJobUpdate)
	assertExecs(t, script, finishJobUpdate, []driver.Value{"stopped", int64(42)})
	assertExecs(t, script, activeUpdate, []driver.Value{"example.com", int64(42)})
}

// A stop that kills the domain in flight is not counted as a failure.
func TestStartBackupJobDoesNotCountAStoppedDomainAsFailed(t *testing.T) {
	t.Setenv("SERVIKA_BACKUP_ROOT", t.TempDir())
	script := backupJobScript(43, []driver.Value{int64(5), "c_example", "example.com"})
	withCommandScript(t, func([]string) (string, int) {
		stopJob(43)
		return "", 1
	})

	w := httptest.NewRecorder()
	(&Handlers{DB: scriptDB(t, script)}).StartBackupJob(w, adminRequest(http.MethodPost, "/admin/backups/jobs", ""))

	script.waitForExec(t, finishJobUpdate)
	assertExecs(t, script, finishJobUpdate, []driver.Value{"stopped", int64(43)})
	assertAlerts(t, script)
}

// A progress write that fails is logged and the job still runs to its end.
func TestStartBackupJobCarriesOnPastFailedProgressWrites(t *testing.T) {
	t.Setenv("SERVIKA_BACKUP_ROOT", t.TempDir())
	script := backupJobScript(44, []driver.Value{int64(5), "c_example", "example.com"})
	script.fail = map[string]error{activeUpdate: errors.New("read-only"), countsUpdate: errors.New("read-only")}
	archiveCommands(t, map[string]string{"c_example_main": completeDump}, 0)

	w := httptest.NewRecorder()
	(&Handlers{DB: scriptDB(t, script)}).StartBackupJob(w, adminRequest(http.MethodPost, "/admin/backups/jobs", ""))

	script.waitForExec(t, finishJobUpdate)
	assertExecs(t, script, finishJobUpdate, []driver.Value{"done", int64(44)})
}

const panicClose = "UPDATE backup_jobs SET status='failed', active_domain='', finished_at=NOW() WHERE id=?"

// A panic inside the job goroutine closes the row as failed instead of leaving
// it running until the next restart.
func TestStartBackupJobRecordsAPanicAsAFailedJob(t *testing.T) {
	t.Setenv("SERVIKA_BACKUP_ROOT", t.TempDir())
	script := backupJobScript(45, []driver.Value{int64(5), "c_example", "example.com"})
	withCommandScript(t, func([]string) (string, int) { panic("a command blew up") })

	w := httptest.NewRecorder()
	(&Handlers{DB: scriptDB(t, script)}).StartBackupJob(w, adminRequest(http.MethodPost, "/admin/backups/jobs", ""))

	assertCreated(t, w, 45, 1)
	script.waitForExec(t, panicClose)
	assertExecs(t, script, panicClose, []driver.Value{int64(45)})
	assertExecs(t, script, finishJobUpdate)
}

func TestStartRestoreJobRefusesWhatItCannotStart(t *testing.T) {
	domains := map[string][][]driver.Value{scopedDomainsQuery: {{int64(5), "c_example", "example.com"}}}
	cases := []struct {
		name    string
		body    string
		script  *sqlScript
		status  int
		message string
	}{
		{"a malformed body", `{`, &sqlScript{}, http.StatusBadRequest, "invalid request body"},
		{"an unknown mode", `{"mode":"db","items":[{"domain_id":5,"backup_id":9}]}`, &sqlScript{}, http.StatusBadRequest, "invalid restore mode"},
		{"no items", `{"mode":" files "}`, &sqlScript{}, http.StatusBadRequest, "no item was selected for restore"},
		{"the domains cannot be resolved", `{"items":[{"domain_id":5,"backup_id":9}]}`,
			&sqlScript{fail: map[string]error{scopedDomainsQuery: errors.New("lost")}},
			http.StatusInternalServerError, "could not resolve domains"},
		{"no item in scope", `{"items":[{"domain_id":8,"backup_id":9}]}`, &sqlScript{rows: domains},
			http.StatusBadRequest, "no valid item was selected"},
		{"the job row cannot be written", `{"items":[{"domain_id":5,"backup_id":9}]}`,
			&sqlScript{rows: domains, fail: map[string]error{startJobInsert: errors.New("read-only")}},
			http.StatusInternalServerError, "could not start the restore job"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			(&Handlers{DB: scriptDB(t, c.script)}).StartRestoreJob(w, adminRequest(http.MethodPost, "/admin/backups/restore", c.body))
			assertRefusal(t, w, c.status, c.message)
		})
	}
}

type restoreResult struct {
	DomainID   int64  `json:"domain_id"`
	DomainName string `json:"domain_name"`
	Status     string `json:"status"`
	Message    string `json:"message"`
}

// restoreJobFixture is a site archive of domain 5 with both domains in scope.
func restoreJobFixture(t *testing.T, jobID int64) *restoreFixture {
	t.Helper()
	f := newRestoreFixture(t, "", siteArchive()...)
	f.script.insertID = jobID
	f.script.rows[scopedDomainsQuery] = [][]driver.Value{{int64(5), "c_example", "example.com"}, {int64(6), "c_other", "other.com"}}
	return f
}

func startRestoreJob(t *testing.T, f *restoreFixture, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	f.h.StartRestoreJob(w, adminRequest(http.MethodPost, "/admin/backups/restore", body))
	return w
}

// A bulk restore records a result per domain in the job detail and closes the
// job with the tallies; a busy domain fails without stopping the rest.
func TestStartRestoreJobRestoresEachItem(t *testing.T) {
	f := restoreJobFixture(t, 51)
	extractingCommands(t)
	release, ok := lockDomain(6)
	if !ok {
		t.Fatal("domain 6 could not be claimed")
	}
	defer release()

	w := startRestoreJob(t, f,
		`{"mode":"files","items":[{"domain_id":5,"backup_id":9},{"domain_id":6,"backup_id":10},{"domain_id":99,"backup_id":1}]}`)

	assertCreated(t, w, 51, 2)
	f.script.waitForExec(t, finishJobUpdate)
	assertExecs(t, f.script, finishJobUpdate, []driver.Value{"partial", int64(51)})
	assertExecs(t, f.script, startJobInsert, []driver.Value{"restore", int64(2), "files", "root"})
	details := f.script.execsContaining(detailUpdate)
	if len(details) != 2 {
		t.Fatalf("detail updates = %+v", details)
	}
	var results []restoreResult
	if err := json.Unmarshal([]byte(details[1].args[3].(string)), &results); err != nil {
		t.Fatal(err)
	}
	want := []restoreResult{
		{DomainID: 5, DomainName: "example.com", Status: "done", Message: "restored files"},
		{DomainID: 6, DomainName: "other.com", Status: "failed", Message: ErrDomainBusy.Error()},
	}
	if !reflect.DeepEqual(results, want) {
		t.Errorf("results = %+v, want %+v", results, want)
	}
}

// A stop between items, and a stop that kills the item in flight, both close the
// job as stopped.
func TestStartRestoreJobStops(t *testing.T) {
	t.Run("between items", func(t *testing.T) {
		f := restoreJobFixture(t, 52)
		extractingCommands(t)
		f.script.onExec = func(query string) {
			if strings.Contains(query, detailUpdate) {
				stopJob(52)
			}
		}
		startRestoreJob(t, f, `{"items":[{"domain_id":5,"backup_id":9},{"domain_id":6,"backup_id":10}]}`)

		f.script.waitForExec(t, finishJobUpdate)
		assertExecs(t, f.script, finishJobUpdate, []driver.Value{"stopped", int64(52)})
		if details := f.script.execsContaining(detailUpdate); len(details) != 1 {
			t.Errorf("an item ran after the stop: %+v", details)
		}
	})
	t.Run("in flight", func(t *testing.T) {
		f := restoreJobFixture(t, 53)
		withCommandScript(t, func([]string) (string, int) {
			stopJob(53)
			return "", 1
		})
		startRestoreJob(t, f, `{"items":[{"domain_id":5,"backup_id":9}]}`)

		f.script.waitForExec(t, finishJobUpdate)
		assertExecs(t, f.script, finishJobUpdate, []driver.Value{"stopped", int64(53)})
		assertExecs(t, f.script, detailUpdate)
	})
}

// A progress write that fails is logged and the job still runs to its end.
func TestStartRestoreJobCarriesOnPastFailedProgressWrites(t *testing.T) {
	f := restoreJobFixture(t, 54)
	extractingCommands(t)
	f.script.fail = map[string]error{activeUpdate: errors.New("read-only"), detailUpdate: errors.New("read-only")}

	startRestoreJob(t, f, `{"mode":"files","items":[{"domain_id":5,"backup_id":9}]}`)

	f.script.waitForExec(t, finishJobUpdate)
	assertExecs(t, f.script, finishJobUpdate, []driver.Value{"done", int64(54)})
}

func TestStartRestoreJobRecordsAPanicAsAFailedJob(t *testing.T) {
	f := restoreJobFixture(t, 55)
	withCommandScript(t, func([]string) (string, int) { panic("a command blew up") })

	w := startRestoreJob(t, f, `{"mode":"files","items":[{"domain_id":5,"backup_id":9}]}`)

	assertCreated(t, w, 55, 1)
	f.script.waitForExec(t, panicClose)
	assertExecs(t, f.script, panicClose, []driver.Value{int64(55)})
	assertExecs(t, f.script, finishJobUpdate)
}

const (
	jobHeaderQuery = "detail FROM backup_jobs j WHERE j.id=?"
	jobItemsQuery  = "SELECT b.id, b.domain_id, d.domain_name, d.system_user, b.size_b, b.type"
)

func jobHeader(operation, activeDomain, startedBy string, detail driver.Value) []driver.Value {
	return []driver.Value{int64(3), "manual", operation, "done", int64(2), int64(2), int64(2), int64(0), int64(100),
		activeDomain, "", startedBy, "2026-01-01 00:00", "2026-01-01 00:10", detail}
}

func jobDetailRequest(claims *auth.Claims) *http.Request {
	route := chi.NewRouteContext()
	route.URLParams.Add("jid", "3")
	r := httptest.NewRequest(http.MethodGet, "/admin/backups/jobs/3", nil)
	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, route)
	if claims != nil {
		ctx = auth.WithClaims(ctx, claims)
	}
	return r.WithContext(ctx)
}

// bodyCheck inspects one decoded answer.
type bodyCheck func(t *testing.T, body map[string]any)

func errorIs(message string) bodyCheck {
	return func(t *testing.T, body map[string]any) {
		t.Helper()
		if body["error"] != message {
			t.Errorf("error = %v, want %q", body["error"], message)
		}
	}
}

// fieldIs checks one top-level field, including one that must be present and
// null.
func fieldIs(key string, want any) bodyCheck {
	return func(t *testing.T, body map[string]any) {
		t.Helper()
		if got, present := body[key]; !present || !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %v (present %t), want %v", key, got, present, want)
		}
	}
}

// jobNamesAre checks the two job fields that name people and domains.
func jobNamesAre(activeDomain, startedBy string) bodyCheck {
	return func(t *testing.T, body map[string]any) {
		t.Helper()
		job, _ := body["job"].(map[string]any)
		if job["active_domain"] != activeDomain || job["started_by"] != startedBy {
			t.Errorf("job = %v, want active_domain %q and started_by %q", job, activeDomain, startedBy)
		}
	}
}

func TestJobDetailAnswersEachKindOfJob(t *testing.T) {
	admin := &auth.Claims{UserID: 1, Username: "root", Role: middleware.RoleAdmin}
	reseller := &auth.Claims{UserID: 7, Username: "agency", Role: middleware.RoleReseller}
	backupHeader := map[string][][]driver.Value{jobHeaderQuery: {jobHeader("backup", "", "root", nil)}}
	adminItem := map[string]any{"backup_id": float64(11), "domain_id": float64(5), "domain_name": "example.com",
		"system_user": "c_example", "size_b": float64(100), "type": "full"}
	cases := []struct {
		name   string
		claims *auth.Claims
		script *sqlScript
		status int
		checks []bodyCheck
	}{
		{name: "an unknown job", claims: admin, script: &sqlScript{rows: map[string][][]driver.Value{jobHeaderQuery: {}}},
			status: http.StatusNotFound, checks: []bodyCheck{errorIs("backup job not found")}},
		{name: "a failed header read", claims: admin, script: &sqlScript{fail: map[string]error{jobHeaderQuery: errors.New("lost")}},
			status: http.StatusInternalServerError, checks: []bodyCheck{errorIs("internal server error")}},
		{name: "a restore job with results", claims: admin,
			script: &sqlScript{rows: map[string][][]driver.Value{jobHeaderQuery: {jobHeader("restore", "", "root", `[{"domain_id":5}]`)}}},
			status: http.StatusOK, checks: []bodyCheck{fieldIs("results", []any{map[string]any{"domain_id": float64(5)}})}},
		{name: "a restore job with no detail", claims: admin,
			script: &sqlScript{rows: map[string][][]driver.Value{jobHeaderQuery: {jobHeader("restore", "", "root", nil)}}},
			status: http.StatusOK, checks: []bodyCheck{fieldIs("results", nil)}},
		{name: "a backup job seen by an admin", claims: admin,
			script: &sqlScript{rows: map[string][][]driver.Value{
				jobHeaderQuery: {jobHeader("backup", "example.com", "agency", nil)},
				jobItemsQuery:  {{int64(11), int64(5), "example.com", "c_example", int64(100), "full"}, {"not a number", int64(6), "x", "y", int64(1), "full"}},
			}},
			status: http.StatusOK, checks: []bodyCheck{fieldIs("domains", []any{adminItem}), jobNamesAre("example.com", "agency")}},
		{name: "a backup job seen by a reseller", claims: reseller,
			script: &sqlScript{rows: map[string][][]driver.Value{
				jobHeaderQuery: {jobHeader("backup", "rival.com", "rival", nil)},
				jobItemsQuery:  {},
			}},
			status: http.StatusOK, checks: []bodyCheck{fieldIs("domains", []any{}), jobNamesAre("", "")}},
		{name: "the item list cannot be read", claims: admin,
			script: &sqlScript{rows: backupHeader, fail: map[string]error{jobItemsQuery: errors.New("lost")}},
			status: http.StatusInternalServerError, checks: []bodyCheck{errorIs("could not list job items")}},
		{name: "the item list ends early", claims: admin,
			script: &sqlScript{
				rows:    map[string][][]driver.Value{jobHeaderQuery: backupHeader[jobHeaderQuery], jobItemsQuery: {}},
				endWith: map[string]error{jobItemsQuery: errors.New("lost")},
			},
			status: http.StatusInternalServerError, checks: []bodyCheck{errorIs("job detail read failed")}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			(&Handlers{DB: scriptDB(t, c.script)}).JobDetail(w, jobDetailRequest(c.claims))
			if w.Code != c.status {
				t.Fatalf("answered %d: %s", w.Code, w.Body.String())
			}
			for _, check := range c.checks {
				check(t, responseBody(t, w))
			}
		})
	}
}
