package resource

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
)

// Show is the screen a customer reads to decide whether they are near a plan
// limit, and nothing exercised it. What matters is that a failed measurement
// never reads as zero: a tenant shown an empty home believes they have room
// they do not have. These tests pin the mapping, both disk sources and every
// counter.

const (
	qDomain   = "FROM domains d WHERE d.id=?"
	qPlan     = "FROM service_plans"
	qSizeKB   = "SELECT size_kb FROM domains"
	qTraffic  = "SELECT traffic_kb FROM domains"
	qDBUsers  = "SELECT db_user FROM db_accounts"
	qFTP      = "FROM ftp_accounts"
	qMail     = "FROM mailboxes"
	qDNS      = "FROM dns_records"
	qBackups  = "FROM backups"
	updSizeKB = "UPDATE domains SET size_kb"
)

// resScript answers the handler's queries and records its statements.
type resScript struct {
	mu       sync.Mutex
	rows     map[string][][]driver.Value
	queryErr map[string]error
	// errAfter fails a matching query AFTER its rows are read, the way a
	// connection dropped mid-read surfaces through rows.Err.
	errAfter map[string]error
	execs    []string
	execArgs map[string][]driver.Value
}

func (s *resScript) answer(query string) (driver.Rows, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for fragment, err := range s.queryErr {
		if strings.Contains(query, fragment) {
			return nil, err
		}
	}
	for fragment, values := range s.rows {
		if strings.Contains(query, fragment) {
			return &resRows{values: values, after: s.errAfter[fragment]}, nil
		}
	}
	return nil, errors.New("the test script has no answer for: " + query)
}

func (s *resScript) record(query string, args []driver.NamedValue) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.execs = append(s.execs, query)
	if s.execArgs == nil {
		s.execArgs = map[string][]driver.Value{}
	}
	values := make([]driver.Value, 0, len(args))
	for _, a := range args {
		values = append(values, a.Value)
	}
	s.execArgs[query] = values
}

func (s *resScript) argsOf(fragment string) []driver.Value {
	s.mu.Lock()
	defer s.mu.Unlock()
	for query, values := range s.execArgs {
		if strings.Contains(query, fragment) {
			return values
		}
	}
	return nil
}

type resRows struct {
	values [][]driver.Value
	at     int
	after  error
}

func (r *resRows) Columns() []string {
	if len(r.values) == 0 {
		return []string{""}
	}
	return make([]string, len(r.values[0]))
}
func (r *resRows) Close() error { return nil }
func (r *resRows) Next(dest []driver.Value) error {
	if r.at >= len(r.values) {
		if r.after != nil {
			return r.after
		}
		return io.EOF
	}
	copy(dest, r.values[r.at])
	r.at++
	return nil
}

type resConn struct{ script *resScript }

func (c resConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c resConn) Driver() driver.Driver                        { return resDriver{} }
func (c resConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c resConn) Close() error                                 { return nil }
func (c resConn) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (c resConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	return c.script.answer(query)
}

func (c resConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.script.record(query, args)
	return resResult{}, nil
}

type resResult struct{}

func (resResult) LastInsertId() (int64, error) { return 1, nil }
func (resResult) RowsAffected() (int64, error) { return 1, nil }

type resDriver struct{}

func (resDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

// onPlan is a tenant domain on a plan, with one database, and counters the
// screen reports.
func onPlan() *resScript {
	return &resScript{
		rows: map[string][][]driver.Value{
			qDomain:  {{"example.com", "c_test", "8.3", "203.0.113.10", int64(1), "2027-03-04", int64(5)}},
			qPlan:    {{"Bronze", int64(2048), int64(51200), int64(3), int64(4), int64(10), int64(2)}},
			qSizeKB:  {{int64(4096)}},
			qTraffic: {{int64(3072)}},
			qDBUsers: {{"c_test_app"}, {"c_test_shop"}},
			qFTP:     {{int64(2)}},
			qMail:    {{int64(6)}},
			qDNS:     {{int64(9)}},
			qBackups: {{int64(3), int64(10 * 1024 * 1024)}},
		},
	}
}

// hostState answers for the host measurements the summary makes.
type hostState struct {
	homeSize  int64
	homeErr   error
	quota     [4]int
	crontab   string
	cronFails bool

	measured []string
}

func (s *hostState) install(t *testing.T) {
	t.Helper()
	homeWas, quotaWas, runWas := homeBytes, quotaStatus, runCommand
	t.Cleanup(func() { homeBytes, quotaStatus, runCommand = homeWas, quotaWas, runWas })
	homeBytes = func(_ context.Context, path string) (int64, error) {
		s.measured = append(s.measured, path)
		return s.homeSize, s.homeErr
	}
	quotaStatus = func(string) (int, int, int, int) {
		return s.quota[0], s.quota[1], s.quota[2], s.quota[3]
	}
	runCommand = func(_ string, _ ...string) *exec.Cmd {
		if s.cronFails {
			return exec.Command("/usr/bin/false")
		}
		return exec.Command("/bin/echo", "-n", s.crontab)
	}
}

func show(t *testing.T, script *resScript, host *hostState) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	host.install(t)
	db := sql.OpenDB(resConn{script: script})
	t.Cleanup(func() { _ = db.Close() })
	h := &Handlers{DB: db}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/domains/7/resources", nil)
	routes := chi.NewRouteContext()
	routes.URLParams.Add("id", "7")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, routes))
	w := httptest.NewRecorder()
	h.Show(w, r)
	var decoded map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &decoded)
	return w, decoded
}

// measuredHome is a host whose home measurement answers 8 MB.
func measuredHome() *hostState {
	return &hostState{homeSize: 8 * 1024 * 1024}
}

// limitOf reads one usage/limit pair out of the answer.
func limitOf(t *testing.T, body map[string]any, key string) (usage, limit float64) {
	t.Helper()
	pair, ok := body[key].(map[string]any)
	if !ok {
		t.Fatalf("%s is missing from %v", key, body)
	}
	return pair["usage"].(float64), pair["limit"].(float64)
}

func TestShowAnswersNotFoundForAnUnknownDomain(t *testing.T) {
	script := onPlan()
	script.queryErr = map[string]error{qDomain: errors.New("no rows")}
	w, decoded := show(t, script, measuredHome())
	if w.Code != http.StatusNotFound || decoded["error"] != "domain not found" {
		t.Fatalf("status = %d error = %v, want 404 domain not found", w.Code, decoded["error"])
	}
}

func TestShowMapsTheDomainRow(t *testing.T) {
	w, decoded := show(t, onPlan(), measuredHome())
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	want := map[string]any{
		"domain_name": "example.com",
		"system_user": "c_test",
		"php_version": "8.3",
		"ipv4":        "203.0.113.10",
		"ssl_enabled": true,
		"ssl_expiry":  "2027-03-04",
		"plan_name":   "Bronze",
	}
	for key, value := range want {
		if decoded[key] != value {
			t.Errorf("%s = %v, want %v", key, decoded[key], value)
		}
	}
}

// A domain with no plan is reported as unlimited rather than as a plan with
// every limit at zero, which the screen would read as a hard stop.
func TestShowReportsNoPlanAsUnlimited(t *testing.T) {
	script := onPlan()
	script.rows[qDomain] = [][]driver.Value{
		{"example.com", "c_test", "8.3", "203.0.113.10", int64(0), nil, nil},
	}
	_, decoded := show(t, script, measuredHome())
	if decoded["plan_name"] != "Unlimited (no plan assigned)" {
		t.Fatalf("plan_name = %v", decoded["plan_name"])
	}
	if decoded["ssl_enabled"] != false {
		t.Errorf("ssl_enabled = %v, want false", decoded["ssl_enabled"])
	}
	if _, ok := decoded["ssl_expiry"]; ok {
		t.Errorf("ssl_expiry = %v, want it omitted for a domain with none", decoded["ssl_expiry"])
	}
	if _, limit := limitOf(t, decoded, "disk_mb"); limit != 0 {
		t.Errorf("disk limit = %v, want 0 for no plan", limit)
	}
}

func TestShowReportsTheMeasuredHomeAndStoresIt(t *testing.T) {
	script, host := onPlan(), measuredHome()
	_, decoded := show(t, script, host)
	usage, limit := limitOf(t, decoded, "disk_mb")
	if usage != 8 || limit != 2048 {
		t.Fatalf("disk usage/limit = %v/%v, want 8/2048", usage, limit)
	}
	if len(host.measured) != 1 || host.measured[0] != "/home/c_test" {
		t.Fatalf("measured %v, want the tenant home", host.measured)
	}
	args := script.argsOf(updSizeKB)
	if len(args) != 2 || args[0] != int64(8192) || args[1] != int64(7) {
		t.Fatalf("stored %v, want the measured size in kilobytes for domain 7", args)
	}
}

// A du that fails must not read as an empty home. The stored size is served
// instead, and it is NOT overwritten with zero.
func TestShowFallsBackToTheStoredSizeWhenTheMeasurementFails(t *testing.T) {
	script := onPlan()
	host := &hostState{homeErr: errors.New("deadline exceeded")}
	_, decoded := show(t, script, host)
	usage, _ := limitOf(t, decoded, "disk_mb")
	if usage != 4 {
		t.Fatalf("disk usage = %v, want the stored 4096 kilobytes as 4 megabytes", usage)
	}
	if script.argsOf(updSizeKB) != nil {
		t.Fatalf("a failed measurement overwrote the stored size: %v", script.execs)
	}
}

// XFS quota is the authority when it is active: it is the number the kernel
// enforces, and it carries inodes, which du cannot see.
func TestShowPrefersTheActiveQuotaOverTheMeasurement(t *testing.T) {
	host := measuredHome()
	host.quota = [4]int{120, 4096, 3100, 50000}
	_, decoded := show(t, onPlan(), host)
	usage, limit := limitOf(t, decoded, "disk_mb")
	if usage != 120 || limit != 4096 {
		t.Fatalf("disk usage/limit = %v/%v, want the quota values", usage, limit)
	}
	if decoded["inode_usage"] != float64(3100) || decoded["inode_limit"] != float64(50000) {
		t.Fatalf("inode usage/limit = %v/%v, want 3100/50000", decoded["inode_usage"], decoded["inode_limit"])
	}
}

// A host with no quota keeps the measured values and reports no inode figures,
// rather than showing a tenant a limit of zero.
func TestShowKeepsTheMeasurementWhenNoQuotaIsActive(t *testing.T) {
	_, decoded := show(t, onPlan(), measuredHome())
	usage, limit := limitOf(t, decoded, "disk_mb")
	if usage != 8 || limit != 2048 {
		t.Fatalf("disk usage/limit = %v/%v, want the measured values", usage, limit)
	}
	if decoded["inode_usage"] != float64(0) || decoded["inode_limit"] != float64(0) {
		t.Fatalf("inode usage/limit = %v/%v, want zero", decoded["inode_usage"], decoded["inode_limit"])
	}
}

func TestShowReportsEveryCounterAgainstItsPlanLimit(t *testing.T) {
	_, decoded := show(t, onPlan(), measuredHome())
	cases := []struct {
		key   string
		usage float64
		limit float64
	}{
		{key: "traffic_mb", usage: 3, limit: 51200},
		{key: "db_count", usage: 2, limit: 4},
		{key: "ftp_count", usage: 2, limit: 2},
		{key: "email_count", usage: 6, limit: 10},
		{key: "domain_count", usage: 1, limit: 3},
	}
	for _, test := range cases {
		usage, limit := limitOf(t, decoded, test.key)
		if usage != test.usage || limit != test.limit {
			t.Errorf("%s = %v/%v, want %v/%v", test.key, usage, limit, test.usage, test.limit)
		}
	}
	if decoded["dns_record"] != float64(9) {
		t.Errorf("dns_record = %v, want 9", decoded["dns_record"])
	}
	if decoded["backup_count"] != float64(3) || decoded["backup_mb"] != float64(10) {
		t.Errorf("backups = %v count and %v megabytes, want 3 and 10", decoded["backup_count"], decoded["backup_mb"])
	}
}

// The length of the database list IS the reported count, so a row that cannot
// be read is skipped and the count reports only what was actually read.
func TestShowSkipsADatabaseAccountItCannotRead(t *testing.T) {
	script := onPlan()
	script.rows[qDBUsers] = [][]driver.Value{{"c_test_app"}, {nil}}
	_, decoded := show(t, script, measuredHome())
	usage, _ := limitOf(t, decoded, "db_count")
	if usage != 1 {
		t.Fatalf("db usage = %v, want only the row that could be read", usage)
	}
}

// A read that stops short understates usage, so the short list is reported and
// the failure is logged rather than passed off as a complete count.
func TestShowReportsWhatItReadWhenTheDatabaseListStopsShort(t *testing.T) {
	script := onPlan()
	script.errAfter = map[string]error{qDBUsers: errors.New("connection reset")}
	w, decoded := show(t, script, measuredHome())
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	usage, _ := limitOf(t, decoded, "db_count")
	if usage != 2 {
		t.Fatalf("db usage = %v, want the rows that were read", usage)
	}
}

// A comment or a blank line in a crontab is not a job.
func TestShowCountsOnlyRealCronJobs(t *testing.T) {
	host := measuredHome()
	host.crontab = "# a comment\n\n* * * * * /usr/bin/true\n   \n0 3 * * * /usr/bin/backup\n"
	_, decoded := show(t, onPlan(), host)
	if decoded["cron_job"] != float64(2) {
		t.Fatalf("cron_job = %v, want 2", decoded["cron_job"])
	}
}

// A tenant with no crontab makes the command fail, and the count stays zero
// rather than failing the whole screen.
func TestShowReportsNoCronJobsWhenTheCrontabCannotBeRead(t *testing.T) {
	host := measuredHome()
	host.cronFails = true
	w, decoded := show(t, onPlan(), host)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if decoded["cron_job"] != float64(0) {
		t.Fatalf("cron_job = %v, want 0", decoded["cron_job"])
	}
}
