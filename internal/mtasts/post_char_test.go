package mtasts

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
)

// Publication is a sequence, and the step that matters is enforce: a sender
// honouring an enforce policy against a server it cannot verify does not
// deliver and does not bounce. The lock itself was proved in enforce_test.go;
// what was never reachable is the endpoint around it, which decides what is
// written to DNS and in which order.

// stsScript answers the handler's queries and records its writes.
type stsScript struct {
	mu sync.Mutex
	// rows answers a query whose text contains the fragment with these rows.
	rows map[string][][]driver.Value
	// noRows answers with no row (sql.ErrNoRows).
	noRows map[string]bool
	// queryErr fails a matching query, execErr a matching statement.
	queryErr map[string]error
	execErr  map[string]error
	execs    []string
	execArgs map[string][]driver.Value
}

func (s *stsScript) answer(query string) (driver.Rows, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for fragment, err := range s.queryErr {
		if strings.Contains(query, fragment) {
			return nil, err
		}
	}
	for fragment := range s.noRows {
		if strings.Contains(query, fragment) {
			return &stsRows{}, nil
		}
	}
	for fragment, values := range s.rows {
		if strings.Contains(query, fragment) {
			return &stsRows{values: values}, nil
		}
	}
	return nil, fmt.Errorf("the test script has no answer for: %s", query)
}

func (s *stsScript) record(query string, args []driver.NamedValue) error {
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
	for fragment, err := range s.execErr {
		if strings.Contains(query, fragment) {
			return err
		}
	}
	return nil
}

func (s *stsScript) argsOf(fragment string) []driver.Value {
	s.mu.Lock()
	defer s.mu.Unlock()
	for query, values := range s.execArgs {
		if strings.Contains(query, fragment) {
			return values
		}
	}
	return nil
}

type stsRows struct {
	values [][]driver.Value
	at     int
}

func (r *stsRows) Columns() []string {
	if len(r.values) == 0 {
		return []string{""}
	}
	return make([]string, len(r.values[0]))
}
func (r *stsRows) Close() error { return nil }
func (r *stsRows) Next(dest []driver.Value) error {
	if r.at >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.at])
	r.at++
	return nil
}

type stsConn struct{ script *stsScript }

func (c stsConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c stsConn) Driver() driver.Driver                        { return stsDriver{} }
func (c stsConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c stsConn) Close() error                                 { return nil }
func (c stsConn) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (c stsConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	return c.script.answer(query)
}

func (c stsConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if err := c.script.record(query, args); err != nil {
		return nil, err
	}
	return stsResult{}, nil
}

type stsResult struct{}

func (stsResult) LastInsertId() (int64, error) { return 1, nil }
func (stsResult) RowsAffected() (int64, error) { return 1, nil }

type stsDriver struct{}

func (stsDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

// The query fragments the handler runs.
const (
	qLoad    = "md.mtasts_id"
	qMX      = "type = 'MX'"
	qSoak    = "mtasts_changed_at IS NOT NULL"
	qPolicy  = "SELECT mtasts_id FROM mail_domains"
	updMode  = "UPDATE mail_domains SET mtasts_mode"
	oneHost  = "mail.example.com"
	theOwner = "example.com"
)

// inMode is a mail domain sitting in the given mode with one MX host.
func inMode(mode Mode) *stsScript {
	return &stsScript{
		rows: map[string][][]driver.Value{
			qLoad:   {{theOwner, string(mode), "abc123", "2026-01-01 00:00"}},
			qMX:     {{oneHost}},
			qSoak:   {{int64(1)}},
			qPolicy: {{"abc123"}},
		},
	}
}

// records is what the two record writers were asked to publish.
type records struct {
	enabled  []string
	policies []string
	order    []string
	enableEr error
	policyEr error
}

func (rec *records) install(t *testing.T) {
	t.Helper()
	previousEnable, previousPolicy := writeEnableRecords, writePolicyTXT
	t.Cleanup(func() { writeEnableRecords, writePolicyTXT = previousEnable, previousPolicy })
	writeEnableRecords = func(_ context.Context, _ *sql.DB, _ int64, domainName, ipv4 string) error {
		rec.enabled = append(rec.enabled, domainName+" -> "+ipv4)
		rec.order = append(rec.order, "enable")
		return rec.enableEr
	}
	writePolicyTXT = func(_ context.Context, _ *sql.DB, _ int64, id string) error {
		rec.policies = append(rec.policies, id)
		rec.order = append(rec.order, "policy")
		return rec.policyEr
	}
}

// postMode asks for a mode on domain 7 and returns the answer.
func postMode(t *testing.T, script *stsScript, rec *records, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec.install(t)
	stubMXCert(t, true)
	previousDNS, previousCert := dnsResolves, certCovers
	dnsResolves = func(string) bool { return true }
	certCovers = func(string) bool { return true }
	t.Cleanup(func() { dnsResolves, certCovers = previousDNS, previousCert })

	db := sql.OpenDB(stsConn{script: script})
	t.Cleanup(func() { _ = db.Close() })

	request := httptest.NewRequest(http.MethodPost, "/domains/7/mtasts", strings.NewReader(body))
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("id", "7")
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeCtx))

	recorder := httptest.NewRecorder()
	(&Handlers{DB: db, IPv4: "203.0.113.9"}).Post(recorder, request)

	answer := map[string]any{}
	if recorder.Body.Len() > 0 {
		_ = json.Unmarshal(recorder.Body.Bytes(), &answer)
	}
	return recorder, answer
}

// A request that names no usable mode never reaches the domain.
func TestOnlyTestingAndEnforceMayBeAskedFor(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{name: "not json", body: `{`, want: "invalid request body"},
		{name: "no mode", body: `{}`, want: "mode must be testing or enforce"},
		{name: "off", body: `{"mode":"off"}`, want: "mode must be testing or enforce"},
		{name: "withdrawing", body: `{"mode":"withdrawing"}`, want: "mode must be testing or enforce"},
	} {
		script := inMode(ModeOff)
		rec := &records{}

		recorder, _ := postMode(t, script, rec, tc.body)

		if recorder.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400: %s", tc.name, recorder.Code, recorder.Body)
		}
		if !strings.Contains(recorder.Body.String(), tc.want) {
			t.Errorf("%s: message = %s", tc.name, recorder.Body)
		}
		if len(rec.order) != 0 {
			t.Errorf("%s: the refusal still wrote %v", tc.name, rec.order)
		}
	}
}

// A domain that does not host mail here, and one that cannot be read, are told
// apart.
func TestAnUnusableDomainStopsThePublication(t *testing.T) {
	missing := inMode(ModeOff)
	missing.noRows = map[string]bool{qLoad: true}
	recorder, _ := postMode(t, missing, &records{}, `{"mode":"testing"}`)
	if recorder.Code != http.StatusNotFound {
		t.Errorf("a domain with no mail answered %d, want 404: %s", recorder.Code, recorder.Body)
	}

	unreadable := inMode(ModeOff)
	unreadable.queryErr = map[string]error{qLoad: errors.New("read failed")}
	recorder, _ = postMode(t, unreadable, &records{}, `{"mode":"testing"}`)
	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("an unreadable domain answered %d, want 500: %s", recorder.Code, recorder.Body)
	}
}

// Asking for testing publishes the policy host and the report address, then
// parks the domain on pending_dns. The policy id is NOT published yet: telling
// senders a policy exists at a host that does not answer keeps them retrying.
func TestTestingWritesTheEnableRecordsAndWaitsForDNS(t *testing.T) {
	script := inMode(ModeOff)
	rec := &records{}

	recorder, _ := postMode(t, script, rec, `{"mode":"testing"}`)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body)
	}
	if len(rec.enabled) != 1 || rec.enabled[0] != theOwner+" -> 203.0.113.9" {
		t.Errorf("the enable records were written as %v", rec.enabled)
	}
	if len(rec.policies) != 0 {
		t.Errorf("the policy id was published before the host answers: %v", rec.policies)
	}
	args := script.argsOf(updMode)
	if len(args) != 2 || args[0] != string(ModePendingDNS) {
		t.Errorf("the mode was written as %v, want pending_dns with no fresh id", args)
	}
}

// A domain that already publishes a policy is not started again.
func TestAPublishedDomainCannotBeStartedAgain(t *testing.T) {
	for _, mode := range []Mode{ModeTesting, ModeEnforce} {
		script := inMode(mode)
		rec := &records{}

		recorder, _ := postMode(t, script, rec, `{"mode":"testing"}`)

		if recorder.Code != http.StatusConflict {
			t.Errorf("%s: status = %d, want 409: %s", mode, recorder.Code, recorder.Body)
		}
		if len(rec.order) != 0 {
			t.Errorf("%s: the refusal still wrote %v", mode, rec.order)
		}
	}
}

// DNS that cannot be written stops the sequence rather than parking the domain
// on a step nothing will complete.
func TestAFailedRecordWriteStopsTheSequence(t *testing.T) {
	script := inMode(ModeOff)
	rec := &records{enableEr: errors.New("zone write failed")}

	recorder, _ := postMode(t, script, rec, `{"mode":"testing"}`)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", recorder.Code, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), "the DNS records could not be written") {
		t.Errorf("message = %s", recorder.Body)
	}
	if script.argsOf(updMode) != nil {
		t.Error("the mode moved although the records were not written")
	}
}

// The lock is checked on the WRITE path: a screen can be stale or bypassed
// entirely, and the answer names the reason as a code the screen translates.
func TestEnforceIsRefusedOnTheWritePathWithItsReason(t *testing.T) {
	script := inMode(ModeTesting)
	script.rows[qSoak] = [][]driver.Value{{int64(0)}}
	rec := &records{}

	recorder, answer := postMode(t, script, rec, `{"mode":"enforce"}`)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", recorder.Code, recorder.Body)
	}
	if answer["reason"] != ReasonSoak {
		t.Errorf("reason = %v, want %s", answer["reason"], ReasonSoak)
	}
	if script.argsOf(updMode) != nil || len(rec.order) != 0 {
		t.Error("a refused enforce still changed something")
	}
}

// An accepted enforce writes the mode with a FRESH id and then republishes the
// policy TXT, so senders refetch instead of keeping the cached testing policy.
func TestAnAcceptedEnforceRepublishesThePolicy(t *testing.T) {
	script := inMode(ModeTesting)
	rec := &records{}

	recorder, _ := postMode(t, script, rec, `{"mode":"enforce"}`)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body)
	}
	args := script.argsOf(updMode)
	if len(args) != 3 || args[0] != string(ModeEnforce) {
		t.Fatalf("the mode was written as %v, want enforce with a fresh id", args)
	}
	if id, ok := args[1].(string); !ok || len(id) != 16 {
		t.Errorf("the fresh policy id is %v", args[1])
	}
	if len(rec.policies) != 1 || rec.policies[0] != "abc123" {
		t.Errorf("the policy TXT was written as %v", rec.policies)
	}
	if strings.Join(rec.order, ",") != "policy" {
		t.Errorf("order = %v", rec.order)
	}
}

// A saved mode with unwritten DNS is reported as exactly that, because the two
// halves have come apart and only one of them can be retried.
func TestAFailedRepublishIsReported(t *testing.T) {
	script := inMode(ModeTesting)
	rec := &records{policyEr: errors.New("zone write failed")}

	recorder, _ := postMode(t, script, rec, `{"mode":"enforce"}`)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", recorder.Code, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), "the mode was saved but DNS could not be updated") {
		t.Errorf("message = %s", recorder.Body)
	}
}

// A mode that cannot be written is reported on both paths, and nothing
// downstream of it runs.
func TestAFailedModeWriteIsReported(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode Mode
		body string
	}{
		{name: "testing", mode: ModeOff, body: `{"mode":"testing"}`},
		{name: "enforce", mode: ModeTesting, body: `{"mode":"enforce"}`},
	} {
		script := inMode(tc.mode)
		script.execErr = map[string]error{updMode: errors.New("write failed")}
		rec := &records{}

		recorder, _ := postMode(t, script, rec, tc.body)

		if recorder.Code != http.StatusInternalServerError {
			t.Errorf("%s: status = %d, want 500: %s", tc.name, recorder.Code, recorder.Body)
		}
		if len(rec.policies) != 0 {
			t.Errorf("%s: the policy was republished although the mode was not saved", tc.name)
		}
	}
}

// An MX list that cannot be read is not proof the policy is safe to enforce.
func TestAnUnreadableMXListRefusesEnforce(t *testing.T) {
	script := inMode(ModeTesting)
	script.queryErr = map[string]error{qMX: errors.New("read failed")}
	rec := &records{}

	recorder, _ := postMode(t, script, rec, `{"mode":"enforce"}`)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", recorder.Code, recorder.Body)
	}
	if script.argsOf(updMode) != nil {
		t.Error("enforce was written although the MX hosts could not be read")
	}
}
