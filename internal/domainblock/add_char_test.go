package domainblock

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"servika/internal/auth"
	"servika/internal/middleware"
)

// The ban list is what keeps a phishing host off the panel, so what the write
// endpoint counts as applied, skipped and rejected has to be exact: an operator
// who believes a name is banned when it is not stops looking. Only the paste
// parser was reachable in a test. These tests run the handler itself against a
// scripted database.

// banScript records every statement and answers with a chosen row count.
type banScript struct {
	mu sync.Mutex
	// affected keys a domain argument to the row count the write reports.
	affected map[string]int64
	// failOn fails a statement whose text contains the fragment.
	failOn string
	execs  []string
	args   [][]driver.Value
}

func (s *banScript) record(query string, args []driver.NamedValue) (driver.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	values := make([]driver.Value, 0, len(args))
	for _, a := range args {
		values = append(values, a.Value)
	}
	s.execs = append(s.execs, query)
	s.args = append(s.args, values)
	if s.failOn != "" && strings.Contains(query, s.failOn) {
		return nil, errors.New("write failed")
	}
	rows := int64(1)
	if len(values) > 0 {
		if name, ok := values[0].(string); ok {
			if n, listed := s.affected[name]; listed {
				rows = n
			}
		}
	}
	return banResult{rows: rows}, nil
}

// argsFor returns the arguments of the first statement whose text contains the
// fragment and whose first argument is the given name.
func (s *banScript) argsFor(fragment, name string) []driver.Value {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, query := range s.execs {
		if !strings.Contains(query, fragment) || len(s.args[i]) == 0 {
			continue
		}
		if first, ok := s.args[i][0].(string); ok && first == name {
			return s.args[i]
		}
	}
	return nil
}

// wrote reports how many statements contained the fragment.
func (s *banScript) wrote(fragment string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, query := range s.execs {
		if strings.Contains(query, fragment) {
			count++
		}
	}
	return count
}

// auditTarget returns the target column of the recorded audit row.
func (s *banScript) auditTarget() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, query := range s.execs {
		if !strings.Contains(query, "audit_log") {
			continue
		}
		for _, value := range s.args[i] {
			if text, ok := value.(string); ok && strings.HasPrefix(text, "applied=") {
				return text
			}
		}
	}
	return ""
}

type banResult struct{ rows int64 }

func (banResult) LastInsertId() (int64, error)   { return 1, nil }
func (r banResult) RowsAffected() (int64, error) { return r.rows, nil }

type banConn struct{ script *banScript }

func (c banConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c banConn) Driver() driver.Driver                        { return banDriver{} }
func (c banConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c banConn) Close() error                                 { return nil }
func (c banConn) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (c banConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return nil, errors.New("this handler runs no query")
}

func (c banConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	return c.script.record(query, args)
}

type banDriver struct{}

func (banDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

// addBan posts a body as the given administrator (0 means no claims at all).
func addBan(t *testing.T, script *banScript, adminID int64, body string) (*httptest.ResponseRecorder, writeResult) {
	t.Helper()
	db := sql.OpenDB(banConn{script: script})
	t.Cleanup(func() { _ = db.Close() })

	request := httptest.NewRequest(http.MethodPost, "/admin/banned-domains", strings.NewReader(body))
	if adminID > 0 {
		request = request.WithContext(auth.WithClaims(request.Context(),
			&auth.Claims{UserID: adminID, Username: "admin", Role: middleware.RoleAdmin}))
	}
	recorder := httptest.NewRecorder()
	(&Handlers{DB: db}).Add(recorder, request)

	var result writeResult
	if recorder.Code == http.StatusOK {
		if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
			t.Fatalf("the answer is not a write result: %s", recorder.Body)
		}
	}
	return recorder, result
}

// manyNames builds a paste of n distinct valid names.
func manyNames(n int) string {
	names := make([]string, 0, n)
	for i := range n {
		names = append(names, "n"+strconv.Itoa(i)+".example.com")
	}
	return strings.Join(names, " ")
}

// Nothing is written for a request that names no usable domain.
func TestAWriteWithNothingToDoIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{name: "not json", body: `{`, want: "invalid request body"},
		{name: "no domains", body: `{"domains":""}`, want: "no domain name was given"},
		{name: "separators only", body: `{"domains":" ,;\n"}`, want: "no domain name was given"},
		{name: "too many", body: `{"domains":"` + manyNames(maxEntriesPerRequest+1) + `"}`, want: "too many domain names in one request"},
	} {
		script := &banScript{}

		recorder, _ := addBan(t, script, 1, tc.body)

		if recorder.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400: %s", tc.name, recorder.Code, recorder.Body)
		}
		if !strings.Contains(recorder.Body.String(), tc.want) {
			t.Errorf("%s: message = %s, want %q", tc.name, recorder.Body, tc.want)
		}
		if script.wrote("banned_domains") != 0 {
			t.Errorf("%s: the refusal still wrote a row", tc.name)
		}
	}
}

// A paste of 501 distinct names is refused, and 500 is accepted, so the ceiling
// is the documented one.
func TestTheCeilingIsFiveHundredNames(t *testing.T) {
	script := &banScript{}

	recorder, result := addBan(t, script, 1, `{"domains":"`+manyNames(maxEntriesPerRequest)+`"}`)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body)
	}
	if result.Applied != maxEntriesPerRequest {
		t.Errorf("applied = %d, want %d", result.Applied, maxEntriesPerRequest)
	}
}

// A name that is not a domain is reported back rather than repaired, and the
// rest of the paste is still written.
func TestAMalformedNameIsReportedAndTheRestIsWritten(t *testing.T) {
	script := &banScript{affected: map[string]int64{"already.example.com": 0}}

	recorder, result := addBan(t, script, 4,
		`{"domains":"good.example.com, not_a_domain, already.example.com"}`)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body)
	}
	if result.Applied != 1 || result.Skipped != 1 {
		t.Errorf("applied = %d, skipped = %d, want 1 and 1", result.Applied, result.Skipped)
	}
	if len(result.Rejected) != 1 || result.Rejected[0] != "not_a_domain" {
		t.Errorf("rejected = %q, want the malformed name", result.Rejected)
	}
	if script.wrote("INSERT INTO banned_domains") != 2 {
		t.Errorf("%d rows were written, want the two valid names", script.wrote("INSERT INTO banned_domains"))
	}
}

// Subdomains are banned unless the operator says otherwise, because a phisher
// hides the brand one label down. An explicit false is told apart from a body
// that never mentioned the field.
func TestSubdomainsAreIncludedUnlessTheOperatorSaysOtherwise(t *testing.T) {
	for _, tc := range []struct {
		body string
		want int64
	}{
		{body: `{"domains":"one.example.com"}`, want: 1},
		{body: `{"domains":"one.example.com","match_subdomains":true}`, want: 1},
		{body: `{"domains":"one.example.com","match_subdomains":false}`, want: 0},
	} {
		script := &banScript{}

		if recorder, _ := addBan(t, script, 1, tc.body); recorder.Code != http.StatusOK {
			t.Fatalf("%s answered %d", tc.body, recorder.Code)
		}
		args := script.argsFor("INSERT INTO banned_domains", "one.example.com")
		if len(args) != 4 {
			t.Fatalf("%s wrote %v", tc.body, args)
		}
		if args[2] != tc.want {
			t.Errorf("%s stored match_subdomains %v, want %v", tc.body, args[2], tc.want)
		}
	}
}

// The description is trimmed and cut to what the column holds, and the writer
// is the administrator who asked. A request with no claims stores no writer
// rather than a wrong one.
func TestTheStoredDescriptionAndWriterArePinned(t *testing.T) {
	long := strings.Repeat("x", 300)
	script := &banScript{}

	if recorder, _ := addBan(t, script, 42, `{"domains":"one.example.com","description":"  `+long+`  "}`); recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	args := script.argsFor("INSERT INTO banned_domains", "one.example.com")
	if len(args) != 4 {
		t.Fatalf("wrote %v", args)
	}
	if description, ok := args[1].(string); !ok || len(description) != 255 {
		t.Errorf("description = %v, want 255 characters", args[1])
	}
	if args[3] != int64(42) {
		t.Errorf("created_by = %v, want the administrator", args[3])
	}

	anonymous := &banScript{}
	if recorder, _ := addBan(t, anonymous, 0, `{"domains":"one.example.com"}`); recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if args := anonymous.argsFor("INSERT INTO banned_domains", "one.example.com"); args[3] != nil {
		t.Errorf("created_by = %v, want none", args[3])
	}
}

// A write that fails stops the request rather than reporting a partial ban as
// done.
func TestAFailedWriteIsReported(t *testing.T) {
	script := &banScript{failOn: "INSERT INTO banned_domains"}

	recorder, _ := addBan(t, script, 1, `{"domains":"one.example.com two.example.com"}`)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", recorder.Code, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), "the list could not be written") {
		t.Errorf("message = %s", recorder.Body)
	}
	if script.wrote("audit_log") != 0 {
		t.Error("a failed write was still recorded in the audit log")
	}
}

// The audit row carries the counts rather than the names, because a bulk paste
// would truncate the target column.
func TestTheAuditRowCarriesTheCounts(t *testing.T) {
	script := &banScript{affected: map[string]int64{"two.example.com": 0}}

	if recorder, _ := addBan(t, script, 1, `{"domains":"one.example.com two.example.com"}`); recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if got := script.auditTarget(); got != "applied=1 skipped=1" {
		t.Errorf("audit target = %q", got)
	}
}
