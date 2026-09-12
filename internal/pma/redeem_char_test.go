package pma

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Redeem hands a tenant's database password to phpMyAdmin. It is reachable only
// with the internal token file, and every refusal on the way is what keeps a
// signon token from being replayed. Nothing exercised it, so these tests pin
// the authentication, each refusal and the single consume the answer depends
// on.

const (
	theToken   = "8f14e45fceea167a5a36dedd4bea2543"
	authHeader = "X-Internal-Auth"
	updConsume = "UPDATE pma_tokens SET used=1"
)

// pmaScript answers the handler's query and records its statements.
type pmaScript struct {
	mu       sync.Mutex
	row      []driver.Value
	noRows   bool
	queryErr error
	execErr  error
	affected int64
	execs    []string
	execArgs map[string][]driver.Value
}

func (s *pmaScript) answer() (driver.Rows, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.queryErr != nil {
		return nil, s.queryErr
	}
	if s.noRows {
		return &pmaRows{}, nil
	}
	return &pmaRows{values: [][]driver.Value{s.row}}, nil
}

func (s *pmaScript) record(query string, args []driver.NamedValue) error {
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
	return s.execErr
}

func (s *pmaScript) argsOf(fragment string) []driver.Value {
	s.mu.Lock()
	defer s.mu.Unlock()
	for query, values := range s.execArgs {
		if strings.Contains(query, fragment) {
			return values
		}
	}
	return nil
}

type pmaRows struct {
	values [][]driver.Value
	at     int
}

func (r *pmaRows) Columns() []string {
	if len(r.values) == 0 {
		return []string{""}
	}
	return make([]string, len(r.values[0]))
}
func (r *pmaRows) Close() error { return nil }
func (r *pmaRows) Next(dest []driver.Value) error {
	if r.at >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.at])
	r.at++
	return nil
}

type pmaConn struct{ script *pmaScript }

func (c pmaConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c pmaConn) Driver() driver.Driver                        { return pmaDriver{} }
func (c pmaConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c pmaConn) Close() error                                 { return nil }
func (c pmaConn) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (c pmaConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return c.script.answer()
}

func (c pmaConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if err := c.script.record(query, args); err != nil {
		return nil, err
	}
	return pmaResult{affected: c.script.affected}, nil
}

type pmaResult struct{ affected int64 }

func (pmaResult) LastInsertId() (int64, error)   { return 1, nil }
func (r pmaResult) RowsAffected() (int64, error) { return r.affected, nil }

type pmaDriver struct{}

func (pmaDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

// liveToken is a token that has neither been used nor expired, on an account
// whose password is a legacy plaintext row.
func liveToken() *pmaScript {
	return &pmaScript{
		row:      []driver.Value{"c_test_app", "c_test_shop", "SecretPass1", int64(0), int64(0)},
		affected: 1,
	}
}

// withAuthFile writes the internal token file and points the handlers at it.
func withAuthFile(t *testing.T, contents string) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "pma-internal-token")
	if contents != "" {
		if err := os.WriteFile(file, []byte(contents), 0o600); err != nil {
			t.Fatalf("write the token file: %v", err)
		}
	}
	t.Setenv("SERVIKA_PMA_TOKEN", file)
}

func redeem(t *testing.T, script *pmaScript, header, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	db := sql.OpenDB(pmaConn{script: script})
	t.Cleanup(func() { _ = db.Close() })
	h := &Handlers{DB: db}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/internal/pma-redeem", strings.NewReader(body))
	if header != "" {
		r.Header.Set(authHeader, header)
	}
	w := httptest.NewRecorder()
	h.Redeem(w, r)
	var decoded map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &decoded)
	return w, decoded
}

const theSecret = "internal-token-value"

func tokenBody() string { return `{"token":"` + theToken + `"}` }

// A host with no token file must not accept ANY header, or the redeem endpoint
// would be open to every process that can reach the panel port.
func TestRedeemRefusesWhenTheHostHasNoTokenFile(t *testing.T) {
	withAuthFile(t, "")
	w, decoded := redeem(t, liveToken(), "", tokenBody())
	if w.Code != http.StatusUnauthorized || decoded["error"] != "unauthorized" {
		t.Fatalf("status = %d error = %v, want 401 unauthorized", w.Code, decoded["error"])
	}
	w, _ = redeem(t, liveToken(), "anything", tokenBody())
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d with a header and no file, want 401", w.Code)
	}
}

func TestRedeemRefusesAMissingOrWrongHeader(t *testing.T) {
	withAuthFile(t, theSecret)
	for _, header := range []string{"", "wrong-value", theSecret + "x"} {
		w, _ := redeem(t, liveToken(), header, tokenBody())
		if w.Code != http.StatusUnauthorized {
			t.Errorf("header %q: status = %d, want 401", header, w.Code)
		}
	}
}

// The file is read with its terminator trimmed, so the value written by the
// installer matches the header signon.php sends.
func TestRedeemAcceptsTheTokenFileValue(t *testing.T) {
	withAuthFile(t, theSecret+"\n")
	w, _ := redeem(t, liveToken(), theSecret, tokenBody())
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestRedeemRequiresAToken(t *testing.T) {
	withAuthFile(t, theSecret)
	for _, body := range []string{"{", `{"token":""}`, `{}`} {
		w, decoded := redeem(t, liveToken(), theSecret, body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want 400", body, w.Code)
		}
		if decoded["error"] != "token is required" {
			t.Errorf("body %q: error = %v", body, decoded["error"])
		}
	}
}

// The join is INNER, so a token whose account was deleted inside the two-minute
// window answers "not found" rather than serving a stale credential.
func TestRedeemAnswersNotFoundForATokenWithNoAccount(t *testing.T) {
	withAuthFile(t, theSecret)
	script := liveToken()
	script.noRows = true
	w, decoded := redeem(t, script, theSecret, tokenBody())
	if w.Code != http.StatusNotFound || decoded["error"] != "token not found" {
		t.Fatalf("status = %d error = %v, want 404 token not found", w.Code, decoded["error"])
	}
}

func TestRedeemFailsWhenTheTokenCannotBeRead(t *testing.T) {
	withAuthFile(t, theSecret)
	script := liveToken()
	script.queryErr = errors.New("connection refused")
	w, decoded := redeem(t, script, theSecret, tokenBody())
	if w.Code != http.StatusInternalServerError || decoded["error"] != "database operation failed" {
		t.Fatalf("status = %d error = %v, want 500", w.Code, decoded["error"])
	}
}

// A token is single use, and the two rejections are distinct so the operator
// can tell a replay from a slow browser.
func TestRedeemRefusesAUsedOrExpiredToken(t *testing.T) {
	withAuthFile(t, theSecret)
	cases := []struct {
		name    string
		used    int64
		expired int64
		want    string
	}{
		{name: "used", used: 1, want: "token has already been used"},
		{name: "expired", expired: 1, want: "token has expired"},
	}
	for _, test := range cases {
		script := liveToken()
		script.row = []driver.Value{"c_test_app", "c_test_shop", "SecretPass1", test.used, test.expired}
		w, decoded := redeem(t, script, theSecret, tokenBody())
		if w.Code != http.StatusGone {
			t.Errorf("%s: status = %d, want 410", test.name, w.Code)
		}
		if decoded["error"] != test.want {
			t.Errorf("%s: error = %v, want %s", test.name, decoded["error"], test.want)
		}
		if len(script.execs) != 0 {
			t.Errorf("%s: a refused token was still consumed: %v", test.name, script.execs)
		}
	}
}

func TestRedeemFailsWhenTheTokenCannotBeConsumed(t *testing.T) {
	withAuthFile(t, theSecret)
	script := liveToken()
	script.execErr = errors.New("connection refused")
	w, decoded := redeem(t, script, theSecret, tokenBody())
	if w.Code != http.StatusInternalServerError || decoded["error"] != "database operation failed" {
		t.Fatalf("status = %d error = %v, want 500", w.Code, decoded["error"])
	}
}

// Two requests racing on one token both pass the read, so the UPDATE is what
// decides. The loser changes no row and gets nothing.
func TestRedeemRefusesWhenTheConsumeChangesNoRow(t *testing.T) {
	withAuthFile(t, theSecret)
	script := liveToken()
	script.affected = 0
	w, decoded := redeem(t, script, theSecret, tokenBody())
	if w.Code != http.StatusGone || decoded["error"] != "token is no longer valid" {
		t.Fatalf("status = %d error = %v, want 410 token is no longer valid", w.Code, decoded["error"])
	}
	if _, ok := decoded["password"]; ok {
		t.Fatal("the password was served to a request that consumed nothing")
	}
}

func TestRedeemServesTheCredentialAndConsumesTheToken(t *testing.T) {
	withAuthFile(t, theSecret)
	script := liveToken()
	w, decoded := redeem(t, script, theSecret, tokenBody())
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	want := map[string]any{
		"username": "c_test_app",
		"password": "SecretPass1",
		"db":       "c_test_shop",
		"host":     "localhost",
	}
	for key, value := range want {
		if decoded[key] != value {
			t.Errorf("%s = %v, want %v", key, decoded[key], value)
		}
	}
	if args := script.argsOf(updConsume); len(args) != 1 || args[0] != theToken {
		t.Fatalf("consumed %v, want the requested token", args)
	}
}

// The stored value is sealed at rest. A row this host cannot open must not fall
// back to serving the ciphertext as the password.
func TestRedeemFailsWhenTheStoredPasswordCannotBeOpened(t *testing.T) {
	withAuthFile(t, theSecret)
	script := liveToken()
	script.row = []driver.Value{"c_test_app", "c_test_shop", "enc:v1:not-openable", int64(0), int64(0)}
	w, decoded := redeem(t, script, theSecret, tokenBody())
	if w.Code != http.StatusInternalServerError || decoded["error"] != "database operation failed" {
		t.Fatalf("status = %d error = %v, want 500", w.Code, decoded["error"])
	}
}
