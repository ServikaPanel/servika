package auth

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"servika/internal/secret"
)

// A scripted driver, because what has to be asserted is the VALUE the handler
// writes: a seed that reaches the column in the clear is the defect. The
// repository carries no sqlmock dependency.
type totpScript struct {
	mu   sync.Mutex
	rows map[string][]driver.Value
	// empty maps a query fragment to the COLUMN COUNT of an empty result set,
	// which is how a "no such row" lookup is scripted. A nil entry in rows
	// would still yield one row of zero columns, and Scan would report a
	// column-count error instead of sql.ErrNoRows.
	empty map[string]int
	// fail maps a statement fragment to the error the driver answers with, which
	// is how a write that the database refuses is scripted.
	fail  map[string]error
	execs []totpExec
}

type totpExec struct {
	query string
	args  []driver.Value
}

func (s *totpScript) answerQuery(query string) (driver.Rows, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for fragment, columns := range s.empty {
		if strings.Contains(query, fragment) {
			// An EMPTY result set of the right width, which is what produces
			// sql.ErrNoRows rather than a scan error.
			return &totpRows{values: make([]driver.Value, columns), done: true}, nil
		}
	}
	for fragment, values := range s.rows {
		if strings.Contains(query, fragment) {
			return &totpRows{values: values}, nil
		}
	}
	return nil, fmt.Errorf("the test script has no answer for: %s", query)
}

func (s *totpScript) recordExec(query string, args []driver.Value) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.execs = append(s.execs, totpExec{query: query, args: args})
}

// execError returns the scripted failure for a statement, or nil.
func (s *totpScript) execError(query string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for fragment, err := range s.fail {
		if strings.Contains(query, fragment) {
			return err
		}
	}
	return nil
}

// storedSeed returns the value written into totp_secret, and whether one was.
func (s *totpScript) storedSeed() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.execs {
		if !strings.Contains(e.query, "totp_secret=?") {
			continue
		}
		if len(e.args) > 0 {
			if text, ok := e.args[0].(string); ok {
				return text, true
			}
		}
	}
	return "", false
}

type totpRows struct {
	values []driver.Value
	done   bool
}

func (r *totpRows) Columns() []string { return make([]string, len(r.values)) }
func (r *totpRows) Close() error      { return nil }
func (r *totpRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	copy(dest, r.values)
	return nil
}

type totpConn struct{ script *totpScript }

func (c totpConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c totpConn) Driver() driver.Driver                        { return totpDriver{} }
func (c totpConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c totpConn) Close() error                                 { return nil }
func (c totpConn) Begin() (driver.Tx, error)                    { return totpTx{}, nil }

func (c totpConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	return c.script.answerQuery(query)
}

func (c totpConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	plain := make([]driver.Value, 0, len(args))
	for _, a := range args {
		plain = append(plain, a.Value)
	}
	c.script.recordExec(query, plain)
	if err := c.script.execError(query); err != nil {
		return nil, err
	}
	return totpResult{}, nil
}

type totpTx struct{}

func (totpTx) Commit() error   { return nil }
func (totpTx) Rollback() error { return nil }

type totpResult struct{}

func (totpResult) LastInsertId() (int64, error) { return 1, nil }
func (totpResult) RowsAffected() (int64, error) { return 1, nil }

type totpDriver struct{}

func (totpDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

func totpDB(t *testing.T, script *totpScript) *sql.DB {
	t.Helper()
	db := sql.OpenDB(totpConn{script: script})
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func meRequest(userID int64, body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/me/2fa/enable", strings.NewReader(body))
	claims := &Claims{UserID: userID, Username: "operator", Role: "admin"}
	return request.WithContext(WithClaims(request.Context(), claims))
}

// Enabling 2FA used to write the raw base32 seed, so any read of the users table
// yielded a working second factor for every operator who had it on.
func TestEnablingTwoFactorStoresNoUsableSeed(t *testing.T) {
	initSecret(t)
	const seed = "JBSWY3DPEHPK3PXP"
	code, err := totpCodeFor(seed)
	if err != nil {
		t.Fatalf("build a valid code: %v", err)
	}
	script := &totpScript{rows: map[string][]driver.Value{}}
	recorder := httptest.NewRecorder()

	(&Handlers{DB: totpDB(t, script)}).TwoFAEnable(recorder,
		meRequest(7, `{"secret":"`+seed+`","code":"`+code+`"}`))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	stored, ok := script.storedSeed()
	if !ok {
		t.Fatal("the handler wrote no totp_secret")
	}
	if stored == seed || strings.Contains(stored, seed) {
		t.Fatalf("the seed reached the column in the clear: %q", stored)
	}
	if !secret.IsEncrypted(stored) {
		t.Fatalf("the stored value is not sealed: %q", stored)
	}
	// And it is the seed, sealed for THIS user.
	opened, err := OpenTOTPSecret(stored, 7)
	if err != nil || opened != seed {
		t.Fatalf("OpenTOTPSecret() = %q, %v; want the seed back", opened, err)
	}
	if _, err := OpenTOTPSecret(stored, 8); err == nil {
		t.Fatal("the stored value opens for another user")
	}
}

// The disable path reads the column back, so it has to open the seal or an
// operator with 2FA on could never turn it off again.
func TestDisablingTwoFactorOpensTheSealedSeed(t *testing.T) {
	initSecret(t)
	const seed = "JBSWY3DPEHPK3PXP"
	code, err := totpCodeFor(seed)
	if err != nil {
		t.Fatalf("build a valid code: %v", err)
	}
	sealed, err := SealTOTPSecret(seed, 7)
	if err != nil {
		t.Fatalf("SealTOTPSecret: %v", err)
	}
	// The disable path reads the last accepted step beside the seed, because it
	// verifies with the replay-protected form.
	script := &totpScript{rows: map[string][]driver.Value{
		"SELECT totp_secret, totp_last_step FROM users": {sealed, int64(-1)},
	}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/me/2fa/disable", strings.NewReader(`{"code":"`+code+`"}`))
	request = request.WithContext(WithClaims(request.Context(),
		&Claims{UserID: 7, Username: "operator", Role: "admin"}))

	(&Handlers{DB: totpDB(t, script)}).TwoFADisable(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
}

// Login is the third place that reads the column. It must open the seal, or
// every operator with 2FA on is locked out of the panel the moment the backfill
// converts their row.
func TestLoginOpensTheSealedSeed(t *testing.T) {
	initSecret(t)
	const seed = "JBSWY3DPEHPK3PXP"
	code, err := totpCodeFor(seed)
	if err != nil {
		t.Fatalf("build a valid code: %v", err)
	}
	sealed, err := SealTOTPSecret(seed, 7)
	if err != nil {
		t.Fatalf("SealTOTPSecret: %v", err)
	}
	script := &totpScript{rows: map[string][]driver.Value{
		// Order matches the SELECT in Login.
		"password_hash, role, status": {int64(7), "operator", mustHash(t, "correct-horse"), "admin", "active", "Operator"},
		"totp_enabled, totp_secret":   {int64(1), sealed, int64(0)},
		"SELECT token_version":        {int64(1)},
	}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/login",
		strings.NewReader(`{"username":"operator","password":"correct-horse","code":"`+code+`"}`))

	(&Handlers{DB: totpDB(t, script), Secret: []byte(strings.Repeat("k", 32)), LifetimeSec: 3600}).
		Login(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "two_factor_required") {
		t.Fatal("the code was not accepted")
	}
}

func mustHash(t *testing.T, password string) string {
	t.Helper()
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	return hash
}

// totpCodeFor produces the code an authenticator would show right now, from the
// package's own generator rather than by searching the six-digit space.
func totpCodeFor(seed string) (string, error) {
	code, ok := hotp(seed, uint64(time.Now().Unix()/30))
	if !ok {
		return "", errors.New("the seed did not produce a code")
	}
	return code, nil
}
