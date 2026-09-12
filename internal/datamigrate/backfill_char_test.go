package datamigrate

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"log"
	"strings"
	"testing"

	"servika/internal/auth"
	"servika/internal/secret"
)

// Two backfills seal a column that was written in the clear before the seal
// existed. Both run at EVERY boot, so what matters is that a converged database
// is left alone, that a row which cannot be sealed is left in the clear rather
// than half written, and that a value saved between the read and the write is
// not overwritten with a re-sealed stale one.

// A scripted database: the repository carries no sqlmock dependency.
type backfillScript struct {
	// rows is what the list query answers, in SELECT order.
	rows [][]driver.Value
	// queryErr fails the list query itself.
	queryErr error
	// rowErr is reported after the last row, as a truncated result would be.
	rowErr error
	// execErr fails every write.
	execErr error

	execs []backfillExec
}

type backfillExec struct {
	query string
	args  []driver.Value
}

// argsOf returns the arguments of the nth recorded write.
func (s *backfillScript) argsOf(t *testing.T, n int) []driver.Value {
	t.Helper()
	if n >= len(s.execs) {
		t.Fatalf("only %d statements ran, wanted number %d", len(s.execs), n+1)
	}
	return s.execs[n].args
}

type backfillConn struct{ script *backfillScript }

func (c backfillConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c backfillConn) Driver() driver.Driver                        { return backfillDriver{} }
func (c backfillConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c backfillConn) Close() error                                 { return nil }
func (c backfillConn) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (c backfillConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	if c.script.queryErr != nil {
		return nil, c.script.queryErr
	}
	return &backfillRows{script: c.script}, nil
}

func (c backfillConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	plain := make([]driver.Value, 0, len(args))
	for _, arg := range args {
		plain = append(plain, arg.Value)
	}
	c.script.execs = append(c.script.execs, backfillExec{query: query, args: plain})
	if c.script.execErr != nil {
		return nil, c.script.execErr
	}
	return backfillResult{}, nil
}

type backfillRows struct {
	script *backfillScript
	at     int
}

func (r *backfillRows) Columns() []string {
	if len(r.script.rows) == 0 {
		return []string{"a", "b", "c"}
	}
	return make([]string, len(r.script.rows[0]))
}

func (r *backfillRows) Close() error { return nil }

func (r *backfillRows) Next(dest []driver.Value) error {
	if r.at >= len(r.script.rows) {
		if r.script.rowErr != nil {
			return r.script.rowErr
		}
		return io.EOF
	}
	copy(dest, r.script.rows[r.at])
	r.at++
	return nil
}

type backfillResult struct{}

func (backfillResult) LastInsertId() (int64, error) { return 1, nil }
func (backfillResult) RowsAffected() (int64, error) { return 1, nil }

type backfillDriver struct{}

func (backfillDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

func backfillDB(t *testing.T, script *backfillScript) *sql.DB {
	t.Helper()
	db := sql.OpenDB(backfillConn{script: script})
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// initSecret gives the package a key, which sealing needs.
func initSecret(t *testing.T) {
	t.Helper()
	if err := secret.Init([]byte("test-key-for-credential-backfill-0123456789")); err != nil {
		t.Fatalf("secret.Init: %v", err)
	}
}

// captureLog collects what a pass reports.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previousOutput, previousFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(previousOutput)
		log.SetFlags(previousFlags)
	})
	return &buf
}

// A cleartext Redis password is sealed against the row's OWN system_user, so a
// ciphertext lifted from one tenant's row does not open in another's.
func TestACleartextRedisPasswordIsSealedAgainstItsOwnTenant(t *testing.T) {
	initSecret(t)
	captureLog(t)
	script := &backfillScript{rows: [][]driver.Value{{int64(4), "c_acme", "hunter2"}}}

	EncryptRedisPasswords(context.Background(), backfillDB(t, script))

	got := script.argsOf(t, 0)
	if len(got) != 3 || got[1] != int64(4) || got[2] != "hunter2" {
		t.Fatalf("write args = %v, want the old value matched on domain 4", got)
	}
	sealed, _ := got[0].(string)
	if !secret.IsEncrypted(sealed) {
		t.Fatalf("the written value is not sealed: %q", sealed)
	}
	back, err := secret.DecryptWith(sealed, "c_acme")
	if err != nil || back != "hunter2" {
		t.Errorf("DecryptWith(own tenant) = %q, %v", back, err)
	}
	if _, err := secret.DecryptWith(sealed, "c_other"); err == nil {
		t.Error("the ciphertext opened under another tenant's name")
	}
}

// A cleartext TOTP seed is sealed against the user id for the same reason: a
// seed copied between rows would let one account's authenticator satisfy
// another account's second factor.
func TestACleartextTOTPSeedIsSealedAgainstItsOwnUser(t *testing.T) {
	initSecret(t)
	captureLog(t)
	script := &backfillScript{rows: [][]driver.Value{{int64(9), "JBSWY3DPEHPK3PXP"}}}

	EncryptTOTPSecrets(context.Background(), backfillDB(t, script))

	got := script.argsOf(t, 0)
	if len(got) != 3 || got[1] != int64(9) || got[2] != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("write args = %v, want the old value matched on user 9", got)
	}
	sealed, _ := got[0].(string)
	back, err := auth.OpenTOTPSecret(sealed, 9)
	if err != nil || back != "JBSWY3DPEHPK3PXP" {
		t.Errorf("OpenTOTPSecret(own user) = %q, %v", back, err)
	}
	if _, err := auth.OpenTOTPSecret(sealed, 10); err == nil {
		t.Error("the sealed seed opened under another user's id")
	}
}

// Both passes run at every boot, so an already-sealed value must not be sealed
// a second time.
func TestAConvergedDatabaseIsLeftAlone(t *testing.T) {
	initSecret(t)
	captureLog(t)
	sealedPassword, err := secret.EncryptWith("hunter2", "c_acme")
	if err != nil {
		t.Fatalf("EncryptWith: %v", err)
	}
	sealedSeed, err := auth.SealTOTPSecret("JBSWY3DPEHPK3PXP", 9)
	if err != nil {
		t.Fatalf("SealTOTPSecret: %v", err)
	}

	redis := &backfillScript{rows: [][]driver.Value{{int64(4), "c_acme", sealedPassword}}}
	EncryptRedisPasswords(context.Background(), backfillDB(t, redis))
	totp := &backfillScript{rows: [][]driver.Value{{int64(9), sealedSeed}}}
	EncryptTOTPSecrets(context.Background(), backfillDB(t, totp))

	if len(redis.execs) != 0 || len(totp.execs) != 0 {
		t.Errorf("a converged database was written to: %d redis, %d totp",
			len(redis.execs), len(totp.execs))
	}
}

// A row that cannot be read is skipped and the rest of the pass goes on: one
// unreadable row must not leave every other value in the clear.
func TestAnUnreadableRowDoesNotStopThePass(t *testing.T) {
	initSecret(t)
	logged := captureLog(t)
	script := &backfillScript{rows: [][]driver.Value{
		{nil, "c_acme", "hunter2"}, // a NULL domain id fails the scan
		{int64(5), "c_beta", "hunter3"},
	}}

	EncryptRedisPasswords(context.Background(), backfillDB(t, script))

	if len(script.execs) != 1 {
		t.Fatalf("wrote %d rows, want only the readable one", len(script.execs))
	}
	if got := script.argsOf(t, 0); got[1] != int64(5) {
		t.Errorf("wrote domain %v, want 5", got[1])
	}
	if !strings.Contains(logged.String(), "skipping an unreadable row") {
		t.Errorf("the skipped row was not reported: %s", logged.String())
	}
}

// A list that ends early is reported, because the count logged at the end would
// otherwise read as a complete pass over a table that still holds cleartext.
func TestATruncatedListIsReported(t *testing.T) {
	initSecret(t)
	logged := captureLog(t)
	script := &backfillScript{
		rows:   [][]driver.Value{{int64(4), "c_acme", "hunter2"}},
		rowErr: errors.New("lost connection"),
	}

	EncryptRedisPasswords(context.Background(), backfillDB(t, script))

	if !strings.Contains(logged.String(), "could not read the whole list") {
		t.Errorf("a truncated list was not reported: %s", logged.String())
	}
}

// A table that is not there yet is an install predating the feature, not a
// failure to act on.
func TestAMissingTableEndsThePassQuietly(t *testing.T) {
	initSecret(t)
	logged := captureLog(t)
	script := &backfillScript{queryErr: errors.New("table does not exist")}

	EncryptRedisPasswords(context.Background(), backfillDB(t, script))

	if len(script.execs) != 0 {
		t.Error("a pass that could not read the table still wrote")
	}
	if !strings.Contains(logged.String(), "could not read domain_redis") {
		t.Errorf("the read failure was not reported: %s", logged.String())
	}
}

// A write that fails leaves the value in the clear and does not count towards
// the total: a value the panel can no longer decrypt is worse than one still
// readable, and a wrong count hides the rows that were missed.
func TestAFailedWriteIsNotCounted(t *testing.T) {
	initSecret(t)
	logged := captureLog(t)
	script := &backfillScript{
		rows:    [][]driver.Value{{int64(4), "c_acme", "hunter2"}},
		execErr: errors.New("refused"),
	}

	EncryptRedisPasswords(context.Background(), backfillDB(t, script))

	body := logged.String()
	if !strings.Contains(body, "could not write domain 4") {
		t.Errorf("the failed write was not reported: %s", body)
	}
	if strings.Contains(body, "encrypted 1") {
		t.Errorf("a failed write was counted as migrated: %s", body)
	}
}

// The seed pass answers each failure the same way the password pass does: a
// row it cannot read is skipped, a list that ends early is reported, a table it
// cannot read ends the pass, and a write that fails leaves the seed readable.
func TestTheSeedPassAnswersEveryFailureTheSameWay(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script *backfillScript
		writes int
		logged string
	}{
		{
			name: "a row that cannot be read",
			script: &backfillScript{rows: [][]driver.Value{
				{nil, "JBSWY3DPEHPK3PXP"},
				{int64(9), "JBSWY3DPEHPK3PXP"},
			}},
			writes: 1, logged: "skipping an unreadable row",
		},
		{
			name: "a list that ends early",
			script: &backfillScript{
				rows:   [][]driver.Value{{int64(9), "JBSWY3DPEHPK3PXP"}},
				rowErr: errors.New("lost connection"),
			},
			writes: 1, logged: "could not read the whole list",
		},
		{
			name:   "a table that cannot be read",
			script: &backfillScript{queryErr: errors.New("table does not exist")},
			logged: "could not read the list",
		},
		{
			name: "a write that fails",
			script: &backfillScript{
				rows:    [][]driver.Value{{int64(9), "JBSWY3DPEHPK3PXP"}},
				execErr: errors.New("refused"),
			},
			writes: 1, logged: "could not write user 9",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			initSecret(t)
			logged := captureLog(t)

			EncryptTOTPSecrets(context.Background(), backfillDB(t, tc.script))

			if len(tc.script.execs) != tc.writes {
				t.Errorf("wrote %d rows, want %d", len(tc.script.execs), tc.writes)
			}
			if !strings.Contains(logged.String(), tc.logged) {
				t.Errorf("the pass did not report %q: %s", tc.logged, logged.String())
			}
		})
	}
}

// Every sealed row is counted once, and the count is only logged when there was
// something to do.
func TestOnlyAPassThatChangedSomethingReportsACount(t *testing.T) {
	initSecret(t)
	logged := captureLog(t)
	script := &backfillScript{rows: [][]driver.Value{
		{int64(4), "c_acme", "hunter2"},
		{int64(5), "c_beta", "hunter3"},
	}}

	EncryptRedisPasswords(context.Background(), backfillDB(t, script))
	EncryptRedisPasswords(context.Background(), backfillDB(t, &backfillScript{}))

	if !strings.Contains(logged.String(), "encrypted 2 cleartext password(s)") {
		t.Errorf("the count is wrong: %s", logged.String())
	}
	if strings.Count(logged.String(), "encrypted") != 1 {
		t.Errorf("an empty pass reported a count: %s", logged.String())
	}
}
