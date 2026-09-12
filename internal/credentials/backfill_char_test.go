package credentials

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"

	"servika/internal/secret"
)

// The FTP backfill has ONE chance to do its job: while the cleartext is still
// readable it must write both the hash Pure-FTPd will verify against and the
// encrypted copy the panel shows the customer. After it writes the hash the
// cleartext is gone. These pin that both land, and that a failure stops rather
// than walking on with rows half converted.

// ftpScript is a database holding the ftp_accounts rows one pass reads.
type ftpScript struct {
	rows     [][]driver.Value
	queryErr error
	rowErr   error
	execErr  error
	execs    [][]driver.Value
}

type ftpConn struct{ script *ftpScript }

func (c ftpConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c ftpConn) Driver() driver.Driver                        { return ftpDriver{} }
func (c ftpConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c ftpConn) Close() error                                 { return nil }
func (c ftpConn) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (c ftpConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	if c.script.queryErr != nil {
		return nil, c.script.queryErr
	}
	return &ftpRows{script: c.script}, nil
}

func (c ftpConn) ExecContext(_ context.Context, _ string, args []driver.NamedValue) (driver.Result, error) {
	plain := make([]driver.Value, 0, len(args))
	for _, arg := range args {
		plain = append(plain, arg.Value)
	}
	c.script.execs = append(c.script.execs, plain)
	if c.script.execErr != nil {
		return nil, c.script.execErr
	}
	return ftpResult{}, nil
}

type ftpRows struct {
	script *ftpScript
	at     int
}

func (r *ftpRows) Columns() []string { return []string{"id", "password_md5"} }
func (r *ftpRows) Close() error      { return nil }
func (r *ftpRows) Next(dest []driver.Value) error {
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

type ftpResult struct{}

func (ftpResult) LastInsertId() (int64, error) { return 1, nil }
func (ftpResult) RowsAffected() (int64, error) { return 1, nil }

type ftpDriver struct{}

func (ftpDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

func ftpDB(t *testing.T, script *ftpScript) *sql.DB {
	t.Helper()
	db := sql.OpenDB(ftpConn{script: script})
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func initBackfillSecret(t *testing.T) {
	t.Helper()
	if err := secret.Init([]byte("test-key-for-credential-backfill-0123456789")); err != nil {
		t.Fatalf("secret.Init: %v", err)
	}
}

// Both values are written in the SAME statement, because after the hash lands
// the cleartext that produced the encrypted copy is gone.
func TestTheBackfillWritesTheHashAndTheEncryptedCopyTogether(t *testing.T) {
	initBackfillSecret(t)
	script := &ftpScript{rows: [][]driver.Value{{int64(3), "hunter2"}}}

	migrated, err := BackfillCleartextPasswords(ftpDB(t, script))

	if err != nil || migrated != 1 {
		t.Fatalf("BackfillCleartextPasswords = %d, %v", migrated, err)
	}
	if len(script.execs) != 1 || len(script.execs[0]) != 3 {
		t.Fatalf("statements = %v", script.execs)
	}
	got := script.execs[0]
	hash, _ := got[0].(string)
	if !IsHashed(hash) || !VerifyPassword(hash, "hunter2") {
		t.Errorf("the stored hash does not verify the original password: %q", hash)
	}
	sealed, _ := got[1].(string)
	back, err := secret.Decrypt(sealed)
	if err != nil || back != "hunter2" {
		t.Errorf("the encrypted copy = %q, %v", back, err)
	}
	if got[2] != int64(3) {
		t.Errorf("wrote row %v, want 3", got[2])
	}
}

// The pass runs at every startup, so a row that is already hashed must be left
// alone: re-hashing it would store the hash of a hash and lock the account out.
func TestAnAlreadyHashedRowIsSkipped(t *testing.T) {
	initBackfillSecret(t)
	hash, err := HashPassword("hunter2")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	script := &ftpScript{rows: [][]driver.Value{{int64(3), hash}}}

	migrated, err := BackfillCleartextPasswords(ftpDB(t, script))

	if err != nil || migrated != 0 {
		t.Fatalf("BackfillCleartextPasswords = %d, %v", migrated, err)
	}
	if len(script.execs) != 0 {
		t.Errorf("a hashed row was rewritten: %v", script.execs)
	}
}

// Every cleartext row in the list is converted, and the count is what the
// caller logs at startup.
func TestEveryCleartextRowIsCounted(t *testing.T) {
	initBackfillSecret(t)
	hash, err := HashPassword("already")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	script := &ftpScript{rows: [][]driver.Value{
		{int64(1), "one-password"},
		{int64(2), hash},
		{int64(3), "another-password"},
	}}

	migrated, err := BackfillCleartextPasswords(ftpDB(t, script))

	if err != nil || migrated != 2 {
		t.Fatalf("BackfillCleartextPasswords = %d, %v, want 2", migrated, err)
	}
}

// A failure STOPS the pass and is reported with the count so far, because the
// caller decides whether a partially converted table may start the panel.
func TestAFailureStopsThePassAndReportsWhatWasDone(t *testing.T) {
	for _, tc := range []struct {
		name     string
		script   *ftpScript
		migrated int
	}{
		{
			name:   "the table cannot be read",
			script: &ftpScript{queryErr: errors.New("table does not exist")},
		},
		{
			name: "a row cannot be read",
			script: &ftpScript{rows: [][]driver.Value{
				{nil, "hunter2"},
				{int64(2), "hunter3"},
			}},
		},
		{
			name: "the list ends early",
			script: &ftpScript{
				rows:   [][]driver.Value{{int64(1), "hunter2"}},
				rowErr: errors.New("lost connection"),
			},
		},
		{
			name: "the write is refused",
			script: &ftpScript{
				rows:    [][]driver.Value{{int64(1), "hunter2"}},
				execErr: errors.New("refused"),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			initBackfillSecret(t)

			migrated, err := BackfillCleartextPasswords(ftpDB(t, tc.script))

			if err == nil {
				t.Fatal("the failure was reported as a completed pass")
			}
			if migrated != tc.migrated {
				t.Errorf("reported %d migrated rows, want %d", migrated, tc.migrated)
			}
		})
	}
}

// The rule a customer-chosen database password is measured against, and the
// English reason each refusal carries to the screen.
func TestStrongPasswordNamesWhatIsMissing(t *testing.T) {
	for _, tc := range []struct {
		name, password string
		ok             bool
		reason         string
	}{
		{name: "letters and digits over twelve characters", password: "correct1horse", ok: true},
		{name: "punctuation is allowed", password: "correct-1-horse!", ok: true},
		{
			name: "a line break", password: "correct1horse\nbattery",
			reason: "password contains invalid characters (line breaks or control chars)",
		},
		{
			name: "a NUL byte", password: "correct1horse\x00",
			reason: "password contains invalid characters (line breaks or control chars)",
		},
		// Measured: only CR, LF and NUL are refused. A bell character is not,
		// because the rule guards the config files the value is written into,
		// which are line based.
		{name: "a bell character", password: "correct1horse\x07", ok: true},
		{name: "eleven characters", password: "correct1hor", reason: "password must be at least 12 characters"},
		{name: "empty", password: "", reason: "password must be at least 12 characters"},
		{name: "no digit", password: "correcthorsebattery", reason: "password must contain both letters and digits"},
		{name: "no letter", password: "1234567890123", reason: "password must contain both letters and digits"},
		{name: "neither", password: "-------------", reason: "password must contain both letters and digits"},
		// Measured: the letter rule is ASCII only, so a password written in
		// another alphabet is refused for having no letter even though it does.
		{name: "twelve non-ASCII characters and a digit", password: "şşşşşşşşşşş1",
			reason: "password must contain both letters and digits"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := StrongPassword(tc.password)

			if ok != tc.ok {
				t.Fatalf("StrongPassword(%q) = %v, want %v (%q)", tc.password, ok, tc.ok, reason)
			}
			if reason != tc.reason {
				t.Errorf("reason = %q, want %q", reason, tc.reason)
			}
		})
	}
}

// The length rule counts CHARACTERS, not bytes: a byte count would refuse a
// password an operator can legitimately type. Measured through the reason,
// because the letter rule refuses this password for a different cause.
func TestTheLengthRuleCountsCharactersNotBytes(t *testing.T) {
	long := strings.Repeat("ş", 11) + "a1" // 13 characters, 24 bytes
	if ok, reason := StrongPassword(long); !ok {
		t.Errorf("a thirteen character password was refused: %s", reason)
	}
	short := strings.Repeat("ş", 9) + "a1" // 11 characters, 20 bytes
	if _, reason := StrongPassword(short); reason != "password must be at least 12 characters" {
		t.Errorf("an eleven character password was refused as %q", reason)
	}
}
