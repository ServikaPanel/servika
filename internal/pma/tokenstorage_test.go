package pma

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// RequestToken decrypted db_accounts.db_pass_plain and INSERTed the plaintext
// into pma_tokens.db_pass, a plain column. That defeated the at-rest encryption
// of db_pass_plain for every database whose owner ever opened phpMyAdmin, and
// put a reusable cleartext tenant database password into every panel database
// dump, which the backup tool also uploads off-site.
func TestTheTokenCarriesNoCredential(t *testing.T) {
	body := readPMASource(t, "pma.go")
	mint := pmaFunction(t, body, "func (h *Handlers) RequestToken(")

	if strings.Contains(mint, "db_pass") {
		t.Error("RequestToken still touches a password column while minting a token")
	}
	if strings.Contains(mint, "DecryptDBPass") {
		t.Error("RequestToken still decrypts the password, so it holds the cleartext")
	}
	if !strings.Contains(mint, "db_account_id") {
		t.Error("RequestToken does not store a reference to the account")
	}
}

// The credential is read from db_accounts at redemption time instead, so it
// exists in exactly one place at rest.
func TestRedeemReadsThePasswordFromTheAccountRow(t *testing.T) {
	body := readPMASource(t, "pma.go")
	// Redeem reads the account through liveToken and decrypts what it returned.
	lookup := pmaFunction(t, body, "func (h *Handlers) liveToken(")
	redeem := pmaFunction(t, body, "func (h *Handlers) Redeem(")

	if !strings.Contains(lookup, "JOIN db_accounts a ON a.id=t.db_account_id") {
		t.Error("Redeem does not resolve the account through the token's reference")
	}
	if !strings.Contains(redeem, "credentials.DecryptDBPass(found.dbUser, found.storedPassword)") {
		t.Error("Redeem does not decrypt the sealed password")
	}
	// An INNER join, so a token whose account was deleted inside the two-minute
	// window answers "not found" rather than serving a stale credential.
	if strings.Contains(lookup, "LEFT JOIN db_accounts") {
		t.Error("Redeem tolerates a token whose account no longer exists")
	}
}

// The only cleanup used to be issued inside RequestToken, so a used or expired
// row was removed only when somebody minted the NEXT token: on a panel where
// nobody does, the last rows survive for the life of the installation.
func TestDeadTokensAreSweptOnATimer(t *testing.T) {
	body := readPMASource(t, "sweep.go")
	if !strings.Contains(body, "func StartTokenSweep(") {
		t.Fatal("there is no scheduled sweep")
	}
	if !strings.Contains(body, "time.NewTicker(sweepInterval)") {
		t.Error("the sweep does not repeat")
	}
	// The startup pass matters on its own: a panel stopped while tokens were
	// live comes back with rows nothing else would delete.
	if !strings.Contains(body, "sweepTokens(ctx, db)\n\t\tticker :=") {
		t.Error("the sweep does not run once at startup, before the first tick")
	}

	main, err := os.ReadFile("../../cmd/server/main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	if !strings.Contains(string(main), "pma.StartTokenSweep(") {
		t.Error("the sweep is never started")
	}
}

// And it actually deletes the right rows.
func TestTheSweepRemovesUsedAndExpiredTokensOnly(t *testing.T) {
	if !strings.Contains(sweepStatement, "expires_at < NOW()") {
		t.Error("the sweep does not remove expired tokens")
	}
	if !strings.Contains(sweepStatement, "used=1") {
		t.Error("the sweep does not remove consumed tokens")
	}
	if strings.Contains(sweepStatement, "used=0") {
		t.Error("the sweep would remove a token that is still valid")
	}

	script := &sweepScript{}
	db := sql.OpenDB(sweepConn{script: script})
	t.Cleanup(func() { _ = db.Close() })

	sweepTokens(context.Background(), db)

	if got := script.statements(); len(got) != 1 || got[0] != sweepStatement {
		t.Errorf("the sweep ran %v, want exactly the sweep statement", got)
	}
}

// The interval has to be short relative to the token's own lifetime, or a dead
// row outlives its validity by an order of magnitude.
func TestTheSweepIntervalIsShort(t *testing.T) {
	if sweepInterval > 15*time.Minute {
		t.Errorf("sweepInterval is %s, which leaves a dead token on disk far longer than its two-minute validity",
			sweepInterval)
	}
}

// A scripted driver that records the statements it was asked to execute. The
// repository carries no sqlmock dependency.
type sweepScript struct {
	mu   sync.Mutex
	seen []string
}

func (s *sweepScript) record(query string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, query)
}

func (s *sweepScript) statements() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...)
}

type sweepConn struct{ script *sweepScript }

func (c sweepConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c sweepConn) Driver() driver.Driver                        { return sweepDriver{} }
func (c sweepConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c sweepConn) Close() error                                 { return nil }
func (c sweepConn) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (c sweepConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.script.record(query)
	return sweepResult{}, nil
}

func (c sweepConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return sweepRows{}, nil
}

type sweepRows struct{}

func (sweepRows) Columns() []string              { return nil }
func (sweepRows) Close() error                   { return nil }
func (sweepRows) Next([]driver.Value) error      { return io.EOF }
func (sweepResult) LastInsertId() (int64, error) { return 0, nil }
func (sweepResult) RowsAffected() (int64, error) { return 0, nil }

type sweepResult struct{}

type sweepDriver struct{}

func (sweepDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

func readPMASource(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(name) // #nosec G304 -- a file of this package.
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(body)
}

// pmaFunction returns one function's body, from its signature to the closing
// brace in the first column.
func pmaFunction(t *testing.T, source, signature string) string {
	t.Helper()
	at := strings.Index(source, signature)
	if at < 0 {
		t.Fatalf("%q is not defined", signature)
	}
	body, _, found := strings.Cut(source[at:], "\n}\n")
	if !found {
		t.Fatalf("%q has no closing brace", signature)
	}
	return body
}
