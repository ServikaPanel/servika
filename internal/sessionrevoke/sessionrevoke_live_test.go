package sessionrevoke

// The revocation list against a real MariaDB.
//
// Every statement here names a column of a table this package's own migration
// creates, and a name that drifts from the schema COMPILES. The failure appears
// only at runtime, as a logout that writes nothing and a session that keeps
// working, which is exactly the defect the table exists to close. Nothing but a
// real server can catch that.
//
// The test is skipped without SERVIKA_TEST_DSN, the same condition
// internal/avsettings and internal/antivirus already use.

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func liveDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("SERVIKA_TEST_DSN")
	if dsn == "" {
		t.Skip("SERVIKA_TEST_DSN is unset, so there is no server to ask")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// clean removes the identifiers a case wrote, so a rerun starts from the same
// state as the first run.
func clean(t *testing.T, db *sql.DB, jtis ...string) {
	t.Helper()
	t.Cleanup(func() {
		for _, jti := range jtis {
			_, _ = db.Exec(`DELETE FROM revoked_sessions WHERE jti=?`, jti)
		}
	})
}

// The round trip the logout path depends on: a written identifier reads back as
// listed, and one nobody wrote reads back as not listed.
func TestAWrittenIdentifierReadsBackAsListed(t *testing.T) {
	db := liveDB(t)
	const listed = "live-test-listed-identifier"
	const absent = "live-test-absent-identifier"
	clean(t, db, listed, absent)

	if err := Revoke(context.Background(), db, listed, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	count, err := Listed(context.Background(), db, listed)
	if err != nil {
		t.Fatalf("Listed: %v", err)
	}
	if count != 1 {
		t.Errorf("the written identifier reads back as %d, want 1", count)
	}
	count, err = Listed(context.Background(), db, absent)
	if err != nil {
		t.Fatalf("Listed for an absent identifier: %v", err)
	}
	if count != 0 {
		t.Errorf("an identifier nobody wrote reads back as %d, want 0", count)
	}
}

// Two tabs both firing the logout is not an error. Without INSERT IGNORE the
// second write fails on the primary key and the handler logs a fault for a
// request that did exactly what it should.
func TestWritingTheSameIdentifierTwiceIsNotAnError(t *testing.T) {
	db := liveDB(t)
	const jti = "live-test-repeated-identifier"
	clean(t, db, jti)

	expires := time.Now().Add(time.Hour)
	if err := Revoke(context.Background(), db, jti, expires); err != nil {
		t.Fatalf("the first write: %v", err)
	}
	if err := Revoke(context.Background(), db, jti, expires); err != nil {
		t.Fatalf("the second write: %v", err)
	}
}

// A row stops mattering when the token it names expires, because the token is
// refused on its own exp. Without the sweep the table keeps every signed-out
// session for the life of the installation.
func TestTheSweepRemovesOnlyTheExpiredRows(t *testing.T) {
	db := liveDB(t)
	const dead = "live-test-expired-identifier"
	const live = "live-test-live-identifier"
	clean(t, db, dead, live)

	if err := Revoke(context.Background(), db, dead, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("write the expired row: %v", err)
	}
	if err := Revoke(context.Background(), db, live, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("write the live row: %v", err)
	}

	sweep(context.Background(), db)

	count, err := Listed(context.Background(), db, dead)
	if err != nil {
		t.Fatalf("Listed after the sweep: %v", err)
	}
	if count != 0 {
		t.Error("the sweep kept a row whose token had already expired")
	}
	count, err = Listed(context.Background(), db, live)
	if err != nil {
		t.Fatalf("Listed after the sweep: %v", err)
	}
	if count != 1 {
		t.Error("the sweep removed a row whose token is still valid")
	}
}
