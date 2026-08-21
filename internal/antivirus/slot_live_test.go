package antivirus

// The scan slot, exercised against a real MariaDB.
//
// A named lock is a server-side object, so an in-memory fake proves nothing
// about the property that matters: that a SECOND PROCESS is refused. The test
// is skipped without SERVIKA_TEST_DSN, and the CI gate runs the rest of the
// suite without it.

import (
	"context"
	"database/sql"
	"os"
	"strconv"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func liveDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("SERVIKA_TEST_DSN")
	if dsn == "" {
		t.Skip("SERVIKA_TEST_DSN is not set")
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

// The slot is held on the SERVER, so a second connection pool, which is what a
// separate process has, is refused. Without the database half this passes
// vacuously, because each pool has its own copy of the atomic.
func TestASecondProcessCannotTakeTheScanSlot(t *testing.T) {
	first := liveDB(t)
	second := liveDB(t)
	ctx := context.Background()

	held, err := takeScanSlot(ctx, first)
	if err != nil {
		t.Fatalf("the first caller could not take the slot: %v", err)
	}
	// The second pool's atomic is untouched, exactly as another process's would
	// be, so only the database lock can refuse this.
	scanning.Store(0)
	if _, err := takeScanSlot(ctx, second); err == nil {
		t.Fatal("a second process took the slot while the first held it")
	}
	held.Release()

	again, err := takeScanSlot(ctx, second)
	if err != nil {
		t.Fatalf("the slot was not given back: %v", err)
	}
	again.Release()
}

// A process that dies holding the slot strands nothing: MariaDB releases a
// named lock when its connection drops. That is why this is a lock rather than
// a claim row, which would need a heal and would hold the slot for as long as
// the panel was down.
//
// The death is simulated with KILL rather than db.Close(), because Close does
// not tear down a connection that is still checked out as a *sql.Conn, so the
// lock would still be held and the test would be measuring nothing. KILL is
// what the SERVER sees when a process is killed.
func TestTheSlotIsGivenBackWhenTheConnectionDies(t *testing.T) {
	first := liveDB(t)
	second := liveDB(t)
	ctx := context.Background()

	held, err := takeScanSlot(ctx, first)
	if err != nil {
		t.Fatalf("the first caller could not take the slot: %v", err)
	}
	var threadID int64
	if err := held.conn.QueryRowContext(ctx, `SELECT CONNECTION_ID()`).Scan(&threadID); err != nil {
		t.Fatalf("the holder's connection id: %v", err)
	}
	// The second pool's atomic is untouched, as another process's would be.
	scanning.Store(0)
	if _, err := second.ExecContext(ctx, "KILL "+strconv.FormatInt(threadID, 10)); err != nil {
		t.Fatalf("the holder's connection could not be killed: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		got, err := takeScanSlot(ctx, second)
		if err == nil {
			got.Release()
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the slot was never given back after the holder's connection died")
		}
		time.Sleep(100 * time.Millisecond)
	}
}
