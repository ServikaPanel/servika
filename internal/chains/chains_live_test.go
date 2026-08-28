package chains

// Live-database tests for the correlator's SQL. They are skipped without
// SERVIKA_TEST_DSN, so a plain `go test ./...` still passes without a database;
// set the variable when a change touches these queries or the schema.

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/go-sql-driver/mysql"
)

const testDomainID = 990001

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

// setup gives the test a clean slate and a real domains row, because
// notifications carries a foreign key to domains; in production the chain's
// domain_id always names a live tenant.
func setup(t *testing.T, db *sql.DB) {
	t.Helper()
	clean(t, db)
	if _, err := db.Exec(
		`INSERT INTO domains (id, domain_name, system_user) VALUES (?,?,?)`,
		testDomainID, "chain-test.example", "c_chaintest"); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	t.Cleanup(func() { clean(t, db) })
}

// clean removes the test's rows. Deleting the domain cascades its notifications,
// so the av_chain notifications go with it.
func clean(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, q := range []string{
		`DELETE FROM av_events WHERE domain_id=?`,
		`DELETE FROM av_chains WHERE domain_id=?`,
		`DELETE FROM domains WHERE id=?`,
	} {
		if _, err := db.Exec(q, testDomainID); err != nil {
			t.Fatalf("clean: %v", err)
		}
	}
}

// A dropped file executed from the SAME path is a causal chain: critical,
// confidence 85, plus one notification.
func TestRunCorrelatesCausalChain(t *testing.T) {
	db := liveDB(t)
	setup(t, db)

	dropped := "/home/c_chaintest/public_html/.x"
	WriteEvent(db, testDomainID, "file", "file_write", "critical", ".x", dropped, 0, "av_scan", 1)
	WriteEvent(db, testDomainID, "process", "execution", "critical", "", dropped, 4242, "av_proc", 0)

	if err := Run(db); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var stages string
	var confidence int
	if err := db.QueryRow(`SELECT stages, confidence FROM av_chains WHERE domain_id=?`, testDomainID).
		Scan(&stages, &confidence); err != nil {
		t.Fatalf("no chain written: %v", err)
	}
	if stages != "file_write>execution" {
		t.Fatalf("stages = %q, want file_write>execution", stages)
	}
	if confidence != 85 {
		t.Fatalf("confidence = %d, want 85 (55 + 25 causal + 5 ordered)", confidence)
	}

	var level string
	var notes int
	if err := db.QueryRow(
		`SELECT level, COUNT(*) FROM notifications WHERE domain_id=? AND ref_type='av_chain'`, testDomainID).
		Scan(&level, &notes); err != nil {
		t.Fatalf("count notifications: %v", err)
	}
	if notes != 1 || level != "critical" {
		t.Fatalf("notifications: count=%d level=%q, want 1 critical", notes, level)
	}
}

// Two INDEPENDENT signals (different paths, no shared pid) still form a chain but
// stay a warning: the FP-laundering gate. This is the whole point of causality.
func TestRunIndependentSignalsStayWarning(t *testing.T) {
	db := liveDB(t)
	setup(t, db)

	WriteEvent(db, testDomainID, "file", "file_write", "critical", "a.php", "/home/c_chaintest/public_html/a.php", 0, "av_scan", 1)
	WriteEvent(db, testDomainID, "process", "execution", "critical", "", "/usr/sbin/php-fpm", 5, "av_proc", 0)
	if err := Run(db); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var level string
	if err := db.QueryRow(
		`SELECT level FROM notifications WHERE domain_id=? AND ref_type='av_chain'`, testDomainID).
		Scan(&level); err != nil {
		t.Fatalf("no notification written: %v", err)
	}
	if level != "warning" {
		t.Fatalf("independent signals should be a warning, got %q", level)
	}
}

// A single stage is not a chain: nothing is written.
func TestRunSingleStageIsNotAChain(t *testing.T) {
	db := liveDB(t)
	setup(t, db)

	WriteEvent(db, testDomainID, "file", "file_write", "critical", "shell.php", "/home/c_chaintest/public_html/shell.php", 0, "av_scan", 1)
	if err := Run(db); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM av_chains WHERE domain_id=?`, testDomainID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("a single stage produced %d chains, want 0", n)
	}
}

// The insert-dedup drops a repeat of the same (domain, stage, path) within the
// window, so two file_write events for one path count as one event.
func TestWriteEventInsertDedup(t *testing.T) {
	db := liveDB(t)
	setup(t, db)

	path := "/home/c_chaintest/public_html/shell.php"
	WriteEvent(db, testDomainID, "file", "file_write", "critical", "shell.php", path, 0, "av_scan", 1)
	WriteEvent(db, testDomainID, "file", "file_write", "critical", "shell.php", path, 0, "av_scan", 1)
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM av_events WHERE domain_id=?`, testDomainID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("insert-dedup: %d events, want 1", n)
	}
}

// The same chain is not reported twice inside the re-dedup window.
func TestRunDedupsWithinWindow(t *testing.T) {
	db := liveDB(t)
	setup(t, db)

	dropped := "/home/c_chaintest/public_html/.x"
	WriteEvent(db, testDomainID, "file", "file_write", "critical", ".x", dropped, 0, "av_scan", 1)
	WriteEvent(db, testDomainID, "process", "execution", "critical", "", dropped, 4242, "av_proc", 0)
	if err := Run(db); err != nil {
		t.Fatalf("Run 1: %v", err)
	}
	if err := Run(db); err != nil {
		t.Fatalf("Run 2: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM av_chains WHERE domain_id=?`, testDomainID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("the same chain was written %d times, want 1 (dedup)", n)
	}
}
