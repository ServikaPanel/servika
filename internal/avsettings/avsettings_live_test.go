package avsettings

// The settings row against a real MariaDB.
//
// Read and Write name their columns in two hand-written lists, and a name that
// drifts from the schema COMPILES. The failure only appears at runtime, as a
// setting that saves and then reads back as its zero value, which on this
// screen means a resource limit the operator set and the kernel never received.
// Nothing but a real server can catch that.
//
// The test is skipped without SERVIKA_TEST_DSN, the same condition
// internal/notifications and internal/antivirus already use.

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
	"testing"

	_ "github.com/go-sql-driver/mysql"
)

func liveSettingsDB(t *testing.T) *sql.DB {
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

// Every field survives a write and a read. A column missing from either list
// leaves its field at zero on the way back, and for a resource limit that reads
// as "automatic" rather than as an error.
func TestTheSettingsRowSurvivesARoundTrip(t *testing.T) {
	db := liveSettingsDB(t)
	ctx := context.Background()

	before, err := Read(ctx, db)
	if err != nil {
		t.Fatalf("the settings row could not be read: %v", err)
	}
	t.Cleanup(func() {
		if err := writeRow(ctx, db, before); err != nil {
			t.Errorf("the original row could not be put back: %v", err)
		}
	})

	// Nothing here may reach systemd: the row is what is being measured.
	restore := sliceCommand
	sliceCommand = func(string, ...string) *exec.Cmd { return exec.Command("true") }
	t.Cleanup(func() { sliceCommand = restore })

	want := Settings{
		RuleEngine: true, LocationHeuristics: false, WPIntegrity: true,
		CriticalThreshold: 77, AutoQuarantine: true,
		Scope: ScopeServer, ExcludedPaths: "/var/lib/mysql\n/proc",
		CPUPercent: 175, RAMMB: 512, IOWeight: 33, CPUWeight: 21,
		ScheduledScan: true, ScheduledHour: 4,
		Realtime: true, ScanWorkers: 6, FileRatePerSec: 250,
	}
	if err := writeRow(ctx, db, want); err != nil {
		t.Fatalf("the settings could not be written: %v", err)
	}
	got, err := Read(ctx, db)
	if err != nil {
		t.Fatalf("the settings could not be read back: %v", err)
	}
	if got != want {
		t.Errorf("the row did not survive the round trip\n got: %+v\nwant: %+v", got, want)
	}
}

// The automatic value is stored as 0 and stays 0 in the row. What turns it into
// a real weight is Resolve, on the way to the slice, so a 0 written back here
// is the row saying "automatic" rather than a value systemd would ignore.
func TestAnAutomaticWeightIsStoredAsZero(t *testing.T) {
	db := liveSettingsDB(t)
	ctx := context.Background()

	before, err := Read(ctx, db)
	if err != nil {
		t.Fatalf("the settings row could not be read: %v", err)
	}
	t.Cleanup(func() {
		if err := writeRow(ctx, db, before); err != nil {
			t.Errorf("the original row could not be put back: %v", err)
		}
	})

	s := before
	s.CPUWeight = 0
	if err := writeRow(ctx, db, s); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := Read(ctx, db)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.CPUWeight != 0 {
		t.Errorf("an automatic weight came back as %d", got.CPUWeight)
	}
	if resolved := got.Resolve(ServerCapacity()).CPUWeight; resolved != defaultCPUWeight {
		t.Errorf("the stored zero resolved to %d, want %d", resolved, defaultCPUWeight)
	}
}
