package backups

import (
	"strings"
	"testing"
)

// An archive that carried no database dump at all yields an EMPTY result set,
// so every counter is zero, including skipped. That is the reachable shape: a
// backup whose dumps failed writes no __db__/*.sql, and the fallback scan for a
// top-level *.sql finds nothing either.
func TestAnArchiveWithNoDumpCountsZeroSkipped(t *testing.T) {
	restored, skipped, failed, _ := dbSummary(nil)

	if restored != 0 || failed != 0 {
		t.Fatalf("restored=%d failed=%d, want 0 and 0", restored, failed)
	}
	if skipped != 0 {
		t.Fatalf("skipped=%d, want 0; a guard keyed on skipped > 0 would let this pass", skipped)
	}
}

// A full restore that restored zero databases is not a successful recovery: the
// site files came back and nothing it connects to did. The guard must test
// `restored` alone.
//
// `restored == 0 && skipped > 0` encodes one SYMPTOM, an empty ownership
// whitelist skipping every database. The invariant is that a full restore
// restores at least one database, which is what the database-only mode already
// used. Both full-restore paths carried the symptom version.
func TestAFullRestoreFailsWhenNoDatabaseCameBack(t *testing.T) {
	for _, file := range []string{"restore.go", "jobs.go"} {
		body := readBackupSource(t, file)
		if strings.Contains(body, "restored == 0 && skipped > 0") {
			t.Errorf("%s still guards the full restore on the symptom rather than the invariant", file)
		}
		if !strings.Contains(body, "no database was restored") {
			t.Errorf("%s no longer refuses a full restore that restored nothing", file)
		}
	}
}

// The database-only mode keeps its own two messages, because there it matters
// whether the archive HELD no database or every one was refused.
func TestTheDatabaseOnlyModeStillSeparatesItsTwoCases(t *testing.T) {
	for _, file := range []string{"restore.go", "jobs.go"} {
		if !strings.Contains(readBackupSource(t, file), "the backup has no database to restore") {
			t.Errorf("%s lost the database-only mode's empty-archive message", file)
		}
	}
}
