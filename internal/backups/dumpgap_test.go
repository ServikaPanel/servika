package backups

import (
	"os"
	"strings"
	"testing"
)

// A database the panel owns whose dump failed used to be recorded ONLY in the
// archive's own manifest, a file inside the artefact that no restore path, no
// endpoint and no screen ever reads. Everything an operator or a customer looks
// at is fed from the backups row, so the gap has to reach that row.
func TestTheBackupRowCarriesTheFailedDumps(t *testing.T) {
	notes := backupNotes("domain: example.com", []string{"c_x_main", "c_x_wp"})

	if !strings.Contains(notes, "domain: example.com") {
		t.Errorf("the original note was lost: %q", notes)
	}
	for _, name := range []string{"c_x_main", "c_x_wp"} {
		if !strings.Contains(notes, name) {
			t.Errorf("%s is not named in the note: %q", name, notes)
		}
	}
}

// A backup that dumped everything must read exactly as it did before, or every
// clean backup would carry a note about a gap that is not there.
func TestACompleteBackupsNoteIsUnchanged(t *testing.T) {
	const base = "domain: example.com"
	if got := backupNotes(base, nil); got != base {
		t.Fatalf("note = %q, want %q", got, base)
	}
	if got := backupNotes(base, []string{}); got != base {
		t.Fatalf("note = %q, want %q", got, base)
	}
}

// buildArchive hands the gap back to its callers rather than keeping it inside
// the archive, and it fails closed when NOTHING was dumped: an archive of a site
// whose every database dump failed is not a backup of that site.
//
// This reads the source because the behaviour lives in a function that needs a
// live MariaDB, a tenant home and a tar to run; what it pins is that the two
// decisions are still in it.
func TestBuildArchiveReportsTheGapAndFailsClosedOnATotalLoss(t *testing.T) {
	body := readBackupSource(t, "granular.go")

	if !strings.Contains(body, "(int64, []string, error)") {
		t.Error("buildArchive no longer returns the failed databases to its callers")
	}
	if !strings.Contains(body, "if len(written) == 0 && len(ownedDBs) > 0 {") {
		t.Error("buildArchive no longer fails closed when every dump failed")
	}
	if !strings.Contains(body, "return size, failedDBs, nil") {
		t.Error("a successful archive no longer reports which dumps failed")
	}
}

// Both producers must record the gap. The scheduler counts its run as succeeded,
// so a domain would otherwise accumulate file-only backups night after night.
func TestBothBackupProducersRecordTheGap(t *testing.T) {
	for _, file := range []string{"backups.go", "jobs.go"} {
		body := readBackupSource(t, file)
		if !strings.Contains(body, "backupNotes(") {
			t.Errorf("%s does not put the failed dumps on the backups row", file)
		}
		if !strings.Contains(body, "notifyDumpsFailed(") {
			t.Errorf("%s does not raise an alert for the failed dumps", file)
		}
	}
}

func readBackupSource(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(body)
}
