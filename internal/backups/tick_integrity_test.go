package backups

import (
	"crypto/sha256"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	dueDomainsQuery     = "UNIX_TIMESTAMP(last_backup_at)"
	scheduledJobInsert  = "INSERT INTO backup_jobs(type, operation, status, total, started_by)"
	integrityListQuery  = "JOIN (SELECT domain_id, MAX(id) AS mid FROM backups WHERE sha256 <> '' GROUP BY domain_id) x"
	diskGateCountQuery  = "SELECT COUNT(*) FROM notifications"
	offsiteNotesQuery   = "SELECT COUNT(*) FROM backups WHERE file=? AND notes LIKE ?"
	scheduledPruneQuery = "SELECT id, file, remote_status FROM backups"
	countsUpdate        = "UPDATE backup_jobs SET completed=?, succeeded=?, failed=?, size_b=? WHERE id=?"
	activeUpdate        = "UPDATE backup_jobs SET active_domain=? WHERE id=?"
	lastBackupUpdate    = "UPDATE domains SET last_backup_at=NOW() WHERE id=?"
)

// withIntegrityScan makes the daily integrity scan due, or already done, for one
// test.
func withIntegrityScan(t *testing.T, due bool) {
	t.Helper()
	integrityMu.Lock()
	previous := lastIntegrityScan
	lastIntegrityScan = time.Now()
	if due {
		lastIntegrityScan = time.Time{}
	}
	integrityMu.Unlock()
	t.Cleanup(func() {
		integrityMu.Lock()
		lastIntegrityScan = previous
		integrityMu.Unlock()
	})
}

func dueRow(id int64, name, user string, last driver.Value) []driver.Value {
	return []driver.Value{id, name, user, "daily", int64(3), int64(7), last}
}

// tickScript is a pass with automatic backups on, no off-site destination and the
// due-domain list given.
func tickScript(settings []driver.Value, domains [][]driver.Value) *sqlScript {
	return &sqlScript{insertID: 61, rows: map[string][][]driver.Value{
		settingsQuery:        {settings},
		dueDomainsQuery:      domains,
		ownedListQuery:       {},
		scheduledPruneQuery:  {},
		domainNameQuery:      {{"example.com"}},
		readDestinationQuery: {},
	}}
}

func TestTickOnceStopsBeforeWritingAnything(t *testing.T) {
	disabled := settingsRow(false, 0, "")
	disabled[0] = int64(0)
	cases := []struct {
		name   string
		script *sqlScript
		check  func(t *testing.T, script *sqlScript)
	}{
		{name: "automatic backups are off", script: tickScript(disabled, nil),
			check: func(t *testing.T, script *sqlScript) {
				if script.queriesContaining(dueDomainsQuery) != 0 {
					t.Error("the domains were read with automatic backups off")
				}
			}},
		{name: "the disk guard refuses, first time today", script: func() *sqlScript {
			s := tickScript(settingsRow(false, 1_000_000_000, ""), nil)
			s.rows[diskGateCountQuery] = [][]driver.Value{{int64(0)}}
			return s
		}(), check: func(t *testing.T, script *sqlScript) {
			alerts := script.execsContaining(notificationInsert)
			if len(alerts) != 1 || alerts[0].args[4] != "backup.diskGate" || alerts[0].args[6] != nil ||
				!strings.Contains(alerts[0].args[5].(string), "threshold 1000000000 GB") {
				t.Errorf("the disk guard alert = %+v", alerts)
			}
		}},
		{name: "the disk guard refuses, already alerted today", script: func() *sqlScript {
			s := tickScript(settingsRow(false, 1_000_000_000, ""), nil)
			s.rows[diskGateCountQuery] = [][]driver.Value{{int64(1)}}
			return s
		}(), check: func(t *testing.T, script *sqlScript) { assertAlerts(t, script) }},
		{name: "the domains cannot be read", script: func() *sqlScript {
			s := tickScript(settingsRow(false, 0, ""), nil)
			delete(s.rows, dueDomainsQuery)
			s.fail = map[string]error{dueDomainsQuery: errors.New("lost")}
			return s
		}()},
		{name: "nothing is due", script: func() *sqlScript {
			s := tickScript(settingsRow(false, 0, ""), [][]driver.Value{
				dueRow(8, "fresh.com", "c_fresh", time.Now().Unix()),
				{"not a number", "x.com", "c_x", "daily", int64(3), int64(7), nil},
			})
			s.endWith = map[string]error{dueDomainsQuery: errors.New("cut short")}
			return s
		}()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// The disk guard measures the backup root, so it has to exist.
			t.Setenv("SERVIKA_BACKUP_ROOT", t.TempDir())
			withIntegrityScan(t, false)
			withCommands(t)
			tickOnce(scriptDB(t, c.script))
			assertExecs(t, c.script, scheduledJobInsert)
			if c.check != nil {
				c.check(t, c.script)
			}
		})
	}
}

// The integrity scan runs once a day, before the master switch.
func TestTickOnceRunsTheIntegrityScanWhenDue(t *testing.T) {
	disabled := settingsRow(false, 0, "")
	disabled[0] = int64(0)
	script := tickScript(disabled, nil)
	script.rows[integrityListQuery] = [][]driver.Value{}
	withIntegrityScan(t, true)

	tickOnce(scriptDB(t, script))

	if script.queriesContaining(integrityListQuery) != 1 {
		t.Error("the integrity scan did not run")
	}
}

// A nightly pass backs up each due domain, alerts on a failure, prunes both and
// closes one scheduled job with the tallies.
func TestTickOnceBacksUpEveryDueDomain(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SERVIKA_BACKUP_ROOT", root)
	withIntegrityScan(t, false)
	script := tickScript(settingsRow(false, 0, ""), [][]driver.Value{
		dueRow(5, "example.com", "c_example", nil),
		dueRow(6, "broken.com", "c_broken", nil),
		dueRow(8, "fresh.com", "c_fresh", time.Now().Unix()),
	})
	archiveCommands(t, map[string]string{"c_example_main": completeDump, "c_broken_main": "FAIL"}, 0)

	tickOnce(scriptDB(t, script))

	size := int64(len(localArchiveBytes))
	assertExecs(t, script, scheduledJobInsert, []driver.Value{int64(2)})
	assertExecs(t, script, activeUpdate, []driver.Value{"example.com", int64(61)}, []driver.Value{"broken.com", int64(61)})
	assertExecs(t, script, lastBackupUpdate, []driver.Value{int64(5)})
	assertExecs(t, script, countsUpdate,
		[]driver.Value{int64(1), int64(1), int64(0), size, int64(61)},
		[]driver.Value{int64(2), int64(1), int64(1), size, int64(61)})
	assertExecs(t, script, finishJobUpdate, []driver.Value{"partial", int64(61)})
	assertAlerts(t, script, alert{key: "backup.backupFailed", domain: int64(6)})
	if prunes := script.queriesContaining("type='scheduled'"); prunes != 2 {
		t.Errorf("retention ran %d times, want both domains", prunes)
	}
	assertScheduledBackupRow(t, script, root)
}

// assertScheduledBackupRow checks the one backup row the pass wrote and the
// archive it names.
func assertScheduledBackupRow(t *testing.T, script *sqlScript, root string) {
	t.Helper()
	rows := script.execsContaining("INSERT INTO backups(")
	if len(rows) != 1 {
		t.Fatalf("backup rows = %+v", rows)
	}
	args := slices.Clone(rows[0].args)
	file, _ := args[2].(string)
	if !strings.HasPrefix(file, "c_example-auto-") {
		t.Errorf("the archive is named %q", file)
	}
	args[2] = "file"
	want := []driver.Value{int64(5), "scheduled", "file", int64(len(localArchiveBytes)), "Scheduled backup (daily)",
		int64(61), digestOf(localArchiveBytes), "ok"}
	if !slices.Equal(args, want) {
		t.Errorf("the backup row = %v, want %v", args, want)
	}
	if _, err := os.Stat(filepath.Join(root, "c_example", file)); err != nil {
		t.Errorf("the archive is missing: %v", err)
	}
}

// A job row that cannot be opened does not stop the pass, and neither does a
// progress, retention or last-backup write that fails.
func TestTickOnceCarriesOnPastFailedBookkeeping(t *testing.T) {
	t.Setenv("SERVIKA_BACKUP_ROOT", t.TempDir())
	withIntegrityScan(t, false)
	script := tickScript(settingsRow(false, 0, ""), [][]driver.Value{dueRow(5, "example.com", "c_example", nil)})
	delete(script.rows, scheduledPruneQuery)
	script.fail = map[string]error{
		scheduledJobInsert: errors.New("read-only"),
		activeUpdate:       errors.New("read-only"),
		countsUpdate:       errors.New("read-only"),
		lastBackupUpdate:   errors.New("read-only"),
		"type='scheduled'": errors.New("lost"),
	}
	archiveCommands(t, map[string]string{"c_example_main": completeDump}, 0)

	tickOnce(scriptDB(t, script))

	assertExecs(t, script, finishJobUpdate, []driver.Value{"done", int64(0)})
}

func TestTickOnceStops(t *testing.T) {
	t.Run("between domains", func(t *testing.T) {
		t.Setenv("SERVIKA_BACKUP_ROOT", t.TempDir())
		withIntegrityScan(t, false)
		script := tickScript(settingsRow(false, 0, ""), [][]driver.Value{
			dueRow(5, "example.com", "c_example", nil), dueRow(6, "second.com", "c_second", nil),
		})
		script.onExec = func(query string) {
			if strings.Contains(query, countsUpdate) {
				stopJob(61)
			}
		}
		archiveCommands(t, map[string]string{"c_example_main": completeDump, "c_second_main": completeDump}, 0)

		tickOnce(scriptDB(t, script))

		assertExecs(t, script, finishJobUpdate, []driver.Value{"stopped", int64(61)})
		assertExecs(t, script, activeUpdate, []driver.Value{"example.com", int64(61)})
	})
	t.Run("in flight", func(t *testing.T) {
		t.Setenv("SERVIKA_BACKUP_ROOT", t.TempDir())
		withIntegrityScan(t, false)
		script := tickScript(settingsRow(false, 0, ""), [][]driver.Value{dueRow(5, "example.com", "c_example", nil)})
		withCommandScript(t, func([]string) (string, int) {
			stopJob(61)
			return "", 1
		})

		tickOnce(scriptDB(t, script))

		assertExecs(t, script, finishJobUpdate, []driver.Value{"stopped", int64(61)})
		assertAlerts(t, script)
	})
}

func integrityRow(id int64, user, file, sum string) []driver.Value {
	return []driver.Value{id, int64(5), user, file, sum}
}

func digestOf(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

// The newest archive of each domain is re-hashed: a match is ok, a mismatch is
// bit-rot and a missing file is lost, and each fault raises one alert.
func TestVerifyBackupIntegrityRecordsEachVerdict(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SERVIKA_BACKUP_ROOT", root)
	writeFixtureFile(t, filepath.Join(root, "c_ok", "ok.tar.gz"), "good")
	writeFixtureFile(t, filepath.Join(root, "c_rot", "rot.tar.gz"), "rotted")
	script := &sqlScript{
		rows: map[string][][]driver.Value{
			integrityListQuery: {
				integrityRow(1, "c_ok", "ok.tar.gz", digestOf("good")),
				integrityRow(2, "c_rot", "rot.tar.gz", digestOf("original")),
				integrityRow(3, "c_gone", "gone.tar.gz", digestOf("x")),
				integrityRow(4, "bad user", "x.tar.gz", digestOf("x")),
				{"not a number", int64(5), "c_x", "x", "y"},
			},
			settingsQuery:   {},
			domainNameQuery: {{"example.com"}},
		},
		endWith: map[string]error{integrityListQuery: errors.New("cut short")},
	}

	verifyBackupIntegrity(scriptDB(t, script))

	assertExecs(t, script, "UPDATE backups SET verification='ok' WHERE id=?", []driver.Value{int64(1)})
	assertExecs(t, script, "UPDATE backups SET verification='corrupt' WHERE id=? AND verification<>'corrupt'",
		[]driver.Value{int64(2)}, []driver.Value{int64(3)})
	assertExecs(t, script, notificationInsert,
		[]driver.Value{"critical", "backup", "Backup corrupted (bit-rot)",
			"The newest backup for example.com (rot.tar.gz) no longer matches its checksum from when it was written; restoring from it may fail.",
			"backup.bitRot", `{"domain":"example.com","file":"rot.tar.gz"}`, int64(5), "backup", int64(2)},
		[]driver.Value{"critical", "backup", "Backup lost or unreadable",
			"The newest backup for example.com could not be read (gone.tar.gz); it may be invalid for recovery.",
			"backup.corruptMissing", `{"domain":"example.com","file":"gone.tar.gz"}`, int64(5), "backup", int64(3)})
}

// A missing archive that was moved off-site on purpose is 'remote', not a fault.
func TestVerifyBackupIntegrityAcceptsAnArchiveMovedOffSite(t *testing.T) {
	t.Setenv("SERVIKA_BACKUP_ROOT", t.TempDir())
	script := &sqlScript{rows: map[string][][]driver.Value{
		integrityListQuery: {integrityRow(7, "c_moved", "moved.tar.gz", digestOf("x"))},
		settingsQuery:      {settingsRow(true, 0, "pw")},
		offsiteNotesQuery:  {{int64(1)}},
	}}

	verifyBackupIntegrity(scriptDB(t, script))

	assertExecs(t, script, "UPDATE backups SET verification='remote' WHERE id=? AND verification<>'corrupt'", []driver.Value{int64(7)})
	assertAlerts(t, script)
}

// Only a transition into corrupt alerts: an archive already recorded corrupt, or
// a verdict that could not be written, raises nothing.
func TestVerifyBackupIntegrityAlertsOnlyOnTheTransition(t *testing.T) {
	const corruptUpdate = "UPDATE backups SET verification='corrupt'"
	for name, script := range map[string]*sqlScript{
		"already corrupt": {affected: map[string]int64{corruptUpdate: 0}},
		"not written":     {fail: map[string]error{corruptUpdate: errors.New("read-only")}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("SERVIKA_BACKUP_ROOT", t.TempDir())
			script.rows = map[string][][]driver.Value{
				integrityListQuery: {integrityRow(2, "c_gone", "gone.tar.gz", digestOf("x"))},
				settingsQuery:      {},
			}
			verifyBackupIntegrity(scriptDB(t, script))
			assertAlerts(t, script)
		})
	}
}

func TestVerifyBackupIntegrityStopsOnAnUnreadableList(t *testing.T) {
	script := &sqlScript{fail: map[string]error{integrityListQuery: errors.New("lost")}}
	verifyBackupIntegrity(scriptDB(t, script))
	if execs := script.execsContaining(""); len(execs) != 0 {
		t.Errorf("verdicts were written without a list: %+v", execs)
	}
}
