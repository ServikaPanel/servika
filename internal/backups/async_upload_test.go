package backups

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	uploadingUpdate      = "UPDATE backups SET remote_status='uploading', remote_error='' WHERE id=?"
	destinationFailed    = "SET last_status='failed', last_error=?, last_upload=NOW() WHERE domain_id=?"
	backupUploadFailed   = "UPDATE backups SET remote_status='failed', remote_error=? WHERE id=?"
	destinationSucceeded = "SET last_status='successful', last_error='', last_upload=NOW() WHERE domain_id=?"
	backupUploaded       = "SET remote_status='successful', remote_key=?, remote_error='' WHERE id=?"
	globalStatusUpdate   = "UPDATE backup_settings SET last_status=?, last_error=?, last_upload=NOW() WHERE id=1"
	globalKeyStore       = "UPDATE backup_settings SET remote_host_key=? WHERE id=1 AND remote_host_key=''"
	movedOffSiteUpdate   = "UPDATE backups SET notes=CONCAT(notes,' [moved off-site]') WHERE id=?"
	domainNameQuery      = "SELECT domain_name FROM domains WHERE id=?"
	notificationInsert   = "INSERT INTO notifications"
	localArchiveBytes    = "archive-bytes"
)

// sizeListing is an lftp long listing of the archive. The owner and group are
// names, because parseRemoteSize takes the largest integer on the line.
func sizeListing(size int) string {
	return fmt.Sprintf("-rw-r--r-- 1 owner group %d Jan  1 00:00 %s\n", size, archiveName)
}

// uploadCommands answers an lftp upload with putOutput and putExit, an lftp size
// listing with listing (an empty listing fails), and ssh-keyscan with a key
// unless scanExit is set.
func uploadCommands(t *testing.T, putOutput string, putExit int, listing string, scanExit int) *commandRecorder {
	t.Helper()
	return withCommandScript(t, func(argv []string) (string, int) {
		switch {
		case argv[0] == "ssh-keyscan":
			if scanExit != 0 {
				return "", scanExit
			}
			return scannedKey + "\n", 0
		case argv[0] == "lftp" && strings.Contains(argv[2], "put -O ."):
			return putOutput, putExit
		case argv[0] == "lftp" && strings.Contains(argv[2], "cls -l"):
			if listing == "" {
				return "", 1
			}
			return listing, 0
		}
		return "", 0
	})
}

func localUpload(t *testing.T) string {
	t.Helper()
	local := filepath.Join(t.TempDir(), archiveName)
	writeFixtureFile(t, local, localArchiveBytes)
	return local
}

// assertUploadAlert waits for the upload alert and checks its reason.
func assertUploadAlert(t *testing.T, script *sqlScript, reason string) {
	t.Helper()
	script.waitForExec(t, notificationInsert)
	assertAlerts(t, script, alert{key: "backup.uploadFailed", domain: int64(5)})
	args := script.execsContaining(notificationInsert)[0].args
	var params map[string]string
	if err := json.Unmarshal([]byte(args[5].(string)), &params); err != nil || params["reason"] != reason || args[8] != int64(9) {
		t.Errorf("the upload alert = %v, want the reason %q for backup 9", args, reason)
	}
}

func TestPushToDestinationAsyncSkipsAMissingOrDisabledDestination(t *testing.T) {
	disabled := domainDestinationRow()
	disabled[12] = int64(0)
	for name, script := range map[string]*sqlScript{
		"no destination":       {rows: map[string][][]driver.Value{readDestinationQuery: {}}},
		"unreadable":           {fail: map[string]error{readDestinationQuery: errors.New("lost")}},
		"disabled destination": {rows: map[string][][]driver.Value{readDestinationQuery: {disabled}}},
	} {
		t.Run(name, func(t *testing.T) {
			commands := uploadCommands(t, "", 0, "", 0)
			pushToDestinationAsync(scriptDB(t, script), 5, 9, localUpload(t), archiveName)
			script.waitForQuery(t, readDestinationQuery)
			time.Sleep(50 * time.Millisecond)
			if execs := script.execsContaining(""); len(execs) != 0 || len(commands.argvs()) != 0 {
				t.Errorf("a skipped upload still wrote %v and ran %v", execs, commands.argvs())
			}
		})
	}
}

// destinationUploadCase is one outcome of an upload to a domain's destination.
type destinationUploadCase struct {
	name      string
	row       []driver.Value
	putOutput string
	putExit   int
	listing   string
	failure   string
	key       string
}

// Every upload outcome lands on the destination row, the backup row and, for a
// failure, in a domain-scoped alert.
func TestPushToDestinationAsyncRecordsTheOutcome(t *testing.T) {
	long := strings.Repeat("x", 600)
	rootDir := domainDestinationRow()
	rootDir[6] = "/"
	cases := []destinationUploadCase{
		{name: "the upload fails", row: domainDestinationRow(), putOutput: long, putExit: 1,
			failure: ("lftp: " + long + ": exit status 1")[:500]},
		{name: "lftp prints a refusal and exits 0", row: domainDestinationRow(), putOutput: "530 Login failed",
			failure: "lftp: 530 Login failed"},
		{name: "the stored object is short", row: domainDestinationRow(), listing: sizeListing(7),
			failure: "remote size mismatch (local=13 remote=7): the upload was incomplete"},
		{name: "the object arrives whole", row: domainDestinationRow(), listing: sizeListing(13),
			key: "backups/" + archiveName},
		{name: "a size that cannot be read, in the root directory", row: rootDir, key: archiveName},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { runDestinationUpload(t, c) })
	}
}

func runDestinationUpload(t *testing.T, c destinationUploadCase) {
	t.Helper()
	script := &sqlScript{rows: map[string][][]driver.Value{
		readDestinationQuery: {c.row}, domainNameQuery: {{"example.com"}},
	}}
	commands := uploadCommands(t, c.putOutput, c.putExit, c.listing, 0)
	local := localUpload(t)

	pushToDestinationAsync(scriptDB(t, script), 5, 9, local, archiveName)

	if c.failure != "" {
		assertUploadAlert(t, script, c.failure)
		assertExecs(t, script, backupUploadFailed, []driver.Value{c.failure, int64(9)})
		assertExecs(t, script, destinationFailed, []driver.Value{c.failure, int64(5)})
	} else {
		script.waitForExec(t, backupUploaded)
		assertExecs(t, script, backupUploaded, []driver.Value{c.key, int64(9)})
		assertExecs(t, script, destinationSucceeded, []driver.Value{int64(5)})
	}
	assertExecs(t, script, uploadingUpdate, []driver.Value{int64(9)})
	if put := commands.argvs()[0][2]; !strings.Contains(put, `put -O . "`+local+`"; bye`) {
		t.Errorf("the upload script is %s", put)
	}
}

// globalRow is the settings singleton with the off-site destination on, changed
// by mutate.
func globalRow(mutate func(row []driver.Value)) []driver.Value {
	row := settingsRow(true, 0, "pw")
	mutate(row)
	return row
}

func TestPushGlobalAsyncSkipsWithoutADestination(t *testing.T) {
	for name, row := range map[string][]driver.Value{
		"off-site is off": globalRow(func(row []driver.Value) { row[3] = int64(0) }),
		"no host":         globalRow(func(row []driver.Value) { row[5] = "  " }),
	} {
		t.Run(name, func(t *testing.T) {
			script := &sqlScript{rows: map[string][][]driver.Value{settingsQuery: {row}}}
			commands := uploadCommands(t, "", 0, "", 0)
			pushGlobalAsync(scriptDB(t, script), 5, 9, localUpload(t), archiveName)
			script.waitForQuery(t, settingsQuery)
			time.Sleep(50 * time.Millisecond)
			if execs := script.execsContaining(""); len(execs) != 0 || len(commands.argvs()) != 0 {
				t.Errorf("a skipped upload still wrote %v and ran %v", execs, commands.argvs())
			}
		})
	}
}

func TestPushGlobalAsyncReportsEachFailure(t *testing.T) {
	initTestSecret(t)
	cases := []struct {
		name      string
		row       []driver.Value
		fail      map[string]error
		putOutput string
		putExit   int
		listing   string
		scanExit  int
		prefix    string
	}{
		{name: "the password cannot be opened", row: globalRow(func(row []driver.Value) { row[8] = "enc:v1:not-sealed" }),
			prefix: "the stored off-site password could not be decrypted (SERVIKA_SECRET_KEY may have changed): "},
		{name: "the key cannot be scanned", row: globalRow(func(row []driver.Value) { row[10] = "" }), scanExit: 1,
			prefix: "the destination's SSH host key could not be read: exit status 1"},
		{name: "the key cannot be stored", row: globalRow(func(row []driver.Value) { row[10] = "" }),
			fail:   map[string]error{globalKeyStore: errors.New("read-only")},
			prefix: "the host key could not be stored: read-only"},
		{name: "the upload fails", row: globalRow(func([]driver.Value) {}), putOutput: "denied", putExit: 1,
			prefix: "lftp: denied: exit status 1"},
		{name: "the stored object is short", row: globalRow(func([]driver.Value) {}), listing: sizeListing(4),
			prefix: "remote size mismatch (local=13 remote=4): the upload was incomplete"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			script := &sqlScript{
				rows: map[string][][]driver.Value{settingsQuery: {c.row}, domainNameQuery: {{"example.com"}}},
				fail: c.fail,
			}
			uploadCommands(t, c.putOutput, c.putExit, c.listing, c.scanExit)

			pushGlobalAsync(scriptDB(t, script), 5, 9, localUpload(t), archiveName)

			script.waitForExec(t, notificationInsert)
			status := script.execsContaining(globalStatusUpdate)
			if len(status) != 1 || status[0].args[0] != "failed" || !strings.HasPrefix(status[0].args[1].(string), c.prefix) {
				t.Errorf("the status = %+v, want failed %q", status, c.prefix)
			}
		})
	}
}

// globalDeleteCase is one delete-local outcome after a successful upload.
type globalDeleteCase struct {
	name     string
	listing  string
	backupID int64
	missing  bool
	removed  bool
}

// A verified off-site copy lets delete-local remove the local archive and mark
// the row; an unverified one, or one with no row to mark, keeps it.
func TestPushGlobalAsyncDeletesTheLocalCopyOnlyWhenVerified(t *testing.T) {
	cases := []globalDeleteCase{
		{name: "verified", listing: sizeListing(13), backupID: 9, removed: true},
		{name: "the size cannot be read", backupID: 9},
		{name: "no backup row", listing: sizeListing(13)},
		{name: "the local copy is already gone", listing: sizeListing(13), backupID: 9, missing: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { runGlobalDelete(t, c) })
	}
}

func runGlobalDelete(t *testing.T, c globalDeleteCase) {
	t.Helper()
	row := globalRow(func(row []driver.Value) { row[10], row[11] = "", int64(1) })
	script := &sqlScript{rows: map[string][][]driver.Value{settingsQuery: {row}}}
	commands := uploadCommands(t, "", 0, c.listing, 0)
	local := localUpload(t)
	if c.missing {
		if err := os.Remove(local); err != nil {
			t.Fatal(err)
		}
	}

	pushGlobalAsync(scriptDB(t, script), 5, c.backupID, local, archiveName)

	if c.removed {
		script.waitForExec(t, movedOffSiteUpdate)
		assertExecs(t, script, movedOffSiteUpdate, []driver.Value{int64(9)})
	} else {
		script.waitForExec(t, globalStatusUpdate)
		time.Sleep(50 * time.Millisecond)
		assertExecs(t, script, movedOffSiteUpdate)
	}
	if _, err := os.Stat(local); errors.Is(err, os.ErrNotExist) != (c.removed || c.missing) {
		t.Errorf("the local copy: %v", err)
	}
	assertExecs(t, script, globalStatusUpdate, []driver.Value{"successful", ""})
	assertExecs(t, script, globalKeyStore, []driver.Value{scannedKey})
	if put := commands.argvs()[1][2]; !strings.Contains(put, `mkdir -p -f "/gpanel/2026-01-01"; cd "/gpanel/2026-01-01"; put -O . "`+local+`"`) {
		t.Errorf("the upload script is %s", put)
	}
}
