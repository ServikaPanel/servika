package backups

import (
	"database/sql"
	"os"
	"strings"
	"testing"
)

// healRecorder captures the one statement the heal issues. It reuses the
// retention driver, whose ExecContext records every query it is given.
func healRecorder(t *testing.T) (*Handlers, *retentionRecorder) {
	t.Helper()
	recorder := &retentionRecorder{}
	name := t.Name()

	retentionStateMu.Lock()
	retentionState[name] = recorder
	retentionStateMu.Unlock()
	t.Cleanup(func() {
		retentionStateMu.Lock()
		delete(retentionState, name)
		retentionStateMu.Unlock()
	})

	db, err := sql.Open("backups_retention_recorder", name)
	if err != nil {
		t.Fatalf("open the recording database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &Handlers{DB: db}, recorder
}

// The upload runs in a detached goroutine and the only exits from 'uploading'
// are 'successful' and 'failed'. A restart inside the 30-minute window left the
// row saying "uploading" for ever: nothing reset it and no route re-triggers the
// push, so the screen showed a transfer that would never advance.
func TestTheHealClosesAnInterruptedUpload(t *testing.T) {
	handlers, recorder := healRecorder(t)

	handlers.HealRemoteUploads()

	if !recorder.sawQueryContaining("UPDATE backups SET remote_status='failed'") {
		t.Error("the heal does not fail the interrupted upload")
	}
	// Scoped to 'uploading'. Without the WHERE it would rewrite the status of
	// every backup on the server, including the ones that really did upload.
	if !recorder.sawQueryContaining("UPDATE backups", "WHERE remote_status='uploading'") {
		t.Error("the heal is not scoped to interrupted uploads")
	}
	// The reason is stored, or the customer sees a failed transfer with nothing
	// saying the panel restarted under it.
	if !recorder.sawQueryContaining("UPDATE backups", "remote_error=") {
		t.Error("the heal records no reason")
	}
	// A successful or already-failed upload is not touched.
	if recorder.sawQueryContaining("UPDATE backups SET remote_status='failed' WHERE id") {
		t.Error("the heal rewrites a single backup rather than the interrupted ones")
	}
}

// A heal nobody calls is not a heal. main.go is the startup sequence, and this
// one has to sit beside the job heal that corrects the same class of state.
func TestTheUploadHealRunsAtStartup(t *testing.T) {
	source, err := os.ReadFile("../../cmd/server/main.go")
	if err != nil {
		t.Fatal(err)
	}
	startup := string(source)
	if !strings.Contains(startup, "backupsH.HealRemoteUploads()") {
		t.Fatal("HealRemoteUploads is never called at startup, so an interrupted upload stays 'uploading'")
	}
	if strings.Index(startup, "backupsH.HealJobsOnStartup()") > strings.Index(startup, "backupsH.HealRemoteUploads()") {
		t.Error("the two backup heals were reordered; they belong together in the startup sequence")
	}
}
