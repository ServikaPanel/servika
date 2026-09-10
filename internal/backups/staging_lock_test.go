package backups

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The staging directory is shared by every producer: the manual handler, the
// nightly scheduler and a bulk job. A second holder must wait for the first,
// because one run deletes __db__ on the way in and again on the way out.
func TestOneTenantStagesOneBackupAtATime(t *testing.T) {
	release, err := lockStaging(context.Background(), "c_example")
	if err != nil {
		t.Fatalf("take the slot: %v", err)
	}
	t.Cleanup(release)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := lockStaging(ctx, "c_example"); err == nil {
		t.Fatal("a second backup of the same tenant took the staging slot while the first held it")
	}
}

// An addon or subdomain row carries its PARENT's system_user, so keying the lock
// on the domain id would leave that pair racing one directory. Two unrelated
// tenants have their own directory and must not wait for each other.
func TestTwoTenantsDoNotWaitForEachOther(t *testing.T) {
	release, err := lockStaging(context.Background(), "c_first")
	if err != nil {
		t.Fatalf("take the first slot: %v", err)
	}
	t.Cleanup(release)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	releaseSecond, err := lockStaging(ctx, "c_second")
	if err != nil {
		t.Fatalf("a second tenant waited for an unrelated tenant's staging slot: %v", err)
	}
	releaseSecond()
}

// The slot is released, not leaked: the next backup of the same tenant takes it.
func TestTheSlotIsHandedOn(t *testing.T) {
	release, err := lockStaging(context.Background(), "c_handover")
	if err != nil {
		t.Fatalf("take the slot: %v", err)
	}
	release()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	next, err := lockStaging(ctx, "c_handover")
	if err != nil {
		t.Fatalf("the released slot was not handed on: %v", err)
	}
	next()
}

// buildArchive must take the slot BEFORE it touches the staging directory. It
// removes __db__ on entry, so a run that started work while another held the slot
// would delete that run's dumps whatever the lock said afterwards. The database
// handle is nil deliberately: reaching it would mean the guard let the work start.
func TestBuildArchiveWaitsBeforeItTouchesTheStagingDirectory(t *testing.T) {
	dir := t.TempDir()
	dbDir := filepath.Join(dir, "__db__")
	if err := os.MkdirAll(dbDir, 0o700); err != nil {
		t.Fatalf("create the staging directory: %v", err)
	}
	marker := filepath.Join(dbDir, "in-flight.sql")
	if err := os.WriteFile(marker, []byte("dump\n"), 0o600); err != nil {
		t.Fatalf("write the in-flight dump: %v", err)
	}

	release, err := lockStaging(context.Background(), "c_busy")
	if err != nil {
		t.Fatalf("take the slot: %v", err)
	}
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := buildArchive(ctx, nil, 1, "c_busy", dir, "out.tar.gz", "2026-01-01 00:00:00"); err == nil {
		t.Fatal("buildArchive ran while another backup of the same tenant held the staging slot")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("the in-flight dump of the holding backup was destroyed: %v", err)
	}
}
