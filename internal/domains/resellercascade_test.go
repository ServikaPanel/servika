package domains

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
)

// These reuse the recording driver bulkowner_test.go registers for this package.
// The snapshot the cascade reads is set per test through the recorder.

// stubApply replaces the per-domain step with one that records the ids it was
// given and succeeds. ApplyDomainSuspend itself renders a vhost and runs
// `nginx -t`, so the cascade's own decisions would otherwise only be observable
// on the failure path.
func stubApply(t *testing.T) *[]int64 {
	t.Helper()
	var seen []int64
	previous := applySuspend
	applySuspend = func(_ context.Context, _ *sql.DB, id int64, _ bool) (string, error) {
		seen = append(seen, id)
		return "example.com", nil
	}
	t.Cleanup(func() { applySuspend = previous })
	return &seen
}

// markedDomains returns the ids the cascade marked as its own work.
func markedDomains(recorder *ownerRecorder) []int64 {
	_, values := recorder.matching("UPDATE domains SET suspended_by_reseller=1 WHERE id=?")
	var ids []int64
	for _, bound := range values {
		if len(bound) == 1 {
			if id, ok := bound[0].(int64); ok {
				ids = append(ids, id)
			}
		}
	}
	return ids
}

// Reactivating a reseller used to resume EVERY domain underneath it, including
// one an administrator had suspended individually for abuse or non-payment. A
// site taken down for hosting malware came back with its FTP, mail and tenant
// runtime restarted, and nothing in the panel said so.
func TestAResellerResumeLiftsOnlyItsOwnSuspensions(t *testing.T) {
	handlers, recorder := ownerHarness(t, true)
	touched := stubApply(t)
	// 7 was closed by the cascade; 8 was closed by an operator naming it.
	recorder.cascadeSnapshot = [][]driver.Value{
		{int64(7), int64(1), int64(1)},
		{int64(8), int64(1), int64(0)},
	}

	affected, failed, err := SuspendResellerDomains(context.Background(), handlers.DB, 9, false)
	if err != nil {
		t.Fatalf("SuspendResellerDomains() returned an error: %v", err)
	}

	if len(*touched) != 1 || (*touched)[0] != 7 {
		t.Fatalf("the resume touched %v, want only the domain the cascade closed ([7])", *touched)
	}
	if affected != 1 || failed != 0 {
		t.Fatalf("affected = %d, failed = %d, want 1 and 0", affected, failed)
	}
}

// A domain that is already closed is left entirely alone, so the sweep does not
// re-render a vhost, rewrite FTP and mail rows and stop a tenant runtime that are
// already in the target state.
func TestAResellerSuspendSkipsADomainThatIsAlreadyClosed(t *testing.T) {
	handlers, recorder := ownerHarness(t, true)
	touched := stubApply(t)
	recorder.cascadeSnapshot = [][]driver.Value{
		{int64(7), int64(0), int64(0)},
		{int64(8), int64(1), int64(0)},
	}

	affected, _, err := SuspendResellerDomains(context.Background(), handlers.DB, 9, true)
	if err != nil {
		t.Fatalf("SuspendResellerDomains() returned an error: %v", err)
	}

	if len(*touched) != 1 || (*touched)[0] != 7 {
		t.Fatalf("the suspend touched %v, want only the open domain ([7])", *touched)
	}
	if affected != 1 {
		t.Fatalf("affected = %d, want 1: the count must name rows that really changed", affected)
	}
}

// Only the rows the cascade actually closed carry the marker. Marking one it
// found already closed would make the next resume open a suspension it never
// applied, which is the defect this exists to close.
func TestOnlyTheRowsTheCascadeClosedAreMarked(t *testing.T) {
	handlers, recorder := ownerHarness(t, true)
	stubApply(t)
	recorder.cascadeSnapshot = [][]driver.Value{
		{int64(7), int64(0), int64(0)},
		{int64(8), int64(1), int64(0)},
	}

	if _, _, err := SuspendResellerDomains(context.Background(), handlers.DB, 9, true); err != nil {
		t.Fatalf("SuspendResellerDomains() returned an error: %v", err)
	}

	marked := markedDomains(recorder)
	if len(marked) != 1 || marked[0] != 7 {
		t.Fatalf("the cascade marked %v, want only the row it closed ([7])", marked)
	}
}

// A row the cascade failed to close must not be marked, or a later resume would
// open a suspension the cascade never applied.
func TestAFailedSuspensionIsNotMarked(t *testing.T) {
	handlers, recorder := ownerHarness(t, true)
	recorder.cascadeSnapshot = [][]driver.Value{{int64(7), int64(0), int64(0)}}
	previous := applySuspend
	applySuspend = func(context.Context, *sql.DB, int64, bool) (string, error) {
		return "example.com", errors.New("the vhost render failed")
	}
	t.Cleanup(func() { applySuspend = previous })

	_, failed, err := SuspendResellerDomains(context.Background(), handlers.DB, 9, true)
	if err != nil {
		t.Fatalf("SuspendResellerDomains() returned an error: %v", err)
	}
	if failed != 1 {
		t.Fatalf("failed = %d, want 1", failed)
	}
	if marked := markedDomains(recorder); len(marked) != 0 {
		t.Fatalf("the cascade marked %v after failing to close it", marked)
	}
}

// The snapshot is read once, before any write. An addon domain is a full domains
// row, so it appears in the list on its own AND is swept by its parent; a
// mid-loop re-read would see the parent's write, conclude the addon was already
// closed, and never mark it, leaving it down for good after the resume.
func TestTheSnapshotIsReadBeforeAnyWrite(t *testing.T) {
	handlers, recorder := ownerHarness(t, true)
	stubApply(t)
	recorder.cascadeSnapshot = [][]driver.Value{
		{int64(7), int64(0), int64(0)},
		{int64(8), int64(0), int64(0)},
	}

	if _, _, err := SuspendResellerDomains(context.Background(), handlers.DB, 9, true); err != nil {
		t.Fatalf("SuspendResellerDomains() returned an error: %v", err)
	}

	// Both rows were open, so both must be marked; the parent's sweep closing the
	// addon must not cost the addon its marker.
	if marked := markedDomains(recorder); len(marked) != 2 {
		t.Fatalf("the cascade marked %v, want both open rows", marked)
	}

	snapshotAt, firstWriteAt := snapshotAndFirstWrite(recorder)
	if snapshotAt < 0 {
		t.Fatal("the cascade never read its snapshot")
	}
	if firstWriteAt >= 0 && snapshotAt > firstWriteAt {
		t.Fatalf("the snapshot was read at %d, after the first write at %d", snapshotAt, firstWriteAt)
	}
}

// snapshotAndFirstWrite returns where the cascade read its snapshot and where
// it first wrote, each -1 when it never did.
func snapshotAndFirstWrite(recorder *ownerRecorder) (snapshotAt, firstWriteAt int) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	snapshotAt, firstWriteAt = -1, -1
	for i, statement := range recorder.statements {
		if snapshotAt < 0 && strings.Contains(statement, "FROM domains d JOIN customers c") {
			snapshotAt = i
		}
		if firstWriteAt < 0 && strings.HasPrefix(statement, "UPDATE ") {
			firstWriteAt = i
		}
	}
	return snapshotAt, firstWriteAt
}

// An empty snapshot is not an error: a reseller with no customers matches
// nothing, and so does an ordinary customer account.
func TestACascadeOverNoDomainsIsNotAnError(t *testing.T) {
	handlers, recorder := ownerHarness(t, true)
	stubApply(t)
	recorder.cascadeSnapshot = nil

	affected, failed, err := SuspendResellerDomains(context.Background(), handlers.DB, 9, true)
	if err != nil {
		t.Fatalf("SuspendResellerDomains() returned an error: %v", err)
	}
	if affected != 0 || failed != 0 {
		t.Fatalf("affected = %d, failed = %d, want 0 and 0", affected, failed)
	}
}
