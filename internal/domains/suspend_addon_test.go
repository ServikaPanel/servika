package domains

import (
	"context"
	"database/sql/driver"
	"strings"
	"testing"
)

// These reuse the recording driver bulkowner_test.go already registers for this
// package, which is what answers the suspension's own queries; a second driver
// of the same shape would only be a copy of it.

// An addon domain carries its PARENT's system_user, so it is the same home
// directory, the same database namespace and the same account. Suspending the
// parent row alone left the addon row active, and every CustomerScope handler
// resolves the tenant from whichever row the URL names, so the suspended
// customer kept the whole surface through the addon's id.
func TestSuspensionReachesTheAddonRows(t *testing.T) {
	handlers, recorder := ownerHarness(t, true)

	// The harness refuses the vhost render, so this returns that error; what it
	// built before then is what this measures.
	_, _ = ApplyDomainSuspend(context.Background(), handlers.DB, 7, true)

	statements, values := recorder.matching("UPDATE domains SET suspended=?, status=? WHERE id=? OR parent_domain_id=?")
	if len(statements) != 1 {
		t.Fatalf("the suspension wrote %d statements covering addon rows, want 1", len(statements))
	}
	if got := values[0]; len(got) != 4 || got[0] != int64(1) || got[1] != "passive" || got[2] != int64(7) || got[3] != int64(7) {
		t.Fatalf("bound values = %v, want [1 passive 7 7]", got)
	}
}

// The rollback puts every row back as it was FOUND. Levelling the addon to the
// parent's state would silently discard a suspension an operator applied to that
// addon on its own, which the endpoint allows.
func TestTheRollbackRestoresEachRowsOwnState(t *testing.T) {
	handlers, recorder := ownerHarness(t, true)

	if _, err := ApplyDomainSuspend(context.Background(), handlers.DB, 7, true); err == nil {
		t.Fatal("the refused render did not fail the suspension")
	}

	_, values := recorder.matching("UPDATE domains SET suspended=?, status=? WHERE id=?")
	var restored [][]driver.Value
	for _, bound := range values {
		if len(bound) == 3 {
			restored = append(restored, bound)
		}
	}
	if len(restored) != 2 {
		t.Fatalf("%d rows were rolled back, want 2", len(restored))
	}
	if got := restored[0]; got[0] != int64(0) || got[1] != "active" || got[2] != int64(7) {
		t.Errorf("the parent was restored as %v, want [0 active 7]", got)
	}
	if got := restored[1]; got[0] != int64(1) || got[1] != "passive" || got[2] != int64(8) {
		t.Errorf("the addon was restored as %v, want [1 passive 8]", got)
	}
}

// The FTP, mail-domain and mailbox cascades run on the same set. A parent-only
// clause leaves the addon's mailboxes and FTP accounts live.
func TestTheDependentCascadesCoverTheAddonRows(t *testing.T) {
	if !strings.Contains(ownedByDomainOrItsAddons, "parent_domain_id=?") {
		t.Fatalf("the cascade clause does not reach addon rows: %q", ownedByDomainOrItsAddons)
	}
	if !strings.Contains(ownedByDomainOrItsAddons, "domain_id=?") {
		t.Fatalf("the cascade clause no longer reaches the domain itself: %q", ownedByDomainOrItsAddons)
	}
}
