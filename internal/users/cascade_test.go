package users

import (
	"strings"
	"testing"
)

// indexOfAssignment returns where a SET assignment to the named column starts, or
// -1 when the statement makes none.
func indexOfAssignment(statement, column string) int {
	return strings.Index(statement, column+" =")
}

// Reactivating a reseller used to set every sub-account back to active, so a
// customer login an administrator had disabled individually for abuse or
// non-payment came back with it. The resume must open only the rows this cascade
// closed.
func TestTheResumeCascadeOnlyOpensWhatItClosed(t *testing.T) {
	statement := subAccountCascade("active")

	if !strings.Contains(statement, "COALESCE(suspended_by_reseller,0)=1") {
		t.Fatalf("the resume cascade is not narrowed to the rows it closed:\n%s", statement)
	}
	if !strings.Contains(statement, "reseller_id=?") {
		t.Fatalf("the resume cascade is no longer bound to one reseller:\n%s", statement)
	}
	if !strings.Contains(statement, "suspended_by_reseller = 0") {
		t.Fatalf("the resume cascade does not release the rows it opened:\n%s", statement)
	}
}

// The suspend direction marks what it closes, and leaves the marker alone on a
// row that was already closed. Marking that one would make the next resume open
// a suspension this cascade never applied.
func TestTheSuspendCascadeMarksOnlyTheRowsItCloses(t *testing.T) {
	statement := subAccountCascade("suspended")

	if !strings.Contains(statement, "IF(status='suspended', COALESCE(suspended_by_reseller,0), 1)") {
		t.Fatalf("the suspend cascade does not mark conditionally on the previous status:\n%s", statement)
	}
	if strings.Contains(statement, "suspended_by_reseller,0)=1") {
		t.Fatalf("the suspend cascade narrowed itself the way the resume does:\n%s", statement)
	}
}

// MariaDB evaluates SET assignments left to right and a later one sees what an
// earlier one wrote. Assigning status first would make every row look
// already-suspended, so nothing would ever be marked and the resume would open
// nothing.
func TestTheMarkerIsAssignedBeforeTheStatusItReads(t *testing.T) {
	statement := subAccountCascade("suspended")

	marker := indexOfAssignment(statement, "suspended_by_reseller")
	status := indexOfAssignment(statement, "status")
	if marker < 0 || status < 0 {
		t.Fatalf("one of the two assignments is missing (marker=%d, status=%d):\n%s", marker, status, statement)
	}
	if marker > status {
		t.Fatalf("the marker is assigned after the status it reads:\n%s", statement)
	}
}

// Both directions revoke a live session, so a suspended account cannot keep
// using the JWT it already holds.
func TestBothDirectionsBumpTheTokenVersion(t *testing.T) {
	for _, status := range []string{"suspended", "active"} {
		if statement := subAccountCascade(status); !strings.Contains(statement, "token_version = token_version+1") {
			t.Errorf("the %q cascade does not revoke live sessions:\n%s", status, statement)
		}
	}
}
