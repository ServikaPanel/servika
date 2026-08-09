package domains

import (
	"os"
	"strings"
	"testing"
)

// Delete tears down MariaDB accounts, systemd slices, Valkey ACLs, nginx and the
// Linux user itself, so it cannot be executed here without a host to take apart.
// What these assertions pin is the ORDER and the CONDITIONS the decision rests
// on, which is where the data loss came from: every teardown named after the
// SYSTEM USER rather than the domain belongs to the survivor while two domains
// share one, and an upgraded panel can still carry such a pair.
//
// The behaviour of the question itself is proven against a recording database in
// internal/provisioner.
func deleteBody(t *testing.T) string {
	t.Helper()
	source, err := os.ReadFile("handlers.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	start := strings.Index(body, "func (h *Handlers) Delete(w http.ResponseWriter, r *http.Request) {")
	if start < 0 {
		t.Fatal("Delete was renamed; these assertions have to follow it")
	}
	end := strings.Index(body[start:], "\nfunc ")
	if end < 0 {
		return body[start:]
	}
	return body[start : start+end]
}

// The question is asked while the row is still there and before anything is
// removed. Asking afterwards would answer about a table that no longer contains
// the domain being deleted.
func TestTheSharedUserQuestionIsAskedFirst(t *testing.T) {
	body := deleteBody(t)

	ask := strings.Index(body, "provisioner.OtherTopLevelDomainsUsing(sk, domainName)")
	teardown := strings.Index(body, "provisioner.Deprovision(domainName, sk)")
	rowGone := strings.Index(body, "`DELETE FROM domains WHERE id=?`")
	switch {
	case ask < 0:
		t.Fatal("Delete no longer asks whether the system user is shared")
	case teardown < 0 || rowGone < 0:
		t.Fatal("the teardown or the row deletion moved; these assertions have to follow them")
	case ask > teardown:
		t.Error("the teardown runs before the question, so a shared tenant is already gone")
	case ask > rowGone:
		t.Error("the question is asked after the row is deleted, so it can never find the domain")
	}
}

// A failed lookup counts as shared. Reading the error and then acting on an
// empty list is the same as never asking.
func TestAFailedLookupKeepsTenantResources(t *testing.T) {
	body := deleteBody(t)

	if !strings.Contains(body, "systemUserShared := siblingErr != nil || len(siblings) > 0") {
		t.Error("a failed sibling lookup no longer counts as shared")
	}
}

// The two teardowns named after the system user are the cgroup slice and the
// Valkey account. Both must be skipped while a sibling still answers to it; only
// this domain's own cache row goes.
func TestTheUserKeyedTeardownsAreSkippedWhileShared(t *testing.T) {
	body := deleteBody(t)

	slice := strings.Index(body, "resourcelimit.DeleteSystemdSlice(sk)")
	guard := strings.Index(body, "if !systemUserShared {")
	if slice < 0 || guard < 0 || guard > slice {
		t.Error("the systemd slice is removed without checking whether the system user is shared")
	}

	acl := strings.Index(body, "redis.CloseDomain(h.DB, id, sk)")
	rowOnly := strings.Index(body, "redis.ForgetDomain(h.DB, id)")
	switch {
	case acl < 0 || rowOnly < 0:
		t.Fatal("the Redis cleanup moved; these assertions have to follow it")
	case rowOnly > acl:
		t.Error("the shared branch no longer comes first, so the survivor's ACL account is revoked")
	}
}

// The shared vhost file is named after the system user, so it still carries the
// deleted domain in server_name until the survivor's own row is rendered again.
func TestTheSurvivingVhostIsRenderedAgain(t *testing.T) {
	body := deleteBody(t)

	render := strings.Index(body, "provisioner.RerenderVhost(h.DB, otherID)")
	rowGone := strings.Index(body, "`DELETE FROM domains WHERE id=?`")
	switch {
	case render < 0:
		t.Fatal("the surviving domain's vhost is never rendered again")
	case render < rowGone:
		t.Error("the vhost is rendered while the deleted domain is still in the table")
	}
}
