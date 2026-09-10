package mail

import (
	"os"
	"strings"
	"testing"
)

// Create writes a Maildir on the host, so it cannot be executed here. What this
// pins is that the per-customer lock spans the plan check and the insert.
//
// The lock's own behaviour is proven with two concurrent callers in
// internal/quota.
func mailboxCreateBody(t *testing.T) string {
	t.Helper()
	source, err := os.ReadFile("mail.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	start := strings.Index(body, "func (h *Handlers) Create(w http.ResponseWriter, r *http.Request) {")
	if start < 0 {
		t.Fatal("Create was renamed; these assertions have to follow it")
	}
	end := strings.Index(body[start:], "\nfunc ")
	if end < 0 {
		return body[start:]
	}
	return body[start : start+end]
}

// max_email is a COUNT followed by a separate INSERT, and the unique key on
// mailboxes constrains the ADDRESS rather than the per-customer count, so
// concurrent requests all read the same total and all insert.
func TestTheMailboxCreateHoldsThePerCustomerLockAcrossTheInsert(t *testing.T) {
	body := mailboxCreateBody(t)
	lock := strings.Index(body, "quota.LockCustomerForDomain(")
	check := strings.Index(body, "quota.CheckMailboxAllowed(")
	insert := strings.Index(body, "INSERT INTO mailboxes(")
	release := strings.Index(body, "\n\tunlock()")
	if lock < 0 || check < 0 || insert < 0 || release < 0 {
		t.Fatal("the lock, the check, the insert or the release is missing from Create")
	}
	if lock > check {
		t.Error("the lock is taken after the quota check, so the race it exists to close is still open")
	}
	if release < insert {
		t.Error("the lock is released before the insert, so a concurrent create still counts a stale total")
	}
}
