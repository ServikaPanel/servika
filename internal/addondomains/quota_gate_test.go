package addondomains

import (
	"os"
	"strings"
	"testing"
)

// Create prepares a document root and writes a domains row, so it cannot be
// executed here without a host. What this pins is that BOTH ceilings are asked
// about before anything is built, which is the part that was missing.
//
// The checks themselves are proven against a scripted database in internal/quota.
func createBody(t *testing.T) string {
	t.Helper()
	source, err := os.ReadFile("addondomains.go")
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

// An addon domain is a real domains row, and every reseller count query includes
// it: none filters on parent_domain_id. Creating one therefore consumes the
// reseller's contracted domain, disk and traffic totals, so it has to pass the
// same three ceilings the top-level path passes. The route is CustomerScope, so
// without this a plain customer could push its own reseller past a ceiling only
// that reseller's administrator can set.
func TestTheAddonPathAppliesBothTheCustomerAndTheResellerCeilings(t *testing.T) {
	body := createBody(t)
	if !strings.Contains(body, "quota.CheckDomainAllowed(r.Context(), h.DB, parent.CustomerID)") {
		t.Error("the customer plan ceiling is not applied to the parent's customer")
	}
	if !strings.Contains(body, "quota.CheckResellerAllowedForCustomer(r.Context(), h.DB, parent.CustomerID)") {
		t.Error("the reseller-wide domain, disk and traffic ceilings are not applied")
	}
}

// Both gates run before the document root is built, or a refused request leaves
// a directory behind that nothing owns.
func TestTheAddonCeilingsRunBeforeTheDocumentRootIsPrepared(t *testing.T) {
	body := createBody(t)
	reseller := strings.Index(body, "quota.CheckResellerAllowedForCustomer(")
	// prepareRoot is the seam that stands in for prepareDocRoot in a test.
	prepare := strings.Index(body, "prepareRoot(")
	if reseller < 0 || prepare < 0 {
		t.Fatal("one of the two steps is missing from Create")
	}
	if reseller > prepare {
		t.Error("the reseller ceiling is checked after the document root is prepared")
	}
}

// Both ceilings are a COUNT followed by a separate INSERT, and the unique keys
// on domains constrain the NAME rather than the per-customer count. Without the
// per-customer lock held across the check and the insert, concurrent requests
// all read the same total and all insert, so a plan allowing one addon yields
// as many as the customer fires at once.
func TestTheAddonCreateHoldsThePerCustomerLockAcrossTheInsert(t *testing.T) {
	body := createBody(t)
	lock := strings.Index(body, "quota.LockCustomerForDomain(")
	check := strings.Index(body, "quota.CheckDomainAllowed(")
	insert := strings.Index(body, "INSERT INTO domains(")
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
