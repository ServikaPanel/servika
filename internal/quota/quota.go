// Package quota enforces plan limits before domains, databases, or FTP accounts are added.
package quota

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
)

// customerMu serializes quota-check-then-create sequences per customer within this
// single-process panel. Without it, concurrent create requests can each pass the count
// check before any insert lands and exceed a plan limit (a check/insert race). Callers
// hold the lock across both the CheckDatabaseAllowed call and the account creation.
var customerMu sync.Map // customerID (int64) -> *sync.Mutex

// LockCustomerForDomain resolves the domain's customer and locks a per-customer mutex,
// returning an unlock function. Admin-owned domains (no customer) return a no-op unlock.
// Use it to make a quota check and the subsequent resource creation atomic:
//
//	unlock := quota.LockCustomerForDomain(ctx, db, domainID)
//	defer unlock()
//	// ... CheckDatabaseAllowed + create ...
func LockCustomerForDomain(ctx context.Context, db *sql.DB, domainID int64) func() {
	var customerID *int64
	if err := db.QueryRowContext(ctx, `SELECT customer_id FROM domains WHERE id=?`, domainID).Scan(&customerID); err != nil || customerID == nil {
		return func() {} // No customer (admin) or lookup failed: the quota check itself will fail closed.
	}
	actual, _ := customerMu.LoadOrStore(*customerID, &sync.Mutex{})
	mu := actual.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// LimitError reports that a plan quota has been reached.
type LimitError struct {
	Message string
}

func (e *LimitError) Error() string { return e.Message }

// ---------- Reseller limits (WHM "reseller limits" equivalent) ----------
//
// A reseller with no row in reseller_limits is UNLIMITED; a 0 value also means
// unlimited (the same quota contract service_plans already uses). Defining a
// limit therefore stays optional and existing behavior is unchanged.

// CheckResellerCustomerAllowed reports whether a reseller may create one more customer.
func CheckResellerCustomerAllowed(ctx context.Context, db *sql.DB, resellerUserID int64) error {
	maximum, err := resellerLimit(ctx, db, resellerUserID, "max_customer")
	if err != nil || maximum <= 0 {
		return nil
	}
	var current int
	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM customers WHERE owner_user_id=?`, resellerUserID).Scan(&current)
	if current >= maximum {
		return &LimitError{Message: fmt.Sprintf("reseller limit reached: at most %d customers", maximum)}
	}
	return nil
}

// CheckResellerDomainAllowed reports whether the reseller's total domain quota is full.
//
// This is separate from the customer plan's max_domain: that caps a single
// customer, this caps the sum across all of the reseller's customers. Both apply.
func CheckResellerDomainAllowed(ctx context.Context, db *sql.DB, resellerUserID int64) error {
	maximum, err := resellerLimit(ctx, db, resellerUserID, "max_domain")
	if err != nil || maximum <= 0 {
		return nil
	}
	var current int
	_ = db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM domains d JOIN customers c ON c.id = d.customer_id
		WHERE c.owner_user_id = ?`, resellerUserID).Scan(&current)
	if current >= maximum {
		return &LimitError{Message: fmt.Sprintf("reseller limit reached: at most %d domains", maximum)}
	}
	return nil
}

// CheckResellerDiskAllowed reports whether the reseller's total disk usage across
// all of its customers has reached the disk_quota_mb ceiling.
//
// domains.size_kb is refreshed periodically by the disk collector, so this check
// is NOT instantaneous — it reflects the last measurement. It is a "new resource"
// gate, not a hard cut: when the quota is full the reseller cannot create a new
// domain, but existing sites keep running. Enforcing a live disk cut is the job
// of the tenant-level XFS quota, not this check.
func CheckResellerDiskAllowed(ctx context.Context, db *sql.DB, resellerUserID int64) error {
	maximum, err := resellerLimit(ctx, db, resellerUserID, "disk_quota_mb")
	if err != nil || maximum <= 0 {
		return nil
	}
	var usedKB int64
	_ = db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(d.size_kb), 0)
		FROM domains d JOIN customers c ON c.id = d.customer_id
		WHERE c.owner_user_id = ?`, resellerUserID).Scan(&usedKB)
	usedMB := int(usedKB / 1024)
	if usedMB >= maximum {
		return &LimitError{Message: fmt.Sprintf("reseller disk quota full: %d MB / %d MB", usedMB, maximum)}
	}
	return nil
}

// CheckResellerTrafficAllowed reports whether the reseller's total monthly traffic
// across all of its customers has reached the traffic_quota_mb ceiling.
// domains.traffic_kb is filled by the monthly traffic collector, so this too
// reflects the last measurement rather than a live figure.
func CheckResellerTrafficAllowed(ctx context.Context, db *sql.DB, resellerUserID int64) error {
	maximum, err := resellerLimit(ctx, db, resellerUserID, "traffic_quota_mb")
	if err != nil || maximum <= 0 {
		return nil
	}
	var usedKB int64
	_ = db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(d.traffic_kb), 0)
		FROM domains d JOIN customers c ON c.id = d.customer_id
		WHERE c.owner_user_id = ?`, resellerUserID).Scan(&usedKB)
	usedMB := int(usedKB / 1024)
	if usedMB >= maximum {
		return &LimitError{Message: fmt.Sprintf("reseller traffic quota full: %d MB / %d MB", usedMB, maximum)}
	}
	return nil
}

// CheckResellerAllowedForCustomer applies all three reseller-wide ceilings to the
// reseller that OWNS customerID.
//
// The reseller quotas count every domains row belonging to every customer the
// reseller owns, and an addon domain IS such a row: none of the three count
// queries above filters on parent_domain_id. A path that creates one therefore
// has to pass the same gates the top-level path passes, or the reseller's
// contracted totals are not a ceiling at all.
//
// domains.Create takes the reseller from the caller's own claims, because only a
// reseller reaches that branch. An addon domain is created by the CUSTOMER, who
// is not the reseller, so the reseller has to be resolved from the customer here.
//
// A customer with no owner belongs to an administrator and has no reseller
// ceiling. A failed read is refused rather than waved through: the caller cannot
// tell an absent limit from an unreadable one.
func CheckResellerAllowedForCustomer(ctx context.Context, db *sql.DB, customerID *int64) error {
	if customerID == nil {
		return nil
	}
	var ownerUserID *int64
	if err := db.QueryRowContext(ctx,
		`SELECT owner_user_id FROM customers WHERE id=?`, *customerID).Scan(&ownerUserID); err != nil {
		return err // FAIL-CLOSED: never bypass the ceiling on a read error.
	}
	if ownerUserID == nil {
		return nil
	}
	for _, check := range []func(context.Context, *sql.DB, int64) error{
		CheckResellerDomainAllowed, CheckResellerDiskAllowed, CheckResellerTrafficAllowed,
	} {
		if err := check(ctx, db, *ownerUserID); err != nil {
			return err
		}
	}
	return nil
}

// resellerLimit reads a single numeric limit from reseller_limits. Returns 0
// (unlimited) when the reseller has no row.
func resellerLimit(ctx context.Context, db *sql.DB, resellerUserID int64, column string) (int, error) {
	// The column name arrives only as a constant string from within this package
	// (no SQL-injection surface); it is still constrained to the expected values.
	switch column {
	case "max_customer", "max_domain", "disk_quota_mb", "traffic_quota_mb":
	default:
		return 0, fmt.Errorf("unknown limit column: %s", column)
	}
	var v int
	err := db.QueryRowContext(ctx,
		`SELECT `+column+` FROM reseller_limits WHERE user_id=?`, resellerUserID).Scan(&v)
	if err != nil {
		return 0, nil // No row = unlimited.
	}
	return v, nil
}

// CheckDomainAllowed checks the customer's plan.max_domain limit when customerID is set.
func CheckDomainAllowed(ctx context.Context, db *sql.DB, customerID *int64) error {
	if customerID == nil {
		return nil // Administrators have no quota limit.
	}
	var planID *int64
	if err := db.QueryRowContext(ctx, `SELECT plan_id FROM customers WHERE id=?`, *customerID).Scan(&planID); err != nil {
		return err
	}
	if planID == nil {
		return nil
	}
	var maximum int
	if err := db.QueryRowContext(ctx, `SELECT max_domain FROM service_plans WHERE id=?`, *planID).Scan(&maximum); err != nil {
		return err
	}
	if maximum <= 0 {
		return nil // Unlimited.
	}
	var current int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM domains WHERE customer_id=?`, *customerID).Scan(&current); err != nil {
		return err // FAIL-CLOSED: never bypass the limit gate on a count error.
	}
	if current >= maximum {
		return &LimitError{Message: fmt.Sprintf("plan limit exceeded: maximum %d domains", maximum)}
	}
	return nil
}

// CheckDatabaseAllowed checks the domain customer's plan.max_db limit.
func CheckDatabaseAllowed(ctx context.Context, db *sql.DB, domainID int64) error {
	var customerID *int64
	if err := db.QueryRowContext(ctx, `SELECT customer_id FROM domains WHERE id=?`, domainID).Scan(&customerID); err != nil {
		return err
	}
	if customerID == nil {
		return nil
	}
	var planID *int64
	if err := db.QueryRowContext(ctx, `SELECT plan_id FROM customers WHERE id=?`, *customerID).Scan(&planID); err != nil {
		return err
	}
	if planID == nil {
		return nil
	}
	var maximum int
	if err := db.QueryRowContext(ctx, `SELECT max_db FROM service_plans WHERE id=?`, *planID).Scan(&maximum); err != nil {
		return err
	}
	if maximum <= 0 {
		return nil
	}
	var current int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM db_accounts a JOIN domains d ON d.id=a.domain_id WHERE d.customer_id=?`,
		*customerID).Scan(&current); err != nil {
		return err // FAIL-CLOSED: never bypass the limit gate on a count error.
	}
	if current >= maximum {
		return &LimitError{Message: fmt.Sprintf("plan limit exceeded: maximum %d databases", maximum)}
	}
	return nil
}

// CheckAppAllowed checks the domain customer's plan.max_app limit.
//
// The count spans every domain the customer owns, not just this one, so the plan
// caps the account rather than each domain separately. That matches how max_db
// and max_email are counted; an app is a long-running process on the host, so a
// per-domain reading would let one customer multiply them by adding domains.
func CheckAppAllowed(ctx context.Context, db *sql.DB, domainID int64) error {
	var customerID *int64
	if err := db.QueryRowContext(ctx, `SELECT customer_id FROM domains WHERE id=?`, domainID).Scan(&customerID); err != nil {
		return err
	}
	if customerID == nil {
		return nil
	}
	var planID *int64
	if err := db.QueryRowContext(ctx, `SELECT plan_id FROM customers WHERE id=?`, *customerID).Scan(&planID); err != nil {
		return err
	}
	if planID == nil {
		return nil
	}
	var maximum int
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(max_app,0) FROM service_plans WHERE id=?`, *planID).Scan(&maximum); err != nil {
		return err
	}
	if maximum <= 0 {
		return nil
	}
	var current int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM apps a JOIN domains d ON d.id=a.domain_id WHERE d.customer_id=?`,
		*customerID).Scan(&current); err != nil {
		return err // FAIL-CLOSED: never bypass the limit gate on a count error.
	}
	if current >= maximum {
		return &LimitError{Message: fmt.Sprintf("plan limit exceeded: maximum %d applications", maximum)}
	}
	return nil
}

// CheckMailboxAllowed checks the domain customer's plan.max_email limit.
func CheckMailboxAllowed(ctx context.Context, db *sql.DB, domainID int64) error {
	var customerID *int64
	if err := db.QueryRowContext(ctx, `SELECT customer_id FROM domains WHERE id=?`, domainID).Scan(&customerID); err != nil {
		return err
	}
	if customerID == nil {
		return nil
	}
	var planID *int64
	if err := db.QueryRowContext(ctx, `SELECT plan_id FROM customers WHERE id=?`, *customerID).Scan(&planID); err != nil {
		return err
	}
	if planID == nil {
		return nil
	}
	var maximum int
	if err := db.QueryRowContext(ctx, `SELECT max_email FROM service_plans WHERE id=?`, *planID).Scan(&maximum); err != nil {
		return err
	}
	if maximum <= 0 {
		return nil
	}
	var current int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM mailboxes m JOIN domains d ON d.id=m.domain_id WHERE d.customer_id=?`,
		*customerID).Scan(&current); err != nil {
		return err // FAIL-CLOSED: never bypass the limit gate on a count error.
	}
	if current >= maximum {
		return &LimitError{Message: fmt.Sprintf("plan limit exceeded: maximum %d mailboxes", maximum)}
	}
	return nil
}
