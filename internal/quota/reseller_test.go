package quota

import (
	"context"
	"database/sql/driver"
	"errors"
	"testing"
)

// resellerScript answers the owner lookup plus the three ceilings, all clear.
// A test then breaks or tightens exactly the one it is about.
func resellerScript() *script {
	return &script{
		rows: map[string][]driver.Value{
			"owner_user_id FROM customers":                  {int64(9)},
			"max_domain FROM reseller_limits":               {int64(10)},
			"disk_quota_mb FROM reseller_limits":            {int64(1000)},
			"traffic_quota_mb FROM reseller_limits":         {int64(1000)},
			"COUNT(*)\n\t\tFROM domains d JOIN customers c": {int64(1)},
			"SUM(d.size_kb)":                                {int64(1024)},
			"SUM(d.traffic_kb)":                             {int64(1024)},
		},
		fail: map[string]error{},
	}
}

// A customer nobody resells belongs to an administrator, and an administrator
// has no reseller ceiling to be measured against.
func TestACustomerWithNoOwnerHasNoResellerCeiling(t *testing.T) {
	s := resellerScript()
	s.rows["owner_user_id FROM customers"] = []driver.Value{nil}

	if err := CheckResellerAllowedForCustomer(context.Background(), scriptedDB(t, s), new(int64(7))); err != nil {
		t.Fatalf("an administrator-owned customer was refused: %v", err)
	}
}

// A domain created with no customer at all cannot consume a reseller's
// allocation, so there is nothing to check.
func TestNoCustomerMeansNoResellerCheck(t *testing.T) {
	if err := CheckResellerAllowedForCustomer(context.Background(), scriptedDB(t, resellerScript()), nil); err != nil {
		t.Fatalf("an unattached domain was refused: %v", err)
	}
}

// The owner lookup decides WHICH reseller is measured, so an unreadable answer
// must refuse rather than silently skip every ceiling. A guard that returned nil
// here would restore exactly the gap this check exists to close, and only while
// the database is unwell, which is the hardest state to notice it in.
func TestAnUnreadableOwnerRefusesTheDomain(t *testing.T) {
	s := resellerScript()
	s.fail["owner_user_id FROM customers"] = errCountUnavailable

	err := CheckResellerAllowedForCustomer(context.Background(), scriptedDB(t, s), new(int64(7)))
	if err == nil {
		t.Fatal("a failed owner lookup was treated as permission to create the domain")
	}
	if _, ok := errors.AsType[*LimitError](err); ok {
		t.Fatalf("a database failure was reported as a quota limit: %v", err)
	}
}

// A reseller at its domain ceiling refuses the addon, in the same shape the
// top-level path refuses it.
func TestAResellerAtItsDomainCeilingIsRefused(t *testing.T) {
	s := resellerScript()
	s.rows["max_domain FROM reseller_limits"] = []driver.Value{int64(1)}

	err := CheckResellerAllowedForCustomer(context.Background(), scriptedDB(t, s), new(int64(7)))
	if _, ok := errors.AsType[*LimitError](err); !ok {
		t.Fatalf("want a LimitError at the ceiling, got %v", err)
	}
}

// The opposite direction, so the tests above are not merely watching a guard
// that always refuses.
func TestAResellerUnderEveryCeilingIsAllowed(t *testing.T) {
	if err := CheckResellerAllowedForCustomer(context.Background(), scriptedDB(t, resellerScript()), new(int64(7))); err != nil {
		t.Fatalf("a reseller under every ceiling was refused: %v", err)
	}
}
