package quota

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"
)

// resellerChecks are the four reseller-wide gates, with the limit column each
// one reads and the usage query fragment each one counts with.
var resellerChecks = []struct {
	name  string
	limit string
	count string
	call  func(context.Context, *sql.DB, int64) error
}{
	{"customers", "max_customer FROM reseller_limits", "COUNT(*) FROM customers", CheckResellerCustomerAllowed},
	{"domains", "max_domain FROM reseller_limits", "COUNT(*)\n\t\tFROM domains d JOIN customers c", CheckResellerDomainAllowed},
	{"disk", "disk_quota_mb FROM reseller_limits", "SUM(d.size_kb)", CheckResellerDiskAllowed},
	{"traffic", "traffic_quota_mb FROM reseller_limits", "SUM(d.traffic_kb)", CheckResellerTrafficAllowed},
}

// clearScript answers every query of every reseller check with room to spare.
// A test then breaks exactly the one it is about.
func clearScript() *script {
	return &script{
		rows: map[string][]driver.Value{
			"max_customer FROM reseller_limits":             {int64(10)},
			"max_domain FROM reseller_limits":               {int64(10)},
			"disk_quota_mb FROM reseller_limits":            {int64(1000)},
			"traffic_quota_mb FROM reseller_limits":         {int64(1000)},
			"COUNT(*) FROM customers":                       {int64(1)},
			"COUNT(*)\n\t\tFROM domains d JOIN customers c": {int64(1)},
			"SUM(d.size_kb)":                                {int64(1024)},
			"SUM(d.traffic_kb)":                             {int64(1024)},
		},
		fail: map[string]error{},
	}
}

// The customer-plan half of this file returns the count error with a FAIL-CLOSED
// comment. The reseller half collapsed every error into "no row = unlimited", so
// one unhealthy database moment lifted all four ceilings at once. The gate runs
// at creation time only, so the excess stays after the database recovers.
func TestAnUnreadableResellerLimitRefuses(t *testing.T) {
	for _, check := range resellerChecks {
		t.Run(check.name, func(t *testing.T) {
			s := clearScript()
			s.fail[check.limit] = errCountUnavailable

			err := check.call(context.Background(), scriptedDB(t, s), 42)
			if err == nil {
				t.Fatal("an unreadable limit was treated as unlimited")
			}
			if _, ok := errors.AsType[*LimitError](err); ok {
				t.Fatalf("a database failure was reported as a quota limit: %v", err)
			}
		})
	}
}

// The usage count decides whether the ceiling has room. Discarded, it stayed at
// zero, which passes every ceiling.
func TestAnUnreadableResellerUsageRefuses(t *testing.T) {
	for _, check := range resellerChecks {
		t.Run(check.name, func(t *testing.T) {
			s := clearScript()
			s.fail[check.count] = errCountUnavailable

			err := check.call(context.Background(), scriptedDB(t, s), 42)
			if err == nil {
				t.Fatal("an unreadable usage count was treated as room under the ceiling")
			}
			if _, ok := errors.AsType[*LimitError](err); ok {
				t.Fatalf("a database failure was reported as a quota limit: %v", err)
			}
		})
	}
}

// A reseller with no reseller_limits row is genuinely unlimited, and that is the
// ONLY error that may mean it.
func TestAMissingResellerLimitRowStaysUnlimited(t *testing.T) {
	for _, check := range resellerChecks {
		t.Run(check.name, func(t *testing.T) {
			s := clearScript()
			s.fail[check.limit] = sql.ErrNoRows

			if err := check.call(context.Background(), scriptedDB(t, s), 42); err != nil {
				t.Fatalf("a reseller with no limits row was refused: %v", err)
			}
		})
	}
}

// The opposite direction, so the tests above are not merely watching a guard
// that always refuses.
func TestAResellerUnderEveryCeilingPasses(t *testing.T) {
	for _, check := range resellerChecks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.call(context.Background(), scriptedDB(t, clearScript()), 42); err != nil {
				t.Fatalf("a reseller under its ceiling was refused: %v", err)
			}
		})
	}
}
