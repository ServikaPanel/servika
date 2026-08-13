package backups

import "testing"

// A domain with automatic backups off has no hour and no retention in force, so
// folding it in would report a schedule nobody is running.
func TestOnlyDomainsWithAutomaticBackupsShapeTheBanner(t *testing.T) {
	s := scheduleFacts{Hour: -1, RetentionMin: -1, RetentionMax: -1}
	s.add("none", 3, 7)
	s.add("none", 21, 90)
	if s.Domains != 0 {
		t.Fatalf("a domain with backups off was counted: %d", s.Domains)
	}
	if s.retentionMin() != 0 || s.retentionMax() != 0 {
		t.Fatalf("the -1 sentinel escaped as a retention range: %d-%d", s.retentionMin(), s.retentionMax())
	}
}

// One shared hour is reportable as a time. Two different hours are not, and
// saying "03:00" for a server where half the domains run at 21:00 is the fixed
// sentence this replaced.
func TestTheHourIsReportedOnlyWhenEveryDomainAgrees(t *testing.T) {
	same := scheduleFacts{Hour: -1, RetentionMin: -1, RetentionMax: -1}
	same.add("daily", 4, 7)
	same.add("weekly", 4, 7)
	if same.Hour != 4 || same.Domains != 2 {
		t.Fatalf("a shared hour was lost: hour=%d domains=%d", same.Hour, same.Domains)
	}

	mixed := scheduleFacts{Hour: -1, RetentionMin: -1, RetentionMax: -1}
	mixed.add("daily", 4, 7)
	mixed.add("daily", 21, 7)
	if mixed.Hour != -1 {
		t.Fatalf("two different hours were reported as %d", mixed.Hour)
	}
	if mixed.Domains != 2 {
		t.Fatalf("the domain count is %d", mixed.Domains)
	}
}

// Midnight is a real hour and 0 is its real value, so the "first domain" test
// cannot be "the hour is still zero".
func TestMidnightIsNotMistakenForAnUnsetHour(t *testing.T) {
	s := scheduleFacts{Hour: -1, RetentionMin: -1, RetentionMax: -1}
	s.add("daily", 0, 7)
	s.add("daily", 0, 7)
	if s.Hour != 0 {
		t.Fatalf("midnight was reported as %d", s.Hour)
	}
}

// Retention is a COUNT of archives and it is per domain, so the banner carries a
// range rather than one number.
func TestRetentionIsReportedAsTheRangeInUse(t *testing.T) {
	s := scheduleFacts{Hour: -1, RetentionMin: -1, RetentionMax: -1}
	s.add("daily", 3, 30)
	s.add("daily", 3, 3)
	s.add("daily", 3, 7)
	if s.retentionMin() != 3 || s.retentionMax() != 30 {
		t.Fatalf("the range is %d-%d", s.retentionMin(), s.retentionMax())
	}
}
