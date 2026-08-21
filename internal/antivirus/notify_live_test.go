package antivirus

// The alert unit, measured against a real MariaDB rather than read.

import (
	"context"
	"database/sql"
	"testing"
)

// A sweep that turns up three hundred infected files across three sites writes
// FOUR rows, not three hundred. Upstream's per-finding version writes three
// hundred and buries every other alert on the server under them.
func TestThreeHundredFindingsAcrossThreeSitesWriteFourAlerts(t *testing.T) {
	db := liveDB(t)
	ctx := context.Background()

	domains := make([]int64, 0, 3)
	for i := range 3 {
		domains = append(domains, makeDomain(t, db, i))
	}
	perDomain := map[int64]int{domains[0]: 150, domains[1]: 100, domains[2]: 50}

	before := countNotifications(t, db)
	notifySweep(ctx, db, 987654, perDomain, 0)
	written := countNotifications(t, db) - before

	if written != 4 {
		t.Errorf("a 300-finding sweep across 3 sites wrote %d alerts, expected 4 (one per site plus one summary)", written)
	}

	// One of them is the panel-wide summary, which names no domain: an operator
	// watching a hundred sites needs the total in one line and cannot see the
	// per-domain rows for a customer they do not own.
	var panelWide int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM notifications WHERE ref_type='av_scan' AND ref_id=987654 AND domain_id IS NULL`).
		Scan(&panelWide); err != nil {
		t.Fatal(err)
	}
	if panelWide != 1 {
		t.Errorf("%d panel-wide summaries were written, expected exactly 1", panelWide)
	}
	// And the summary carries the TOTAL, not one site's count.
	var params string
	if err := db.QueryRow(
		`SELECT params FROM notifications WHERE ref_type='av_scan' AND ref_id=987654 AND domain_id IS NULL`).
		Scan(&params); err != nil {
		t.Fatal(err)
	}
	if params == "" || !contains(params, `"count":300`) || !contains(params, `"sites":3`) {
		t.Errorf("the summary does not carry the totals: %s", params)
	}

	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM notifications WHERE ref_type='av_scan' AND ref_id=987654`)
		for _, id := range domains {
			_, _ = db.Exec(`DELETE FROM domains WHERE id=?`, id)
		}
	})
}

// A clean sweep is not an event, so the nightly job does not light the badge
// every morning.
func TestACleanSweepWritesNothingAtAll(t *testing.T) {
	db := liveDB(t)
	before := countNotifications(t, db)
	notifySweep(context.Background(), db, 987655, map[int64]int{}, 0)
	if after := countNotifications(t, db); after != before {
		t.Errorf("a sweep that found nothing wrote %d alert(s)", after-before)
	}
}

func makeDomain(t *testing.T, db *sql.DB, index int) int64 {
	t.Helper()
	name := "notify" + string(rune('a'+index)) + ".example.test"
	user := "c_notify" + string(rune('a'+index))
	_, _ = db.Exec(`DELETE FROM domains WHERE domain_name=?`, name)
	res, err := db.Exec(`INSERT INTO domains (domain_name, system_user) VALUES (?,?)`, name, user)
	if err != nil {
		t.Fatalf("fixture domain: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func countNotifications(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM notifications`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
