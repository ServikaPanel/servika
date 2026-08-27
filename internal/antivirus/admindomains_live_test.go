package antivirus

// The per-domain summary, exercised against a real MariaDB.
//
// Everything asserted here lives in the server rather than in Go: the scope
// narrowing is a clause over a join, the containment state is a LEFT JOIN whose
// right side may be absent, and the two scan filters are about rows other parts
// of this package write. None of it can be proved with a fake.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"servika/internal/middleware"

	_ "github.com/go-sql-driver/mysql"
)

type domainListBody struct {
	Entries     []DomainEntry `json:"entries"`
	LastSweepAt string        `json:"last_sweep_at"`
}

func domainList(t *testing.T, h *Handlers, r *http.Request) domainListBody {
	t.Helper()
	rec := httptest.NewRecorder()
	h.AdminDomains(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("the list answered %d: %s", rec.Code, rec.Body.String())
	}
	var body domainListBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return body
}

func domainEntry(entries []DomainEntry, domainID int64) (DomainEntry, bool) {
	for _, entry := range entries {
		if entry.DomainID == domainID {
			return entry, true
		}
	}
	return DomainEntry{}, false
}

// insertRow adds a fixture row and removes it again, so a test that fails half
// way does not leave the next run failing on a duplicate instead of the defect.
func insertRow(t *testing.T, db *sql.DB, table, query string, args ...any) int64 {
	t.Helper()
	res, err := db.ExecContext(context.Background(), query, args...)
	if err != nil {
		t.Fatalf("fixture: %v (%s)", err, query)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("fixture id: %v", err)
	}
	t.Cleanup(func() {
		// #nosec G202 -- table is a literal from this file, never caller text.
		_, _ = db.Exec(`DELETE FROM `+table+` WHERE id=?`, id)
	})
	return id
}

// A reseller sees their own domains and nobody else's. The narrowing has to be
// in the query, because rows filtered afterwards have already been read.
func TestTheDomainListIsNarrowedToTheCallersScope(t *testing.T) {
	db := liveDB(t)
	h := &Handlers{DB: db}
	f := newQuarantineFixture(t, db)

	admin := domainList(t, h, scopedRequest(middleware.RoleAdmin, f.adminID))
	if _, ok := domainEntry(admin.Entries, f.domainA); !ok {
		t.Error("the admin cannot see domain A")
	}
	if _, ok := domainEntry(admin.Entries, f.domainB); !ok {
		t.Error("the admin cannot see domain B")
	}

	resellerA := domainList(t, h, scopedRequest(middleware.RoleReseller, f.resellerA))
	if _, ok := domainEntry(resellerA.Entries, f.domainA); !ok {
		t.Error("reseller A cannot see their own domain")
	}
	if _, ok := domainEntry(resellerA.Entries, f.domainB); ok {
		t.Error("reseller A can see a neighbour's domain")
	}
}

// An addon row carries its PARENT's system_user, and the per-domain scan builds
// its root from that name. Offering such a row would scan the parent's tree and
// record the result against the wrong domain.
func TestAnAddonRowIsNotOfferedAsItsOwnDomain(t *testing.T) {
	db := liveDB(t)
	h := &Handlers{DB: db}
	f := newQuarantineFixture(t, db)

	var parentUser string
	if err := db.QueryRow(`SELECT system_user FROM domains WHERE id=?`, f.domainA).Scan(&parentUser); err != nil {
		t.Fatalf("read the parent system user: %v", err)
	}
	addon := insertRow(t, db, "domains",
		`INSERT INTO domains (domain_name, system_user, customer_id, parent_domain_id)
		 SELECT ?, ?, customer_id, ? FROM domains WHERE id=?`,
		uniqueName(t, "addon")+".example.com", parentUser, f.domainA, f.domainA)

	body := domainList(t, h, scopedRequest(middleware.RoleAdmin, f.adminID))
	if _, ok := domainEntry(body.Entries, addon); ok {
		t.Error("an addon row is listed as a domain of its own")
	}
	if _, ok := domainEntry(body.Entries, f.domainA); !ok {
		t.Error("the parent disappeared with it")
	}
}

// A real-time detection writes a FINISHED av_scans row with domain_id set and
// scanned=1. Read as the domain's last scan it says "1 file", which is not a
// scan of anything. A running scan is not the last one either.
func TestOnlyAFinishedScanOfThisDomainCountsAsItsLastScan(t *testing.T) {
	db := liveDB(t)
	h := &Handlers{DB: db}
	f := newQuarantineFixture(t, db)

	read := func() DomainEntry {
		t.Helper()
		body := domainList(t, h, scopedRequest(middleware.RoleAdmin, f.adminID))
		entry, ok := domainEntry(body.Entries, f.domainA)
		if !ok {
			t.Fatal("the domain is missing from the list")
		}
		return entry
	}

	// A real scan of this domain, and it IS reported. Without this the two
	// checks below would pass on a column that never reports anything.
	insertRow(t, db, "av_scans",
		`INSERT INTO av_scans (domain_id, scope, status, scanned, engine, source, finished_at)
		 VALUES (?, 'domain', 'finished', 4210, 'heuristic', ?, NOW())`, f.domainA, SourceManual)
	if entry := read(); entry.LastScanAt == "" || entry.Scanned != 4210 {
		t.Fatalf("a finished scan of the domain was not reported: %q (%d files)",
			entry.LastScanAt, entry.Scanned)
	}

	// Each competing row is inserted AFTER it, so it has the higher id and wins
	// the ORDER BY whenever its filter is missing. Inserting them first would
	// leave the real scan winning on id alone and neither filter would be
	// measured (proven: with them first, dropping status='finished' still
	// passed).
	//
	// What the watcher writes: domain_id set, scope realtime, scanned 1.
	insertRow(t, db, "av_scans",
		`INSERT INTO av_scans (domain_id, scope, status, scanned, infected, engine, source, finished_at)
		 VALUES (?, 'realtime', 'finished', 1, 1, 'heuristic', ?, NOW())`, f.domainA, SourceRealtime)
	if entry := read(); entry.Scanned != 4210 {
		t.Errorf("a realtime detection was reported as the last scan: %q (%d files)",
			entry.LastScanAt, entry.Scanned)
	}

	// A scan of this domain that has not finished yet.
	insertRow(t, db, "av_scans",
		`INSERT INTO av_scans (domain_id, scope, status, engine, source)
		 VALUES (?, 'domain', 'running', 'heuristic', ?)`, f.domainA, SourceManual)
	if entry := read(); entry.LastScanAt == "" || entry.Scanned != 4210 {
		t.Errorf("a running scan was reported as the last one: %q (%d files)",
			entry.LastScanAt, entry.Scanned)
	}
}

// A sweep writes domain_id NULL, so it can never reach the per-domain column.
// On a server where only the nightly sweep runs, every row would read "never"
// for good, so the sweep travels beside the list as its own value.
func TestTheServerSweepIsReportedBesideTheDomainsItCovers(t *testing.T) {
	db := liveDB(t)
	h := &Handlers{DB: db}
	f := newQuarantineFixture(t, db)

	insertRow(t, db, "av_scans",
		`INSERT INTO av_scans (domain_id, scope, status, scanned, engine, source, finished_at)
		 VALUES (NULL, 'host', 'finished', 900000, 'heuristic', ?, NOW())`, SourceScheduled)

	body := domainList(t, h, scopedRequest(middleware.RoleAdmin, f.adminID))
	if body.LastSweepAt == "" {
		t.Fatal("a finished sweep was not reported")
	}
	entry, ok := domainEntry(body.Entries, f.domainA)
	if !ok {
		t.Fatal("the domain is missing from the list")
	}
	if entry.LastScanAt != "" {
		t.Errorf("the sweep leaked into the domain's own scan column: %q", entry.LastScanAt)
	}
}

// The number that means somebody has to act is the detection LEFT WHERE IT WAS
// FOUND. It is derived from av_quarantine rather than read from
// av_findings.quarantined, because that column records what happened when the
// row was written and is never updated afterwards.
func TestContainmentMovesAFindingBetweenTheTwoCounts(t *testing.T) {
	db := liveDB(t)
	h := &Handlers{DB: db}
	f := newQuarantineFixture(t, db)

	scan := insertRow(t, db, "av_scans",
		`INSERT INTO av_scans (domain_id, scope, status, engine, source, finished_at)
		 VALUES (?, 'domain', 'finished', 'heuristic', ?, NOW())`, f.domainA, SourceManual)
	// quarantined=1 is written deliberately: the count must NOT come from it.
	finding := insertRow(t, db, "av_findings",
		`INSERT INTO av_findings (scan_id, domain_id, file, signature, engine, quarantined)
		 VALUES (?, ?, 'public_html/shell.php', 'PHP.Webshell.EvalBase64', 'heuristic', 1)`,
		scan, f.domainA)

	read := func() DomainEntry {
		t.Helper()
		body := domainList(t, h, scopedRequest(middleware.RoleAdmin, f.adminID))
		entry, ok := domainEntry(body.Entries, f.domainA)
		if !ok {
			t.Fatal("the domain is missing from the list")
		}
		return entry
	}

	// The fixture already holds one file for this domain, so the held count
	// starts at one and the finding is uncontained despite quarantined=1.
	before := read()
	if before.Uncontained != 1 {
		t.Errorf("a finding nobody contained was counted as %d, want 1", before.Uncontained)
	}
	baseHeld := before.Held

	held := insertRow(t, db, "av_quarantine",
		`INSERT INTO av_quarantine (domain_id, finding_id, system_user, orig_rel, stored_name, signature, engine)
		 SELECT domain_id, ?, system_user, 'public_html/shell.php', ?, signature, engine
		   FROM av_quarantine WHERE id=?`, finding, uniqueName(t, "q")+".php", f.entryA)

	taken := read()
	if taken.Uncontained != 0 {
		t.Errorf("a contained finding is still counted as left in place: %d", taken.Uncontained)
	}
	if taken.Held != baseHeld+1 {
		t.Errorf("held is %d, want %d", taken.Held, baseHeld+1)
	}

	// Putting it back makes it a finding nobody contained again. Reading
	// av_findings.quarantined would still say it was taken.
	if _, err := db.Exec(`UPDATE av_quarantine SET restored_at=NOW() WHERE id=?`, held); err != nil {
		t.Fatalf("restore: %v", err)
	}
	restored := read()
	if restored.Uncontained != 1 {
		t.Errorf("a restored file is not counted as left in place again: %d", restored.Uncontained)
	}
	if restored.Held != baseHeld {
		t.Errorf("held is %d after a restore, want %d", restored.Held, baseHeld)
	}
}

// A control that can never succeed is worse than no control. Scan refuses a
// demo subscription with 403, so the row says so instead.
func TestADemoDomainIsNotOfferedAScan(t *testing.T) {
	db := liveDB(t)
	h := &Handlers{DB: db}
	f := newQuarantineFixture(t, db)

	body := domainList(t, h, scopedRequest(middleware.RoleAdmin, f.adminID))
	entry, ok := domainEntry(body.Entries, f.domainA)
	if !ok {
		t.Fatal("the domain is missing from the list")
	}
	if !entry.Scannable {
		t.Fatal("an ordinary domain is not offered a scan, so the flag proves nothing")
	}

	if _, err := db.Exec(`UPDATE domains SET is_demo=1 WHERE id=?`, f.domainA); err != nil {
		t.Fatalf("mark the domain as demo: %v", err)
	}
	body = domainList(t, h, scopedRequest(middleware.RoleAdmin, f.adminID))
	entry, _ = domainEntry(body.Entries, f.domainA)
	if entry.Scannable {
		t.Error("a demo domain is offered a scan the handler always refuses")
	}
}
