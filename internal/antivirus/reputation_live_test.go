package antivirus

// Domain reputation, exercised against a real MariaDB.
//
// Two things here belong to the server rather than to Go: the scope narrowing is
// a SQL clause over a JOIN, and the "never queried" state is a LEFT JOIN whose
// right side is absent. Neither can be proved with a fake. The blocklist itself
// is replaced by a stub resolver, because a test must not depend on a third
// party's live service and because the three answers being separated (a
// listing, a clean name, an error code) are exactly what a live service refuses
// to give on demand.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"servika/internal/dnsbl"
	"servika/internal/middleware"

	_ "github.com/go-sql-driver/mysql"
)

// stubResolver answers from a table, so the three cases a blocklist can produce
// are all reachable in one test.
type stubResolver map[string][]string

func (s stubResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if addresses, ok := s[host]; ok {
		return addresses, nil
	}
	return nil, errors.New("no such host")
}

func withResolver(t *testing.T, stub dnsbl.HostLookup) {
	t.Helper()
	original := reputationResolver
	t.Cleanup(func() { reputationResolver = original })
	reputationResolver = func() dnsbl.HostLookup { return stub }
}

func setZones(t *testing.T, h *Handlers, zones string) {
	t.Helper()
	if _, err := h.DB.Exec(`UPDATE panel_settings SET domain_dnsbl_zones=? WHERE id=1`, zones); err != nil {
		t.Fatalf("set zones: %v", err)
	}
	t.Cleanup(func() { _, _ = h.DB.Exec(`UPDATE panel_settings SET domain_dnsbl_zones='' WHERE id=1`) })
}

func reputationList(t *testing.T, h *Handlers, r *http.Request) []ReputationEntry {
	t.Helper()
	rec := httptest.NewRecorder()
	h.AdminReputation(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("the list answered %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Entries []ReputationEntry `json:"entries"`
		Zones   []string          `json:"zones"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return body.Entries
}

// hostnameFor gives a fixture domain a name a blocklist can actually be asked
// about. uniqueName separates with underscores, which are legal in a database
// row and not legal in a hostname, and dnsbl.Apex refuses a name that is not
// one rather than sending a query that can only fail.
func hostnameFor(t *testing.T, h *Handlers, domainID int64, label string) string {
	t.Helper()
	name := label + "-" + strings.ToLower(strings.ReplaceAll(t.Name(), "_", "-")) + ".example.test"
	if _, err := h.DB.Exec(`UPDATE domains SET domain_name=? WHERE id=?`, name, domainID); err != nil {
		t.Fatalf("rename the fixture domain: %v", err)
	}
	return name
}

func entryFor(entries []ReputationEntry, domainID int64) (ReputationEntry, bool) {
	for _, entry := range entries {
		if entry.DomainID == domainID {
			return entry, true
		}
	}
	return ReputationEntry{}, false
}

// The three answers a blocklist can give, separated. The middle one is the
// reason this package exists: measured against the live Spamhaus service
// through a public resolver, a listed name and a clean one BOTH answer
// 127.255.255.254, so a scan that reads any resolution as a hit reports every
// domain on the server as listed.
func TestTheThreeBlocklistAnswersAreSeparated(t *testing.T) {
	db := liveDB(t)
	h := &Handlers{DB: db}
	f := newQuarantineFixture(t, db)
	setZones(t, h, "dbl.example.test")
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM domain_reputation WHERE domain_id IN (?,?)`, f.domainA, f.domainB)
	})

	nameA := hostnameFor(t, h, f.domainA, "a")
	nameB := hostnameFor(t, h, f.domainB, "b")

	withResolver(t, stubResolver{
		// A real listing.
		nameA + ".dbl.example.test": {"127.0.1.2"},
		// The blocklist reporting a problem with the QUERY, not an answer about
		// the subject.
		nameB + ".dbl.example.test": {"127.255.255.254"},
	})

	if err := ScanReputation(context.Background(), db); err != nil {
		t.Fatalf("scan: %v", err)
	}

	entries := reputationList(t, h, scopedRequest(middleware.RoleAdmin, f.adminID))
	a, ok := entryFor(entries, f.domainA)
	if !ok {
		t.Fatal("the listed domain is missing from the list")
	}
	if !a.Queried || len(a.Listed) != 1 || a.Listed[0] != "dbl.example.test" {
		t.Errorf("the listed domain came back queried=%v listed=%v", a.Queried, a.Listed)
	}
	b, ok := entryFor(entries, f.domainB)
	if !ok {
		t.Fatal("the domain that got an error code is missing from the list")
	}
	if !b.Queried {
		t.Error("a zone that answered was recorded as not queried")
	}
	if len(b.Listed) != 0 {
		t.Errorf("127.255.255.254 was recorded as a listing: %v", b.Listed)
	}
}

// With no zone configured, a domain is "could not be checked", never clean. An
// empty hit list is what a clean domain produces too, so the two are separated
// by a column rather than by an absence.
func TestNoZoneMeansNotQueriedRatherThanClean(t *testing.T) {
	db := liveDB(t)
	h := &Handlers{DB: db}
	f := newQuarantineFixture(t, db)
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM domain_reputation WHERE domain_id IN (?,?)`, f.domainA, f.domainB)
	})

	withResolver(t, stubResolver{})
	if err := ScanReputation(context.Background(), db); err != nil {
		t.Fatalf("scan: %v", err)
	}

	entries := reputationList(t, h, scopedRequest(middleware.RoleAdmin, f.adminID))
	a, ok := entryFor(entries, f.domainA)
	if !ok {
		t.Fatal("the domain is missing from the list")
	}
	if a.Queried {
		t.Error("a domain nothing asked about was recorded as queried")
	}
	if len(a.Listed) != 0 {
		t.Errorf("a domain nothing asked about carries a listing: %v", a.Listed)
	}
}

// A row whose domain_name is not a hostname is recorded as NOT QUERIED, never
// as clean. The panel validates a domain on the way in, but this reads a column
// that outlives the code that wrote it: a restored database, or a row edited by
// hand, can carry anything. Sending it as a query would produce an error that
// looks exactly like "not listed".
func TestANameThatIsNotAHostnameIsNotQueried(t *testing.T) {
	db := liveDB(t)
	h := &Handlers{DB: db}
	f := newQuarantineFixture(t, db)
	setZones(t, h, "dbl.example.test")
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM domain_reputation WHERE domain_id IN (?,?)`, f.domainA, f.domainB)
	})

	// An underscore is legal in this column and illegal in a hostname.
	if _, err := db.Exec(`UPDATE domains SET domain_name=? WHERE id=?`,
		"not_a_hostname.example.test", f.domainA); err != nil {
		t.Fatal(err)
	}
	// The stub answers EVERYTHING as listed, so a query that was sent would come
	// back as a hit and this test would fail rather than pass by accident.
	withResolver(t, alwaysListed{})

	if err := ScanReputation(context.Background(), db); err != nil {
		t.Fatalf("scan: %v", err)
	}
	entries := reputationList(t, h, scopedRequest(middleware.RoleAdmin, f.adminID))
	entry, ok := entryFor(entries, f.domainA)
	if !ok {
		t.Fatal("the domain is missing from the list")
	}
	if entry.Queried {
		t.Error("a name that is not a hostname was recorded as queried")
	}
	if len(entry.Listed) != 0 {
		t.Errorf("a name that is not a hostname carries a listing: %v", entry.Listed)
	}
}

// alwaysListed answers every query as a listing, so a test asserting that NO
// query was sent cannot pass because the query merely failed.
type alwaysListed struct{}

func (alwaysListed) LookupHost(context.Context, string) ([]string, error) {
	return []string{"127.0.1.2"}, nil
}

// A domain the scanner has never reached is still listed, drawn as unchecked. It
// is exactly the domain an operator needs to see, and leaving it out would make
// the list read as complete when it is not.
func TestADomainWithNoStoredRowIsStillListed(t *testing.T) {
	db := liveDB(t)
	h := &Handlers{DB: db}
	f := newQuarantineFixture(t, db)

	entries := reputationList(t, h, scopedRequest(middleware.RoleAdmin, f.adminID))
	entry, ok := entryFor(entries, f.domainA)
	if !ok {
		t.Fatal("a domain with no stored row was dropped from the list")
	}
	if entry.Queried {
		t.Error("a domain with no stored row reads as queried")
	}
	if entry.LastScanAt != "" {
		t.Errorf("a domain with no stored row carries a scan time: %q", entry.LastScanAt)
	}
}

// Each reseller sees their own domain and not the other's; an admin sees both.
// The narrowing is in the QUERY, because a row-by-row check on a list endpoint
// runs after the rows a caller may not see have already been read.
func TestTheReputationListIsNarrowedToTheCallersScope(t *testing.T) {
	db := liveDB(t)
	h := &Handlers{DB: db}
	f := newQuarantineFixture(t, db)

	admin := reputationList(t, h, scopedRequest(middleware.RoleAdmin, f.adminID))
	if _, ok := entryFor(admin, f.domainA); !ok {
		t.Error("the admin cannot see domain A")
	}
	if _, ok := entryFor(admin, f.domainB); !ok {
		t.Error("the admin cannot see domain B")
	}

	resellerA := reputationList(t, h, scopedRequest(middleware.RoleReseller, f.resellerA))
	if _, ok := entryFor(resellerA, f.domainA); !ok {
		t.Error("reseller A cannot see their own domain")
	}
	if _, ok := entryFor(resellerA, f.domainB); ok {
		t.Error("reseller A can read another reseller's domain off this screen")
	}

	customer := reputationList(t, h, scopedRequest(middleware.RoleUser, f.customerA))
	if _, ok := entryFor(customer, f.domainA); !ok {
		t.Error("the customer cannot see their own domain")
	}
	if _, ok := entryFor(customer, f.domainB); ok {
		t.Error("the customer can read another customer's domain off this screen")
	}
}

// The zone list is validated on the WRITE path, and each way it can be wrong
// answers with its own stable code, because the screen renders twelve languages.
func TestAZoneListIsValidatedOnTheWritePath(t *testing.T) {
	db := liveDB(t)
	h := &Handlers{DB: db}
	t.Cleanup(func() { _, _ = db.Exec(`UPDATE panel_settings SET domain_dnsbl_zones='' WHERE id=1`) })

	save := func(zones string) (int, string) {
		body := strings.NewReader(`{"zones":` + mustJSON(zones) + `}`)
		rec := httptest.NewRecorder()
		h.AdminReputationZonesSave(rec, httptest.NewRequest(http.MethodPut, "/", body))
		return rec.Code, rec.Body.String()
	}

	if code, body := save("dbl.spamhaus.org multi.uribl.com"); code != http.StatusOK {
		t.Fatalf("a valid zone list answered %d: %s", code, body)
	}
	var stored string
	if err := db.QueryRow(`SELECT domain_dnsbl_zones FROM panel_settings WHERE id=1`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "dbl.spamhaus.org multi.uribl.com" {
		t.Errorf("the stored zone list is %q", stored)
	}

	// A single label is not a zone: accepting one lets a typo in a
	// space-separated list pass as an entry that then matches nothing.
	code, body := save("dbl.spamhaus.org notazone")
	if code != http.StatusBadRequest || !strings.Contains(body, reasonZonesInvalid) {
		t.Errorf("an invalid zone answered %d: %s", code, body)
	}
	// A newline would rewrite a Postfix restriction list, so it is refused
	// rather than quoted. strings.Fields splits on it, so the refusal comes from
	// the resulting entry not being a hostname.
	code, body = save("dbl.spamhaus.org\nsmtpd_recipient_restrictions=permit")
	if code != http.StatusBadRequest {
		t.Errorf("a zone list carrying a newline answered %d: %s", code, body)
	}

	long := strings.Repeat("a.example.test ", dnsbl.MaxZones+1)
	code, body = save(long)
	if code != http.StatusBadRequest || !strings.Contains(body, reasonZonesTooMany) {
		t.Errorf("an over-long zone list answered %d: %s", code, body)
	}

	// A refused write leaves the previous value in place.
	if err := db.QueryRow(`SELECT domain_dnsbl_zones FROM panel_settings WHERE id=1`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "dbl.spamhaus.org multi.uribl.com" {
		t.Errorf("a refused write changed the stored list to %q", stored)
	}
}

func mustJSON(value string) string {
	out, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(out)
}
