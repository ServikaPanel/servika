package transfers

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// dnsSeams records the DNS default seeding and zone writing seams.
type dnsSeams struct {
	mu                 sync.Mutex
	seeded             []string
	zones              []int64
	seedFail, zoneFail error
}

func withDNSSeams(t *testing.T, seedFail, zoneFail error) *dnsSeams {
	t.Helper()
	d := &dnsSeams{seedFail: seedFail, zoneFail: zoneFail}
	setForTest(t, &seedDNSDefaults, d.seed)
	setForTest(t, &writeDNSZone, d.zone)
	return d
}

func (d *dnsSeams) seed(_ context.Context, _ *sql.DB, domainID int64, domainName, ipv4 string) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seeded = append(d.seeded, fmt.Sprintf("%d %s %s", domainID, domainName, ipv4))
	return 5, d.seedFail
}

func (d *dnsSeams) zone(_ context.Context, _ *sql.DB, domainID int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.zones = append(d.zones, domainID)
	return d.zoneFail
}

// dnsHolders answers the record lookups migrateDNS makes from the name each one
// asks about: cnamed holds a CNAME, existing holds a record of the asked type,
// and duplicate holds the exact record.
type dnsHolders struct{ cnamed, existing, duplicate string }

func (d dnsHolders) answer(query string, args []driver.Value) ([][]driver.Value, bool) {
	if len(args) < 2 {
		return nil, false
	}
	name, _ := args[1].(string)
	switch {
	case strings.Contains(query, "type='CNAME'"):
		return countRow(name == d.cnamed), true
	case strings.Contains(query, "AND value=?"):
		return countRow(name == d.duplicate), true
	case strings.Contains(query, "FROM dns_records"):
		return countRow(name == d.existing), true
	}
	return nil, false
}

// dnsScript answers the server address lookup and the record lookups.
func dnsScript(holders dnsHolders) *sqlScript {
	s := newScript()
	s.rows["SELECT ipv4 FROM domains"] = [][]driver.Value{{"203.0.113.99"}}
	s.answer = holders.answer
	return s
}

func dnsRecord(name, typ, value string, ttl, priority int64) []driver.Value {
	return []driver.Value{int64(7), name, typ, value, ttl, priority}
}

// The source records merge into the seeded zone: an A record at the apex, at
// www or on the old address moves to this server, a CNAME clears its name once,
// a source-wins type clears the default once, and a record the zone already
// holds is skipped.
func TestMigrateDNSMergesTheSourceRecords(t *testing.T) {
	plesk := strings.Join([]string{
		"example.com. A 198.51.100.7",
		"www.example.com. A 198.51.100.7",
		"shop.example.com. A 198.51.100.7",
		"ext.example.com. A 192.0.2.50",
		"blog.example.com. CNAME host.example.net.",
		"blog.example.com. CNAME other.example.net.",
		"example.com. MX 10 mx1.example.net.",
		"example.com. MX 20 mx2.example.net.",
		"cnamed.example.com. A 192.0.2.60",
		"existing.example.com. A 192.0.2.61",
		"dup.example.com. A 192.0.2.62",
	}, "\n")
	remoteAnswers(t, map[string]commandAnswer{"plesk bin dns --info 'example.com'": {output: plesk}})
	seams := withDNSSeams(t, nil, nil)
	s := dnsScript(dnsHolders{cnamed: "cnamed", existing: "existing", duplicate: "dup"})
	var log logLines

	n, err := (&Handlers{DB: scriptDB(t, s)}).migrateDNS(t.Context(), passwordSource("plesk"), 7, "example.com", log.logf)
	assertErrText(t, err, "")
	if n != 8 {
		t.Fatalf("migrateDNS added %d records, want 8", n)
	}
	assertExecArgs(t, s, "INSERT INTO dns_records",
		dnsRecord("@", "A", "203.0.113.99", 3600, 0),
		dnsRecord("www", "A", "203.0.113.99", 3600, 0),
		dnsRecord("shop", "A", "203.0.113.99", 3600, 0),
		dnsRecord("ext", "A", "192.0.2.50", 3600, 0),
		dnsRecord("blog", "CNAME", "host.example.net", 3600, 0),
		dnsRecord("blog", "CNAME", "other.example.net", 3600, 0),
		dnsRecord("@", "MX", "mx1.example.net", 3600, 10),
		dnsRecord("@", "MX", "mx2.example.net", 3600, 20),
	)
	assertExecArgs(t, s, "DELETE FROM dns_records",
		[]driver.Value{int64(7), "blog"},
		[]driver.Value{int64(7), "@", "MX"},
	)
	if !reflect.DeepEqual(seams.seeded, []string{"7 example.com 203.0.113.99"}) || !reflect.DeepEqual(seams.zones, []int64{7}) {
		t.Fatalf("seeded %q, zones %v", seams.seeded, seams.zones)
	}
	assertLog(t, &log, "DNS: 8 record(s) migrated")
}

// A Plesk store that cannot be read falls back to the zone file, the old address
// comes from the source host when no apex record names it, and the failures of
// the seeding and the zone write are both reported.
func TestMigrateDNSFallsBackToTheZoneFile(t *testing.T) {
	remoteAnswers(t, map[string]commandAnswer{
		"plesk bin dns":   {stderr: "plesk: not found", exit: 127},
		"cat /var/named/": {output: "shop 300 IN A 198.51.100.7\n"},
	})
	withDNSSeams(t, errScripted, errScripted)
	s := dnsScript(dnsHolders{})
	source := passwordSource("plesk")
	source.Host = "198.51.100.7"
	var log logLines

	n, err := (&Handlers{DB: scriptDB(t, s)}).migrateDNS(t.Context(), source, 7, "example.com", log.logf)
	assertErrText(t, err, "the zone could not be written: scripted failure")
	if n != 1 {
		t.Fatalf("migrateDNS added %d records, want 1", n)
	}
	assertExecArgs(t, s, "INSERT INTO dns_records", dnsRecord("shop", "A", "203.0.113.99", 300, 0))
	assertLog(t, &log, "warning: the DNS defaults could not be written: scripted failure")
}

// Without a readable source record the default zone is written, and a refused
// insert is not counted.
func TestMigrateDNSWithoutSourceRecords(t *testing.T) {
	cases := []struct {
		name     string
		zone     commandAnswer
		zoneFail error
		want     string
	}{
		{"an empty zone file", commandAnswer{output: "  \n"}, nil, "the source DNS records could not be read"},
		{"a zone read that fails", commandAnswer{stderr: "denied", exit: 1}, errScripted, "scripted failure"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			remoteAnswers(t, map[string]commandAnswer{"cat /var/named/": c.zone})
			seams := withDNSSeams(t, nil, c.zoneFail)
			n, err := (&Handlers{DB: scriptDB(t, dnsScript(dnsHolders{}))}).migrateDNS(t.Context(), passwordSource("cpanel"), 7, "example.com", (&logLines{}).logf)
			assertErrText(t, err, c.want)
			if n != 0 || !reflect.DeepEqual(seams.zones, []int64{7}) {
				t.Fatalf("n = %d, zones %v", n, seams.zones)
			}
		})
	}

	remoteAnswers(t, map[string]commandAnswer{"cat /var/named/": {output: "@ IN A 192.0.2.1\n"}})
	withDNSSeams(t, nil, nil)
	s := dnsScript(dnsHolders{})
	s.fail["INSERT INTO dns_records"] = errScripted
	var log logLines
	n, err := (&Handlers{DB: scriptDB(t, s)}).migrateDNS(t.Context(), passwordSource("cpanel"), 7, "example.com", log.logf)
	assertErrText(t, err, "")
	if n != 0 {
		t.Fatalf("a refused insert was counted: %d", n)
	}
	assertLog(t, &log, "DNS: 0 record(s) migrated")
}
