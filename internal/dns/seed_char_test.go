package dns

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"
)

const (
	templateQuery     = "FROM dns_template ORDER BY sort_order, id"
	templateMetaQuery = "FROM dns_template_meta WHERE id=1"
	resellerNSQuery   = "JOIN reseller_nameservers rn"
	panelNSQuery      = "SELECT ns1_hostname, ns2_hostname FROM panel_settings"
	domainIPv6Query   = "SELECT COALESCE(ipv6,'') FROM domains WHERE id=?"
	seedCountQuery    = "SELECT COUNT(*) FROM dns_records WHERE domain_id=? AND name=? AND type=? AND value=?"
	seedInsert        = "VALUES(?,?,?,?,?,?,1)"
	soaCountQuery     = "SELECT COUNT(*) FROM dns_soa WHERE domain_id=?"
	soaInsert         = "INSERT INTO dns_soa"
	aaaaCountQuery    = "SELECT COUNT(*) FROM dns_records WHERE domain_id=? AND name=? AND type='AAAA'"
	aaaaInsert        = "VALUES(?,?,'AAAA',?,?,0,1)"
)

// templateRow is one stored template row, in the order LoadTemplate selects.
func templateRow(name, recordType, value string, enabled int) []driver.Value {
	return []driver.Value{int64(1), name, recordType, value, int64(3600), int64(0), int64(10), int64(enabled)}
}

// seedScript answers a seed run for domain 7, example.com, with the panel-wide
// nameserver pair, no IPv6 address and no stored SOA row.
func seedScript(rows ...[]driver.Value) *sqlScript {
	s := newScript()
	s.rows[templateQuery] = rows
	s.rows[templateMetaQuery] = nil
	s.rows[resellerNSQuery] = nil
	s.rows[panelNSQuery] = [][]driver.Value{{"ns1.host.example", "ns2.host.example"}}
	s.rows[domainIPv6Query] = [][]driver.Value{{""}}
	s.rows[seedCountQuery] = [][]driver.Value{{int64(0)}}
	s.rows[glueStale] = nil
	s.rows[soaCountQuery] = [][]driver.Value{{int64(0)}}
	return s
}

// seedSOAWrite is the SOA row a seed writes for a domain that has none.
var seedSOAWrite = sqlScriptExec{query: soaInsert, args: []driver.Value{
	int64(7), "ns1.host.example", "admin@example.com",
	int64(3600), int64(900), int64(1209600), int64(3600), int64(3600),
}}

// recordWrite is the statement a seeded record produces.
func recordWrite(name, recordType, value string) sqlScriptExec {
	return sqlScriptExec{query: seedInsert, args: []driver.Value{
		int64(7), name, recordType, value, int64(3600), int64(0),
	}}
}

// dkimFunc is the ensureDKIM seam's own type, so a test can swap it.
type dkimFunc = func(context.Context, *sql.DB, int64, string, string) (string, error)

func TestSeedDefaultsWritesOnlyWhatTheZoneIsMissing(t *testing.T) {
	dkimRow := templateRow("default._domainkey", "TXT", "{DKIM}", 1)
	cases := []struct {
		name   string
		rows   [][]driver.Value
		script func(s *sqlScript)
		dkim   dkimFunc
		added  int
		writes []sqlScriptExec
	}{
		{name: "a record the zone does not hold", rows: [][]driver.Value{templateRow("@", "A", "{IP}", 1)},
			added: 1, writes: []sqlScriptExec{recordWrite("@", "A", "192.0.2.10"), seedSOAWrite}},
		{name: "a record that is already there", rows: [][]driver.Value{templateRow("@", "A", "{IP}", 1)},
			script: func(s *sqlScript) { s.rows[seedCountQuery] = [][]driver.Value{{int64(1)}} },
			writes: []sqlScriptExec{seedSOAWrite}},
		{name: "a disabled template row", rows: [][]driver.Value{templateRow("@", "A", "{IP}", 0)},
			writes: []sqlScriptExec{seedSOAWrite}},
		{name: "an AAAA row on a domain with no IPv6", rows: [][]driver.Value{templateRow("@", "AAAA", "{IP6}", 1)},
			writes: []sqlScriptExec{seedSOAWrite}},
		{name: "an AAAA row on a domain that has one", rows: [][]driver.Value{templateRow("@", "AAAA", "{IP6}", 1)},
			script: func(s *sqlScript) { s.rows[domainIPv6Query] = [][]driver.Value{{"2001:db8::1"}} },
			added:  1, writes: []sqlScriptExec{recordWrite("@", "AAAA", "2001:db8::1"), seedSOAWrite}},
		{name: "a DKIM row with a key", rows: [][]driver.Value{dkimRow},
			dkim:  func(context.Context, *sql.DB, int64, string, string) (string, error) { return "v=DKIM1; p=abc", nil },
			added: 1, writes: []sqlScriptExec{recordWrite("default._domainkey", "TXT", "v=DKIM1; p=abc"), seedSOAWrite}},
		{name: "a DKIM row whose key cannot be made", rows: [][]driver.Value{dkimRow},
			dkim:   func(context.Context, *sql.DB, int64, string, string) (string, error) { return "", errScripted },
			writes: []sqlScriptExec{seedSOAWrite}},
		{name: "a record the database refuses", rows: [][]driver.Value{templateRow("@", "A", "{IP}", 1)},
			script: func(s *sqlScript) { s.fail[seedInsert] = errScripted },
			writes: []sqlScriptExec{recordWrite("@", "A", "192.0.2.10"), seedSOAWrite}},
		{name: "a domain that already has an SOA row", rows: [][]driver.Value{templateRow("@", "A", "{IP}", 1)},
			script: func(s *sqlScript) { s.rows[soaCountQuery] = [][]driver.Value{{int64(1)}} },
			added:  1, writes: []sqlScriptExec{recordWrite("@", "A", "192.0.2.10")}},
		{name: "glue records that cannot be settled", rows: [][]driver.Value{templateRow("@", "A", "{IP}", 1)},
			script: func(s *sqlScript) { s.fail[glueStale] = errScripted },
			added:  1, writes: []sqlScriptExec{recordWrite("@", "A", "192.0.2.10"), seedSOAWrite}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := seedScript(tc.rows...)
			if tc.script != nil {
				tc.script(script)
			}
			setForTest(t, &ensureDKIM, refusedDKIM(t, tc.dkim))
			added, err := SeedDefaults(context.Background(), scriptDB(t, script), 7, "example.com", "192.0.2.10")
			assertCountAndErr(t, added, err, tc.added, nil)
			assertWrites(t, script, tc.writes)
		})
	}
}

// refusedDKIM returns the case's DKIM function, or one that fails the test
// because the case must never reach the key generator.
func refusedDKIM(t *testing.T, dkim dkimFunc) dkimFunc {
	t.Helper()
	if dkim != nil {
		return dkim
	}
	return func(context.Context, *sql.DB, int64, string, string) (string, error) {
		t.Error("the seed asked for a DKIM key it does not need")
		return "", nil
	}
}

func assertCountAndErr(t *testing.T, count int, err error, wantCount int, wantErr error) {
	t.Helper()
	if count != wantCount {
		t.Errorf("count = %d, want %d", count, wantCount)
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want %v", err, wantErr)
	}
}

// A stored template that cannot be read falls back to the built-in one, so the
// zone still gets its records.
func TestSeedDefaultsFallsBackToTheBuiltInTemplate(t *testing.T) {
	script := seedScript()
	script.fail[templateQuery] = errScripted
	setForTest(t, &ensureDKIM, dkimFunc(func(context.Context, *sql.DB, int64, string, string) (string, error) {
		return "v=DKIM1; p=abc", nil
	}))
	added, err := SeedDefaults(context.Background(), scriptDB(t, script), 7, "example.com", "192.0.2.10")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	// 15 of the built-in template's rows reach a domain with no IPv6 address:
	// the rest are disabled or exist only to carry that address.
	if added != 15 {
		t.Errorf("added = %d, want 15 of the %d built-in rows", added, len(builtinDefaults()))
	}
}

// A domain with no IPv4 address is seeded against the loopback address, which
// is what the template's {IP} placeholder then resolves to.
func TestSeedDefaultsFallsBackToTheLoopbackAddress(t *testing.T) {
	script := seedScript(templateRow("@", "A", "{IP}", 1))
	setForTest(t, &ensureDKIM, refusedDKIM(t, nil))
	added, err := SeedDefaults(context.Background(), scriptDB(t, script), 7, "example.com", "")
	if err != nil || added != 1 {
		t.Fatalf("added = %d, err = %v", added, err)
	}
	assertWrites(t, script, []sqlScriptExec{recordWrite("@", "A", "127.0.0.1"), seedSOAWrite})
}

// ipv6Script answers an addIPv6Records run for domain 7 with the panel-wide
// nameserver pair and no AAAA record yet.
func ipv6Script(rows ...[]driver.Value) *sqlScript {
	s := newScript()
	s.rows[templateQuery] = rows
	s.rows[templateMetaQuery] = nil
	s.rows[resellerNSQuery] = nil
	s.rows[panelNSQuery] = [][]driver.Value{{"ns1.host.example", "ns2.host.example"}}
	s.rows[aaaaCountQuery] = [][]driver.Value{{int64(0)}}
	return s
}

// A stored template that cannot be read falls back to the built-in one on this
// path too, so a domain that gains an address still gets its AAAA records.
func TestAddIPv6RecordsFallsBackToTheBuiltInTemplate(t *testing.T) {
	script := ipv6Script()
	script.fail[templateQuery] = errScripted
	added, err := addIPv6Records(context.Background(), scriptDB(t, script), 7, "example.com", "2001:db8::1")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if added != 7 {
		t.Errorf("added = %d, want the built-in template's 7 AAAA rows", added)
	}
}

func TestAddIPv6RecordsWritesTheTemplatesAAAARows(t *testing.T) {
	aaaaRow := templateRow("@", "AAAA", "{IP6}", 1)
	written := sqlScriptExec{query: aaaaInsert, args: []driver.Value{int64(7), "@", "2001:db8::1", int64(3600)}}
	cases := []struct {
		name    string
		rows    [][]driver.Value
		next    string
		script  func(s *sqlScript)
		added   int
		wantErr error
		writes  []sqlScriptExec
	}{
		{name: "a domain with no address", rows: [][]driver.Value{aaaaRow}},
		{name: "an AAAA row the zone is missing", rows: [][]driver.Value{aaaaRow}, next: "2001:db8::1",
			added: 1, writes: []sqlScriptExec{written}},
		{name: "a name that already answers over IPv6", rows: [][]driver.Value{aaaaRow}, next: "2001:db8::1",
			script: func(s *sqlScript) { s.rows[aaaaCountQuery] = [][]driver.Value{{int64(1)}} }},
		{name: "a count that cannot be read", rows: [][]driver.Value{aaaaRow}, next: "2001:db8::1",
			script:  func(s *sqlScript) { s.fail[aaaaCountQuery] = errScripted },
			wantErr: errScripted},
		{name: "an insert the database refuses", rows: [][]driver.Value{aaaaRow}, next: "2001:db8::1",
			script:  func(s *sqlScript) { s.fail[aaaaInsert] = errScripted },
			wantErr: errScripted, writes: []sqlScriptExec{written}},
		{name: "rows that do not carry this domain's address", next: "2001:db8::1",
			rows: [][]driver.Value{
				templateRow("@", "A", "{IP}", 1),
				templateRow("fixed", "AAAA", "2001:db8::99", 1),
				templateRow("off", "AAAA", "{IP6}", 0),
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := ipv6Script(tc.rows...)
			if tc.script != nil {
				tc.script(script)
			}
			added, err := addIPv6Records(context.Background(), scriptDB(t, script), 7, "example.com", tc.next)
			assertCountAndErr(t, added, err, tc.added, tc.wantErr)
			assertWrites(t, script, tc.writes)
		})
	}
}
