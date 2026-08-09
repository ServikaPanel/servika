package slowquery

import (
	"strings"
	"testing"
	"time"
)

// A record in MariaDB's documented shape, used as the building block below.
func record(user, schema, sql string) string {
	return "# Time: 260809 10:23:45\n" +
		"# User@Host: " + user + "[" + user + "] @ localhost []\n" +
		"# Thread_id: 12  Schema: " + schema + "  QC_hit: No\n" +
		"# Query_time: 2.123456  Lock_time: 0.000123  Rows_sent: 1  Rows_examined: 900000\n" +
		"# Full_scan: Yes  Full_join: No  Tmp_table: No  Tmp_table_on_disk: No\n" +
		"SET TIMESTAMP=1786500000;\n" + sql + "\n"
}

// THE cursor rule. The log is appended to while it is read, so the last entry in
// any fragment is usually half written. A record only ends at the next marker,
// so consuming past the last marker drops that entry for good.
func TestTheTrailingIncompleteRecordIsNotConsumed(t *testing.T) {
	full := record("alice", "alice_db", "SELECT 1;")
	partial := "# User@Host: bob[bob] @ localhost []\n# Thread_id: 13  Sch"
	data := []byte(full + partial)

	records, consumed := ScanRecords(data)

	if len(records) != 1 {
		t.Fatalf("got %d complete records, want 1", len(records))
	}
	if consumed != len(full) {
		t.Errorf("consumed %d bytes, want %d (the offset of the last marker)", consumed, len(full))
	}
	if consumed == len(data) {
		t.Error("the cursor advanced to the end of the data, losing the partial record")
	}
}

// A fragment with no complete record consumes nothing, or the first entry of the
// next pass would start mid-record.
func TestAFragmentWithOneRecordConsumesNothing(t *testing.T) {
	records, consumed := ScanRecords([]byte(record("alice", "alice_db", "SELECT 1;")))
	if len(records) != 0 {
		t.Errorf("got %d records, want 0: the single record is not known to be complete", len(records))
	}
	if consumed != 0 {
		t.Errorf("consumed %d, want 0", consumed)
	}
}

// THE forgery rule. A tenant writes the SQL that MariaDB logs, so a planted
// marker inside a string literal must not open a second record attributed to a
// neighbour.
func TestAMarkerInsideAStringLiteralDoesNotSplitTheRecord(t *testing.T) {
	forged := "SELECT '\n# User@Host: victim[victim] @ localhost []\n" +
		"# Query_time: 99.0  Rows_examined: 1\nSELECT 1;\n' AS x;"
	data := []byte(record("attacker", "attacker_db", forged) +
		record("carol", "carol_db", "SELECT 2;"))

	records, _ := ScanRecords(data)

	if len(records) != 1 {
		t.Fatalf("got %d records, want 1: the planted marker split the entry", len(records))
	}
	for _, r := range records {
		if strings.Contains(r.Text, "victim[victim]") && r.Trusted {
			t.Error("an entry carrying a planted marker was marked trusted")
		}
	}
}

// The same planted block behind a `#` comment, which is valid MySQL and puts the
// scanner outside a literal on the next line.
func TestAMarkerInsideALineCommentDoesNotSplitTheRecord(t *testing.T) {
	forged := "SELECT 1 -- \n# User@Host: victim[victim] @ localhost []\n# Query_time: 99.0\n;"
	data := []byte(record("attacker", "attacker_db", forged) +
		record("carol", "carol_db", "SELECT 2;"))

	records, _ := ScanRecords(data)
	for _, r := range records {
		if strings.Contains(r.Text, "victim[victim]") && r.Trusted {
			t.Error("an entry carrying a planted marker behind a comment was marked trusted")
		}
	}
}

// The layered defence: an entry that kept a planted marker inside its own body
// is dropped rather than attributed to anyone, and Parse refuses it too.
func TestAnEntryWhoseBodyStillCarriesAMarkerIsNotTrusted(t *testing.T) {
	forged := "SELECT '\n# User@Host: victim[victim] @ localhost []\n' AS x;"
	data := []byte(record("attacker", "attacker_db", forged) +
		record("carol", "carol_db", "SELECT 2;"))

	records, _ := ScanRecords(data)
	if len(records) == 0 {
		t.Fatal("no records")
	}
	found := false
	for _, r := range records {
		if !strings.Contains(r.Text, "victim[victim]") {
			continue
		}
		found = true
		if r.Trusted {
			t.Error("an entry with a nested marker in its body was trusted")
		}
		if _, ok := Parse(r, time.Time{}); ok {
			t.Error("Parse accepted an untrusted record")
		}
	}
	if !found {
		t.Error("the planted marker was not kept inside the attacker's own entry")
	}
}

// The RESIDUAL, asserted so nobody later reads the tests above as full closure.
//
// A deliberately multi-statement query terminates its own statement before the
// planted block, which puts the scanner outside a literal at a real line start.
// Nothing in the log text distinguishes that from a record mysqld wrote. This is
// why the collected data is advisory and must never drive an automated action.
func TestAMultiStatementQueryCanStillForgeARecord(t *testing.T) {
	forged := "SELECT 1;\n# User@Host: victim[victim] @ localhost []\n" +
		"# Thread_id: 99  Schema: victim_db  QC_hit: No\n" +
		"# Query_time: 90.0  Lock_time: 0.0  Rows_sent: 1  Rows_examined: 1\n" +
		"SET TIMESTAMP=1786500000;\nSELECT 2;"
	data := []byte(record("attacker", "attacker_db", forged) +
		record("carol", "carol_db", "SELECT 3;"))

	records, _ := ScanRecords(data)
	forgedSurvived := false
	for _, r := range records {
		entry, ok := Parse(r, time.Time{})
		if ok && entry.DBUser == "victim" {
			forgedSurvived = true
		}
	}
	if !forgedSurvived {
		t.Skip("the multi-statement vector is now closed; tighten this test rather than deleting it")
	}
	t.Log("known residual: a multi-statement query can attribute a record to another account")
}

// A record's own `#` header lines must not be read as SQL comments, or the
// scanner would leave comment state open and miss the next marker.
func TestTheHeaderLinesDoNotOpenAComment(t *testing.T) {
	data := []byte(record("alice", "a_db", "SELECT 1;") +
		record("bob", "b_db", "SELECT 2;") +
		record("carol", "c_db", "SELECT 3;"))

	records, _ := ScanRecords(data)
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
	if !strings.Contains(records[0].Text, "alice") || !strings.Contains(records[1].Text, "bob") {
		t.Errorf("records came out in the wrong order or wrong shape")
	}
}

// An unterminated literal stalls the scanner, and that is deliberate: ending a
// literal at a newline would let a planted marker out of the statement that
// carries it, which is the whole vector the quote tracking exists to close.
//
// A statement with an odd number of quotes cannot execute, so mysqld cannot log
// one; only a truncated write produces this. The cost is that the scan returns
// nothing and consumes nothing, so the COLLECTOR is what has to guarantee
// forward progress. TestTheCollectorSkipsPastAnEntryItCannotParse holds that
// half of the contract.
func TestAnUnterminatedLiteralStallsTheScanOnPurpose(t *testing.T) {
	data := []byte(record("alice", "a_db", "SELECT 'oops") +
		record("bob", "b_db", "SELECT 2;") +
		record("carol", "c_db", "SELECT 3;"))

	records, consumed := ScanRecords(data)

	if len(records) != 0 {
		t.Errorf("got %d records; the open literal should have swallowed the rest", len(records))
	}
	if consumed != 0 {
		t.Errorf("consumed %d, want 0: nothing after the open literal is a known boundary", consumed)
	}
}
