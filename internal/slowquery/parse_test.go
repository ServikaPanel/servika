package slowquery

import (
	"strings"
	"testing"
	"time"
)

func firstEntry(t *testing.T, log string) Entry {
	t.Helper()
	records, _ := ScanRecords([]byte(log))
	if len(records) == 0 {
		t.Fatal("no complete records")
	}
	entry, ok := Parse(records[0], time.Time{})
	if !ok {
		t.Fatalf("Parse refused the record:\n%s", records[0].Text)
	}
	return entry
}

// Every header MariaDB writes has to survive, because each one is a column the
// screen ranks or explains by.
func TestTheHeaderFieldsAreRead(t *testing.T) {
	entry := firstEntry(t, record("alice", "alice_db", "SELECT 1;")+
		record("bob", "b_db", "SELECT 2;"))

	if entry.DBUser != "alice" {
		t.Errorf("DBUser = %q, want alice", entry.DBUser)
	}
	if entry.Schema != "alice_db" {
		t.Errorf("Schema = %q, want alice_db", entry.Schema)
	}
	if entry.QueryMS != 2123 {
		t.Errorf("QueryMS = %d, want 2123", entry.QueryMS)
	}
	if entry.LockMS != 0 {
		t.Errorf("LockMS = %d, want 0", entry.LockMS)
	}
	if entry.RowsSent != 1 || entry.RowsExamined != 900000 {
		t.Errorf("rows = %d/%d, want 1/900000", entry.RowsSent, entry.RowsExamined)
	}
	if !entry.FullScan {
		t.Error("FullScan is false, but the record says Full_scan: Yes")
	}
	if entry.At.IsZero() {
		t.Error("the record's own # Time: line was not read")
	}
}

// The account comes from the BRACKETED name, which is the one that
// authenticated and therefore the one that maps to db_accounts.
func TestTheAuthenticatedAccountIsTaken(t *testing.T) {
	log := "# Time: 260809 10:23:45\n" +
		"# User@Host: proxied[real_user] @ localhost []\n" +
		"# Query_time: 3.0  Lock_time: 0.0  Rows_sent: 1  Rows_examined: 1\n" +
		"SET TIMESTAMP=1;\nSELECT 1;\n" +
		record("bob", "b_db", "SELECT 2;")

	if got := firstEntry(t, log).DBUser; got != "real_user" {
		t.Errorf("DBUser = %q, want real_user", got)
	}
}

// Everything in the log is third-party text, so an account name that could not
// be a MariaDB account is refused rather than carried into a query.
func TestAnImpossibleAccountNameIsRefused(t *testing.T) {
	for _, name := range []string{"a'b", "a b", "a;b", strings.Repeat("x", 65), "a`b"} {
		if got := parseUser(name + "[" + name + "] @ localhost []"); got != "" {
			t.Errorf("parseUser(%q) = %q, want empty", name, got)
		}
	}
	if got := parseUser("u_shop-1.x[u_shop-1.x] @ localhost []"); got != "u_shop-1.x" {
		t.Errorf("a legitimate name was refused: %q", got)
	}
}

// MariaDB repeats the SET TIMESTAMP prologue on one line, which the
// documentation's own example shows. Leaving it in would make every shape
// unique, because the epoch differs on every execution.
func TestTheTimestampPrologueIsRemoved(t *testing.T) {
	body := "SET TIMESTAMP=1405348239;SET TIMESTAMP=1405348239;\nSELECT * FROM t WHERE id=5;"
	entry := firstEntry(t, record("alice", "a_db", body)+record("bob", "b_db", "SELECT 2;"))

	if strings.Contains(strings.ToUpper(entry.SQL), "SET TIMESTAMP") {
		t.Errorf("the prologue survived: %q", entry.SQL)
	}
	if !strings.HasPrefix(entry.SQL, "SELECT") {
		t.Errorf("SQL = %q, want it to start at the statement", entry.SQL)
	}

	normalized, first := Normalize(entry.SQL)
	if strings.Contains(normalized, "1405348239") {
		t.Errorf("the epoch reached the stored shape: %q", normalized)
	}
	// The same query a second later must land on the same shape, or every
	// execution would be its own row and the totals would never add up.
	later := strings.ReplaceAll(body, "1405348239", "1405348240")
	other := firstEntry(t, record("alice", "a_db", later)+record("bob", "b_db", "SELECT 2;"))
	_, second := Normalize(other.SQL)
	if first != second {
		t.Errorf("two executions of one query produced different digests: %s vs %s", first, second)
	}
}

// A record with no `# Time:` line of its own inherits the previous one, which is
// how MariaDB writes them: the line appears only when the second changes.
func TestATimelessRecordInheritsThePreviousTime(t *testing.T) {
	previous := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	log := "# User@Host: alice[alice] @ localhost []\n" +
		"# Query_time: 3.0  Lock_time: 0.0  Rows_sent: 1  Rows_examined: 1\n" +
		"SET TIMESTAMP=1;\nSELECT 1;\n" +
		record("bob", "b_db", "SELECT 2;")

	records, _ := ScanRecords([]byte(log))
	entry, ok := Parse(records[0], previous)
	if !ok {
		t.Fatal("Parse refused a record with no # Time: line")
	}
	if !entry.At.Equal(previous) {
		t.Errorf("At = %v, want the inherited %v", entry.At, previous)
	}
}

// A record with no account or no duration is not usable, and fails closed rather
// than becoming an unattributed row nobody can act on.
func TestAnIncompleteRecordIsRefused(t *testing.T) {
	noUser := "# User@Host:  @ localhost []\n# Query_time: 3.0\nSET TIMESTAMP=1;\nSELECT 1;\n"
	noTime := "# User@Host: alice[alice] @ localhost []\n# Rows_sent: 1\nSET TIMESTAMP=1;\nSELECT 1;\n"
	noBody := "# User@Host: alice[alice] @ localhost []\n# Query_time: 3.0\nSET TIMESTAMP=1;\n"

	for name, text := range map[string]string{"no user": noUser, "no time": noTime, "no body": noBody} {
		if _, ok := Parse(Record{Text: text, Trusted: true}, time.Time{}); ok {
			t.Errorf("%s: Parse accepted an unusable record", name)
		}
	}
}

// A duration far outside anything real is clamped rather than allowed to
// dominate a sum, because the value is third-party text.
func TestAnAbsurdDurationIsClamped(t *testing.T) {
	if got := secondsToMS("999999999"); got != 24*60*60*1000 {
		t.Errorf("secondsToMS = %d, want the one-day clamp", got)
	}
	if got := secondsToMS("-5"); got != 0 {
		t.Errorf("secondsToMS(-5) = %d, want 0", got)
	}
	if got := secondsToMS("2.123456"); got != 2123 {
		t.Errorf("secondsToMS = %d, want 2123", got)
	}
}
