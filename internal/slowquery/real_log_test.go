package slowquery

import (
	"os"
	"strings"
	"testing"
	"time"
)

// The fixture is REAL output, captured from mariadb:10.11 by running slow
// queries as a tenant account. A hand-written fixture agrees with whatever the
// author believed; this one disagrees with anything the author got wrong.
//
// It carries four shapes the hand-written one missed: a single-digit hour with
// two spaces before it, a `use ` prologue before SET timestamp, the
// `# Rows_affected:` and `# Filesort:` header lines, and mysqld's own restart
// banner sitting MID-FILE, which is what a toggled setting leaves behind.
const realLogPath = "testdata/mariadb-10.11-slow.log"

func realLog(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(realLogPath)
	if err != nil {
		t.Fatalf("read %s: %v", realLogPath, err)
	}
	return data
}

func TestTheRealLogParses(t *testing.T) {
	data := realLog(t)
	records, consumed := ScanRecords(data)

	if len(records) == 0 {
		t.Fatal("no records were found in real MariaDB output")
	}
	if consumed == 0 {
		t.Fatal("nothing was consumed, so the cursor would never advance")
	}

	var entries []Entry
	var previous time.Time
	for _, record := range records {
		entry, ok := Parse(record, previous)
		if !ok {
			t.Errorf("Parse refused a real record:\n%s", record.Text)
			continue
		}
		previous = entry.At
		entries = append(entries, entry)
	}
	if len(entries) == 0 {
		t.Fatal("no real record survived Parse")
	}

	for _, entry := range entries {
		if entry.DBUser != "u_shop_wp" {
			t.Errorf("DBUser = %q, want u_shop_wp", entry.DBUser)
		}
		if entry.Schema != "shop" {
			t.Errorf("Schema = %q, want shop", entry.Schema)
		}
		if entry.QueryMS < 2000 {
			t.Errorf("QueryMS = %d, want at least 2000", entry.QueryMS)
		}
		if entry.At.IsZero() {
			t.Errorf("the record's own # Time: line was not read: %q", entry.SQL)
		}
		if strings.Contains(strings.ToUpper(entry.SQL), "SET TIMESTAMP") {
			t.Errorf("the SET timestamp prologue survived: %q", entry.SQL)
		}
		if strings.HasPrefix(strings.ToLower(entry.SQL), "use ") {
			t.Errorf("the use prologue survived: %q", entry.SQL)
		}
	}
}

// The value a tenant compared against must not reach the stored shape. The
// fixture contains a real address inside a real query.
func TestNoRealValueSurvivesTheRealLog(t *testing.T) {
	records, _ := ScanRecords(realLog(t))
	var previous time.Time
	found := false
	for _, record := range records {
		entry, ok := Parse(record, previous)
		if !ok {
			continue
		}
		previous = entry.At
		normalized, _ := Normalize(entry.SQL)
		if strings.Contains(normalized, "gizli@ornek.com") || strings.Contains(normalized, "'a'") {
			t.Errorf("a literal survived: %q", normalized)
		}
		if strings.Contains(entry.SQL, "gizli@ornek.com") {
			found = true
		}
	}
	if !found {
		t.Error("the fixture no longer contains the literal this test exists to check")
	}
}

// mysqld appends its startup banner whenever the log is reopened, which a
// toggled setting does mid-file. The banner is not SQL and not a header, so
// without recognising it the terminator rule reads `Argument` as the last
// significant byte and every record after it is silently swallowed.
func TestTheRestartBannerDoesNotSwallowLaterRecords(t *testing.T) {
	data := realLog(t)
	if !strings.Contains(string(data), "started with:") {
		t.Skip("the fixture no longer contains a mid-file banner")
	}
	banner := strings.Index(string(data), "started with:")
	tail := string(data)[banner:]
	if !strings.Contains(tail, recordMarker) {
		t.Skip("the banner is not followed by another record in this fixture")
	}

	// The record that follows the banner is the LAST one in the captured file,
	// and ScanRecords withholds the last record on purpose because the log is
	// appended to while it is read. One more entry makes it complete, which is
	// what a live file always provides.
	data = append(data, []byte(record("later", "later_db", "SELECT 1;"))...)

	records, _ := ScanRecords(data)
	for _, r := range records {
		if strings.Count(r.Text, recordMarker) > 1 {
			t.Errorf("the banner merged records into one:\n%s", r.Text)
		}
		if strings.Contains(r.Text, "started with:") && strings.Contains(r.Text, "Thread_id: 9") {
			t.Error("the banner was kept inside the record that follows it")
		}
	}

	// The record written AFTER the banner has to come back on its own.
	afterBanner := 0
	for _, r := range records {
		if strings.Contains(r.Text, "Thread_id: 9") {
			afterBanner++
		}
	}
	if afterBanner != 1 {
		t.Errorf("the record after the banner appeared %d times, want once", afterBanner)
	}
}
