package slowquery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// readSource returns one file of this package so a rule about HOW something is
// written can be asserted. The alternative is a live MariaDB, which no unit test
// in this repository has.
func readSource(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(body)
}

// Fifty executions of one shape are ONE row with a total, which is the whole
// reason the feature exists: the shape that costs a server is the one that runs
// constantly, not the one that runs once and is slow.
func TestOneShapeRunManyTimesIsOneRow(t *testing.T) {
	var log strings.Builder
	for range 50 {
		log.WriteString(record("alice", "alice_db", "SELECT * FROM t WHERE id=1;"))
	}
	log.WriteString(record("bob", "b_db", "SELECT 2;"))

	records, _ := ScanRecords([]byte(log.String()))
	buckets := aggregate(records)

	if len(buckets) != 1 {
		t.Fatalf("got %d buckets, want 1", len(buckets))
	}
	for key, row := range buckets {
		if key.dbUser != "alice" {
			t.Errorf("dbUser = %q, want alice", key.dbUser)
		}
		if row.calls != 50 {
			t.Errorf("calls = %d, want 50", row.calls)
		}
		if row.totalMS != 50*2123 {
			t.Errorf("totalMS = %d, want %d", row.totalMS, 50*2123)
		}
		if row.maxMS != 2123 {
			t.Errorf("maxMS = %d, want 2123", row.maxMS)
		}
		if row.fullScanCalls != 50 {
			t.Errorf("fullScanCalls = %d, want 50", row.fullScanCalls)
		}
	}
}

// Two accounts running the same shape stay apart, or one tenant's cost would be
// reported against another's name.
func TestTwoAccountsRunningOneShapeStayApart(t *testing.T) {
	log := record("alice", "alice_db", "SELECT * FROM t WHERE id=1;") +
		record("bob", "bob_db", "SELECT * FROM t WHERE id=2;") +
		record("carol", "c_db", "SELECT 3;")

	buckets := aggregate(mustScan(t, log))
	if len(buckets) != 2 {
		t.Fatalf("got %d buckets, want 2", len(buckets))
	}
	users := map[string]bool{}
	for key := range buckets {
		users[key.dbUser] = true
	}
	if !users["alice"] || !users["bob"] {
		t.Errorf("accounts merged: %v", users)
	}
}

// The in-memory aggregate is bounded. If the normaliser ever meets an input it
// cannot reduce, the pass must not write a row per query.
func TestTheAggregateIsBounded(t *testing.T) {
	var log strings.Builder
	for i := range digestCap + 500 {
		// A different table name per query, so every one is genuinely its own
		// shape and the cap is the only thing that can bound the map.
		log.WriteString(record("alice", "alice_db",
			"SELECT * FROM t"+strings.Repeat("x", i%40)+itoa(i)+" WHERE id=1;"))
	}
	log.WriteString(record("bob", "b_db", "SELECT 2;"))

	buckets := aggregate(mustScan(t, log.String()))

	if len(buckets) > digestCap+1 {
		t.Errorf("got %d buckets, want at most %d", len(buckets), digestCap+1)
	}
	overflow := buckets[bucketKey{digest: otherDigest, hour: buckets2Hour(buckets), dbUser: "alice"}]
	if overflow == nil {
		t.Fatal("nothing was counted under the overflow digest")
	}
	if overflow.calls == 0 {
		t.Error("the overflow row counted no calls, so the total is now wrong")
	}
	if strings.Contains(overflow.normalized, "SELECT") {
		t.Errorf("the overflow row kept a query shape: %q", overflow.normalized)
	}
}

// Records land in the hour they happened, so a screen asking for the last day
// gets the right window rather than the collection time.
func TestRecordsLandInTheHourTheyHappened(t *testing.T) {
	early := "# Time: 260809 08:15:00\n" +
		"# User@Host: alice[alice] @ localhost []\n" +
		"# Query_time: 3.0  Lock_time: 0.0  Rows_sent: 1  Rows_examined: 1\n" +
		"SET TIMESTAMP=1;\nSELECT * FROM t WHERE id=1;\n"
	late := "# Time: 260809 09:15:00\n" +
		"# User@Host: alice[alice] @ localhost []\n" +
		"# Query_time: 3.0  Lock_time: 0.0  Rows_sent: 1  Rows_examined: 1\n" +
		"SET TIMESTAMP=1;\nSELECT * FROM t WHERE id=2;\n"

	buckets := aggregate(mustScan(t, early+late+record("bob", "b_db", "SELECT 9;")))
	if len(buckets) != 2 {
		t.Fatalf("got %d buckets, want 2: the two hours merged", len(buckets))
	}
	hours := map[int]bool{}
	for key := range buckets {
		hours[key.hour.Hour()] = true
		if key.hour != key.hour.Truncate(time.Hour) {
			t.Errorf("bucket_hour is not truncated: %v", key.hour)
		}
	}
	if !hours[8] || !hours[9] {
		t.Errorf("hours = %v, want 8 and 9", hours)
	}
}

// THE cursor rule. Committing the rows first and the cursor second re-reads and
// re-stores everything the pass covered whenever the second write fails, so the
// totals climb without any query having run.
func TestTheRowsAndTheCursorShareOneTransaction(t *testing.T) {
	source := readSource(t, "collect.go")
	store := source[strings.Index(source, "func storeBuckets"):]

	begin := strings.Index(store, "db.BeginTx(")
	rows := strings.Index(store, "INSERT INTO slow_query_stats")
	cursor := strings.Index(store, "INSERT INTO slow_query_cursor")
	commit := strings.Index(store, "tx.Commit()")
	if begin < 0 || rows < 0 || cursor < 0 || commit < 0 {
		t.Fatalf("unexpected shape of storeBuckets")
	}
	if begin >= rows || rows >= cursor || cursor >= commit {
		t.Error("the rows and the cursor are not written between one Begin and one Commit")
	}
	if strings.Count(store, "tx.Commit()") != 1 {
		t.Error("storeBuckets commits more than once")
	}
	if strings.Contains(store, "db.Exec") {
		t.Error("storeBuckets writes outside its transaction")
	}
}

// Off means off: nothing is opened, not even to measure the file.
func TestNothingIsOpenedWhileTheFeatureIsOff(t *testing.T) {
	source := readSource(t, "collect.go")
	once := source[strings.Index(source, "func CollectOnce"):]
	once = once[:strings.Index(once, "\nfunc ")]

	enabled := strings.Index(once, "collectionEnabled(")
	pass := strings.Index(once, "collectPass(")
	if enabled < 0 || pass < 0 || enabled > pass {
		t.Error("the pass runs before the setting is read")
	}
	if !strings.Contains(once, "if !enabled {") {
		t.Error("CollectOnce does not return early when the feature is off")
	}
}

// The collector must guarantee forward progress. ScanRecords deliberately
// consumes nothing when it can find no boundary, so a damaged region would
// otherwise stall collection for good.
func TestTheCollectorSkipsPastAnEntryItCannotParse(t *testing.T) {
	source := readSource(t, "collect.go")
	if !strings.Contains(source, "if consumed == 0 {") {
		t.Fatal("collectPass does not handle a pass that found no boundary")
	}
	pass := source[strings.Index(source, "if consumed == 0 {"):]
	pass = pass[:strings.Index(pass, "\n\tbuckets :=")]

	if !strings.Contains(pass, "passByteCap") {
		t.Error("the skip is not bounded by the pass cap, so a partly written record would be skipped too")
	}
	if !strings.Contains(pass, "start+int64(len(data))") {
		t.Error("the cursor does not advance past the damaged window")
	}
}

// The log is opened without following a link and without blocking on a pipe, and
// the regular-file check is made on the DESCRIPTOR rather than on a separate
// stat of the path.
func TestTheLogIsOpenedSafely(t *testing.T) {
	source := readSource(t, "collect.go")
	read := source[strings.Index(source, "func readFrom"):]

	for _, want := range []string{"syscall.O_NOFOLLOW", "syscall.O_NONBLOCK", "file.Stat()", "IsRegular()"} {
		if !strings.Contains(read, want) {
			t.Errorf("readFrom does not use %s", want)
		}
	}
	if strings.Contains(read, "os.Stat(path)") {
		t.Error("readFrom checks the path rather than the descriptor")
	}
}

// The same open, exercised rather than read: a symlink is refused outright.
func TestASymlinkedLogIsRefused(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.log")
	if err := os.WriteFile(real, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.log")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if _, err := readFrom(link, 0, 1024); err == nil {
		t.Error("readFrom followed a symlink")
	}
	if _, err := readFrom(real, 0, 1024); err != nil {
		t.Errorf("readFrom refused the real file: %v", err)
	}
}

// Retention is applied in the same pass, so the table never needs its own
// maintenance and never grows without bound.
func TestOldRowsArePrunedInTheSamePass(t *testing.T) {
	source := readSource(t, "collect.go")
	if !strings.Contains(source, "DELETE FROM slow_query_stats WHERE bucket_hour < NOW() - INTERVAL ? DAY") {
		t.Error("the pass does not prune old rows")
	}
	if retentionDays <= 0 || retentionDays > 90 {
		t.Errorf("retentionDays = %d, which is not a sane window", retentionDays)
	}
}

// The pass runs under its own deadline, shorter than the interval, so a slow
// pass cannot overlap the next one.
func TestThePassHasItsOwnDeadline(t *testing.T) {
	source := readSource(t, "collect.go")
	if !strings.Contains(source, "context.WithTimeout(context.Background()") {
		t.Error("the pass does not set its own deadline")
	}
	if !strings.Contains(source, "collectInterval-") {
		t.Error("the deadline is not derived from the interval, so it can exceed it")
	}
}

func mustScan(t *testing.T, log string) []Record {
	t.Helper()
	records, _ := ScanRecords([]byte(log))
	if len(records) == 0 {
		t.Fatal("no records")
	}
	return records
}

// buckets2Hour returns the hour every bucket in the map shares, which the tests
// above rely on because all their records carry one timestamp.
func buckets2Hour(buckets map[bucketKey]*bucket) time.Time {
	for key := range buckets {
		return key.hour
	}
	return time.Time{}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
