package geoip

import (
	"encoding/csv"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// latching yields a valid CSV prefix and then returns the same non-EOF error on
// every subsequent Read. That is what archive/zip's checksumReader does once it
// has seen a CRC mismatch, a corrupt deflate stream or a truncated member: the
// error is stored and replayed, so io.EOF never arrives.
type latching struct {
	prefix *strings.Reader
	err    error
}

func (l *latching) Read(p []byte) (int, error) {
	if l.prefix.Len() > 0 {
		return l.prefix.Read(p)
	}
	return 0, l.err
}

var errLatched = errors.New("zip: checksum error")

func brokenReader(prefix string) *csv.Reader {
	records := csv.NewReader(&latching{prefix: strings.NewReader(prefix), err: errLatched})
	records.FieldsPerRecord = -1
	return records
}

// The loops treated every non-EOF error as a malformed row and skipped it, so a
// damaged archive member spun for ever: one core pinned at 100% for the life of
// the process, the admin request never returning, and the daily updater
// goroutine wedged so the country database silently stopped refreshing.
//
// Measured before the fix with this same reader: 100000 further csv.Read calls
// returned the identical error and never io.EOF.
func TestABrokenStreamEndsTheWalkInsteadOfSpinning(t *testing.T) {
	records := brokenReader("geoname_id,country_iso_code\n1,TR\n")
	if _, err := records.Read(); err != nil { // header
		t.Fatalf("the header could not be read: %v", err)
	}

	done := make(chan struct{})
	var fatal error
	go func() {
		defer close(done)
		for range 10000 {
			_, finished, err := nextRecord(records)
			if err != nil {
				fatal = err
				return
			}
			if finished {
				return
			}
		}
		fatal = errors.New("the walk never ended")
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the walk did not end; this is the spin the fix exists to stop")
	}
	if !errors.Is(fatal, errLatched) {
		t.Errorf("the walk ended with %v, want the stream error reported", fatal)
	}
}

// A malformed ROW is still skipped: this is a third-party file, and discarding
// the whole database for one bad line means no country blocking at all until
// MaxMind's next release.
func TestAMalformedRowIsSkipped(t *testing.T) {
	records := csv.NewReader(strings.NewReader("a,b\n\"unterminated,1\n"))
	records.FieldsPerRecord = -1
	if _, err := records.Read(); err != nil {
		t.Fatalf("the header could not be read: %v", err)
	}

	row, done, fatal := nextRecord(records)
	if fatal != nil {
		t.Errorf("a malformed row was reported as a stream failure: %v", fatal)
	}
	if done {
		t.Error("a malformed row ended the walk")
	}
	if row != nil {
		t.Errorf("a malformed row was returned as data: %v", row)
	}
}

// And a clean file still walks to the end.
func TestACleanFileReachesTheEnd(t *testing.T) {
	records := csv.NewReader(strings.NewReader("a,b\n1,TR\n2,DE\n"))
	records.FieldsPerRecord = -1
	if _, err := records.Read(); err != nil {
		t.Fatalf("the header could not be read: %v", err)
	}

	rows := 0
	for range 10 {
		row, done, fatal := nextRecord(records)
		if fatal != nil {
			t.Fatalf("a clean file reported a stream failure: %v", fatal)
		}
		if done {
			break
		}
		if row != nil {
			rows++
		}
	}
	if rows != 2 {
		t.Errorf("read %d rows, want 2", rows)
	}
}

// The discriminator is csv.ParseError, not "any error that is not io.EOF".
func TestOnlyAParseErrorCountsAsARowProblem(t *testing.T) {
	if recordError(io.ErrUnexpectedEOF) {
		t.Error("a stream error was classified as a malformed row")
	}
	if !recordError(&csv.ParseError{Err: csv.ErrQuote}) {
		t.Error("a parse error was not classified as a malformed row")
	}
}
