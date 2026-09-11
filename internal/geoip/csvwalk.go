package geoip

import (
	"encoding/csv"
	"errors"
	"io"
)

// encoding/csv reports a MALFORMED RECORD and a BROKEN STREAM through the same
// error channel, and both loops in the parser treated every non-EOF error as
// the first kind and skipped the row.
//
// A malformed row genuinely must be skipped: this is a third-party file and
// discarding the whole database for one bad line means no country blocking at
// all until MaxMind's next release. A broken stream is the opposite: csv.Read
// returns the SAME error on every subsequent call, io.EOF never arrives, and
// the loop spins for ever. archive/zip's checksumReader latches its error
// exactly that way after a CRC mismatch, a corrupt deflate stream or a
// truncated member, so a damaged download pinned a core at 100% for the life of
// the process, with the admin request never returning and the daily updater
// goroutine wedged so the database silently stopped refreshing.
//
// Measured with a reader that yields a valid CSV prefix and then returns the
// same non-EOF error: 100000 further csv.Read calls returned that identical
// error and never io.EOF.
//
// csv.ParseError is what the package wraps a record-level problem in, so it is
// the discriminator: anything else came from the reader underneath.
func recordError(err error) (skip bool) {
	var parseErr *csv.ParseError
	return errors.As(err, &parseErr)
}

// nextRecord reads one row and classifies the outcome.
//
// done is true at the end of the data or on a stream error; fatal carries the
// stream error so the caller can report the member as failed rather than
// returning a half-built result as if it were complete.
func nextRecord(records *csv.Reader) (row []string, done bool, fatal error) {
	row, err := records.Read()
	switch {
	case err == nil:
		return row, false, nil
	case errors.Is(err, io.EOF):
		return nil, true, nil
	case recordError(err):
		return nil, false, nil // A bad line: skip it and keep going.
	default:
		return nil, true, err
	}
}
