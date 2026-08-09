// Package slowquery turns MariaDB's slow query log into per-tenant, per-shape
// statistics.
//
// The panel already kills a query that outruns its plan limit, but it samples
// the process list every five seconds, so it only ever sees a query that lasts
// longer than the poll interval. What actually costs a shared server is usually
// the opposite shape: a short query running constantly. The slow log is the only
// place that shape is visible.
//
// Everything in this file works on bytes and produces records. Nothing here
// touches the database or the filesystem, so the rules below are unit-testable
// on their own.
package slowquery

import (
	"strings"
)

// recordMarker starts a slow log entry. MariaDB writes an optional `# Time:`
// line first and repeats it only when the second changes, so this is the only
// line that reliably begins every record.
const recordMarker = "# User@Host:"

// Record is one entry's raw text: the `#` header lines followed by the SQL.
type Record struct {
	// Text is the whole entry, marker line included.
	Text string
	// Trusted is false when the entry's own body still contains a line that
	// looks like a record marker. See ScanRecords for why that matters.
	Trusted bool
}

// ScanRecords splits a slow log fragment into records.
//
// consumed is the number of bytes that are safe to advance a cursor by, which is
// NOT len(data): the log is being appended to while it is read, so the last
// entry in a fragment is usually incomplete. A record only ends at the next
// marker, so the final marker's offset is the furthest point that can be
// committed. Consuming past it would drop that entry for good.
func ScanRecords(data []byte) (records []Record, consumed int) {
	text := string(data)
	starts := markerOffsets(text)
	if len(starts) == 0 {
		// No complete record begins here. Nothing may be consumed: a marker may
		// still arrive in the bytes that follow.
		return nil, 0
	}
	// Every marker except the last one begins an entry whose end is known.
	for i := 0; i+1 < len(starts); i++ {
		entry := text[starts[i]:starts[i+1]]
		records = append(records, Record{Text: entry, Trusted: bodyIsClean(entry)})
	}
	return records, starts[len(starts)-1]
}

// markerOffsets returns the byte offset at which every record begins.
//
// Two rules decide a boundary, and each closes a way a tenant could otherwise
// forge a record attributed to a neighbour. A tenant writes the SQL that MariaDB
// logs, so a query can carry any text at all.
//
//  1. The scan is quote and comment aware, so a marker planted inside a string
//     literal stays inside the statement that produced it, where normalisation
//     reduces the whole literal to `?`.
//  2. A marker only begins a record when the statement before it has been
//     TERMINATED. MariaDB always ends a logged body with `;`, while a planted
//     line inside an unterminated statement is a `#` comment as far as MySQL is
//     concerned, and must be read as one here too.
//
// A deliberately multi-statement query can still satisfy both, which is why
// bodyIsClean exists and why the result is advisory. See the package rules in
// CLAUDE.md.
func markerOffsets(text string) []int {
	var offsets []int
	state := newSQLState()
	atLineStart := true
	// The last non-space byte of plain SQL seen since the current record began.
	// Zero means "nothing yet", which only holds before the first record.
	var lastSignificant byte
	seenRecord := false

	for i := 0; i < len(text); i++ {
		// mysqld appends its own banner every time it opens the log, which
		// happens on a restart and on any toggle of slow_query_log. The banner
		// is neither SQL nor a header, so without this its last word would be
		// read as the previous statement's last significant byte and every
		// record after it would be swallowed. Measured against real 10.11
		// output; testdata/mariadb-10.11-slow.log carries one mid-file.
		if atLineStart && state.outsideCode() && isBannerLine(text[i:]) {
			i = skipBanner(text, i)
			atLineStart = true
			state = newSQLState()
			lastSignificant = ';'
			continue
		}
		terminated := lastSignificant == ';' || !seenRecord
		if atLineStart && state.outsideCode() && terminated &&
			strings.HasPrefix(text[i:], recordMarker) {
			offsets = append(offsets, recordStart(text, i))
			seenRecord = true
			lastSignificant = 0
			// The marker line is MariaDB's own text, not SQL. Skip it whole so
			// its `#` cannot open a comment and its content cannot set state.
			end := strings.IndexByte(text[i:], '\n')
			if end < 0 {
				return offsets
			}
			i += end
			atLineStart = true
			state = newSQLState()
			continue
		}
		atLineStart = text[i] == '\n'
		// The byte only counts when it is plain SQL both before AND after the
		// step. Checking only "before" would let the `#` that OPENS MariaDB's own
		// `# Time:` line count as the last significant byte, which then makes the
		// marker under it look unterminated and swallows every later record.
		before := state.outsideCode()
		state.step(text, i)
		if before && state.outsideCode() {
			switch c := text[i]; c {
			case ' ', '\t', '\r', '\n':
			default:
				lastSignificant = c
			}
		}
	}
	return offsets
}

// isBannerLine reports whether the text at a line start is the first line of
// mysqld's log banner, which reads
//
//	mariadbd, Version: 10.11.16-MariaDB (…). started with:
//
// A tenant could write the same text through the comment vector already
// documented on markerOffsets, which gains them nothing they did not already
// have there.
func isBannerLine(rest string) bool {
	line := rest
	if end := strings.IndexByte(line, '\n'); end >= 0 {
		line = line[:end]
	}
	return strings.Contains(line, ", Version: ") &&
		strings.HasSuffix(strings.TrimRight(line, "\r"), "started with:")
}

// skipBanner returns the index of the last byte of the banner block, so the loop
// resumes at the line after it. The block ends at the first line that begins a
// record header, which is what mysqld writes next.
func skipBanner(text string, i int) int {
	for i < len(text) {
		end := strings.IndexByte(text[i:], '\n')
		if end < 0 {
			return len(text) - 1
		}
		next := i + end + 1
		if next >= len(text) || text[next] == '#' {
			return i + end
		}
		i = next
	}
	return len(text) - 1
}

// recordStart backs a marker offset up over the `# Time:` line that belongs to
// the same record. MariaDB writes that line only when the second changes, so it
// is optional, but when it is there it is part of the record that FOLLOWS it.
// Starting at the marker instead would leave it at the tail of the previous
// record's body and lose the record's own timestamp.
func recordStart(text string, marker int) int {
	if marker == 0 {
		return 0
	}
	previousEnd := marker - 1 // the '\n' before the marker
	lineStart := strings.LastIndexByte(text[:previousEnd], '\n') + 1
	if strings.HasPrefix(text[lineStart:], "# Time:") {
		return lineStart
	}
	return marker
}

// bodyIsClean reports whether an entry's SQL body is free of anything that looks
// like a record marker at the start of a line.
//
// A multi-statement query can legitimately terminate a statement before such a
// line, which puts the scanner back outside a literal and makes the forged block
// indistinguishable from a real record. Rather than attribute either half, the
// whole entry is dropped: losing one row costs nothing, and a real query
// containing this text at the start of a line is not a shape anyone writes.
func bodyIsClean(entry string) bool {
	body := entry
	// Skip the marker line itself and the `#` header lines under it.
	for {
		end := strings.IndexByte(body, '\n')
		if end < 0 {
			return true
		}
		next := body[end+1:]
		if !strings.HasPrefix(next, "#") {
			body = next
			break
		}
		body = next
	}
	return !strings.Contains("\n"+body, "\n"+recordMarker)
}

// sqlState tracks whether a byte offset sits inside a string literal, a quoted
// identifier or a comment. One implementation serves both the record scanner and
// the normaliser, so the two can never disagree about where a literal ends.
type sqlState struct {
	quote   byte // 0, '\'', '"' or '`'
	escaped bool
	line    bool // -- or # comment, runs to end of line
	block   bool // /* */ comment
	skip    int  // bytes already accounted for by a multi-byte token
}

func newSQLState() *sqlState { return &sqlState{} }

// outsideCode reports whether the current offset is plain SQL rather than a
// literal, a quoted identifier or a comment.
func (s *sqlState) outsideCode() bool {
	return s.quote == 0 && !s.line && !s.block
}

// step advances the state by the byte at index i of text.
func (s *sqlState) step(text string, i int) {
	if s.skip > 0 {
		s.skip--
		return
	}
	c := text[i]

	if s.line {
		if c == '\n' {
			s.line = false
		}
		return
	}
	if s.block {
		if c == '*' && i+1 < len(text) && text[i+1] == '/' {
			s.block = false
			s.skip = 1
		}
		return
	}
	if s.quote != 0 {
		switch {
		case s.escaped:
			s.escaped = false
		case c == '\\':
			// MariaDB honours backslash escapes inside a string literal unless
			// NO_BACKSLASH_ESCAPES is set. Treating one as an escape when the
			// server would not only ever ends a literal LATER than the server
			// does, which keeps a planted marker inside the statement.
			s.escaped = true
		case c == s.quote:
			if i+1 < len(text) && text[i+1] == s.quote {
				// Doubled quote: an escaped quote, not the end.
				s.skip = 1
				return
			}
			s.quote = 0
		}
		return
	}

	switch {
	case c == '\'' || c == '"' || c == '`':
		s.quote = c
	case c == '#':
		s.line = true
	case c == '-' && i+1 < len(text) && text[i+1] == '-':
		// MariaDB requires whitespace or end of input after `--`.
		if i+2 >= len(text) || text[i+2] == ' ' || text[i+2] == '\t' ||
			text[i+2] == '\n' || text[i+2] == '\r' {
			s.line = true
			s.skip = 1
		}
	case c == '/' && i+1 < len(text) && text[i+1] == '*':
		s.block = true
		s.skip = 1
	}
}
