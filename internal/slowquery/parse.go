package slowquery

import (
	"strconv"
	"strings"
	"time"
)

// Entry is one parsed slow log record.
type Entry struct {
	// At is the time MariaDB recorded. A record without its own `# Time:` line
	// carries the previous record's time, which is how MariaDB writes them: the
	// line is repeated only when the second changes.
	At time.Time
	// DBUser is the account the query ran as, taken from the marker line.
	DBUser string
	// Schema is the default database at the time, or empty.
	Schema string
	// QueryMS and LockMS are milliseconds, rounded from MariaDB's microseconds.
	QueryMS int64
	LockMS  int64
	// RowsSent and RowsExamined come straight from the header.
	RowsSent     int64
	RowsExamined int64
	// FullScan is true when log_slow_verbosity=query_plan reported one. It is
	// the cheapest signal that a query has no usable index.
	FullScan bool
	// SQL is the statement body with MariaDB's own SET TIMESTAMP prologue
	// removed. It is never stored; Normalize turns it into a shape first.
	SQL string
}

// Parse turns one record into an Entry. previous carries the time of the record
// before it so a record with no `# Time:` line inherits it.
//
// The boolean is false when the record is not usable: no account, no query time,
// or a body that failed the marker check in ScanRecords.
func Parse(record Record, previous time.Time) (Entry, bool) {
	if !record.Trusted {
		return Entry{}, false
	}
	entry := Entry{At: previous}

	lines := strings.Split(record.Text, "\n")
	bodyStart := len(lines)
	for i, line := range lines {
		if !strings.HasPrefix(line, "#") {
			bodyStart = i
			break
		}
		switch {
		case strings.HasPrefix(line, "# Time:"):
			if at, ok := parseLogTime(strings.TrimSpace(line[len("# Time:"):])); ok {
				entry.At = at
			}
		case strings.HasPrefix(line, recordMarker):
			entry.DBUser = parseUser(line[len(recordMarker):])
		default:
			fields := headerFields(line)
			if value, ok := fields["Schema"]; ok {
				entry.Schema = value
			}
			if value, ok := fields["Query_time"]; ok {
				entry.QueryMS = secondsToMS(value)
			}
			if value, ok := fields["Lock_time"]; ok {
				entry.LockMS = secondsToMS(value)
			}
			if value, ok := fields["Rows_sent"]; ok {
				entry.RowsSent = parseCount(value)
			}
			if value, ok := fields["Rows_examined"]; ok {
				entry.RowsExamined = parseCount(value)
			}
			if value, ok := fields["Full_scan"]; ok {
				entry.FullScan = strings.EqualFold(value, "Yes")
			}
		}
	}
	if entry.DBUser == "" || entry.QueryMS <= 0 {
		return Entry{}, false
	}
	entry.SQL = stripTimestampPrologue(strings.Join(lines[bodyStart:], "\n"))
	if strings.TrimSpace(entry.SQL) == "" {
		return Entry{}, false
	}
	return entry, true
}

// parseUser reads the account out of `dbuser[dbuser] @ localhost []`.
//
// The bracketed name is the account the connection AUTHENTICATED as, which is
// the one that maps to a tenant. The leading name can differ under a proxy user.
func parseUser(rest string) string {
	rest = strings.TrimSpace(rest)
	open := strings.IndexByte(rest, '[')
	if open < 0 {
		return sanitizeIdent(strings.Fields(rest + " ")[0])
	}
	close := strings.IndexByte(rest[open:], ']')
	if close < 0 {
		return sanitizeIdent(rest[:open])
	}
	name := rest[open+1 : open+close]
	if name == "" {
		name = rest[:open]
	}
	return sanitizeIdent(name)
}

// sanitizeIdent keeps only what MariaDB allows in an account or schema name the
// panel will later match against db_accounts, and bounds it to the column width.
// Everything in this file is third-party text, so nothing reaches a query
// unchecked.
func sanitizeIdent(value string) string {
	value = strings.TrimSpace(value)
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '_', r == '-', r == '.':
			b.WriteRune(r)
		default:
			return ""
		}
	}
	out := b.String()
	if len(out) > 64 {
		return ""
	}
	return out
}

// headerFields reads a `# Name: value  Name: value` line into a map. Values
// never contain a space in MariaDB's own output, which is what makes the two
// spaces between pairs unnecessary to rely on.
func headerFields(line string) map[string]string {
	fields := map[string]string{}
	parts := strings.Fields(strings.TrimPrefix(line, "#"))
	for i := 0; i+1 < len(parts); i++ {
		if !strings.HasSuffix(parts[i], ":") {
			continue
		}
		name := strings.TrimSuffix(parts[i], ":")
		if name == "" || strings.HasSuffix(parts[i+1], ":") {
			continue
		}
		fields[name] = parts[i+1]
	}
	return fields
}

// secondsToMS converts MariaDB's fractional seconds to whole milliseconds.
func secondsToMS(value string) int64 {
	seconds, err := strconv.ParseFloat(value, 64)
	if err != nil || seconds < 0 {
		return 0
	}
	ms := seconds * 1000
	// A slow log entry claiming more than a day is either a clock artefact or
	// forged text; clamping keeps it from dominating a sum.
	if ms > float64(24*60*60*1000) {
		return 24 * 60 * 60 * 1000
	}
	return int64(ms + 0.5)
}

func parseCount(value string) int64 {
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// parseLogTime reads MariaDB's two `# Time:` shapes: the classic `060214 9:30:15`
// and the ISO 8601 form newer builds write.
func parseLogTime(value string) (time.Time, bool) {
	for _, layout := range []string{
		"060102 15:04:05",
		"060102  15:04:05",
		time.RFC3339,
		"2006-01-02T15:04:05.999999Z07:00",
	} {
		if at, err := time.Parse(layout, value); err == nil {
			return at, true
		}
	}
	return time.Time{}, false
}

// stripTimestampPrologue removes the SET TIMESTAMP statements MariaDB writes
// before the query. The documented output repeats it on one line
// (`SET TIMESTAMP=1405348239;SET TIMESTAMP=1405348239;`), so this loops rather
// than dropping a single leading statement. `use <db>;` gets the same treatment.
func stripTimestampPrologue(sql string) string {
	for {
		trimmed := strings.TrimLeft(sql, " \t\r\n")
		upper := strings.ToUpper(trimmed)
		var cut int
		switch {
		case strings.HasPrefix(upper, "SET TIMESTAMP"):
			cut = len("SET TIMESTAMP")
		case strings.HasPrefix(upper, "USE "):
			cut = len("USE ")
		default:
			return trimmed
		}
		end := strings.IndexByte(trimmed[cut:], ';')
		if end < 0 {
			return trimmed
		}
		sql = trimmed[cut+end+1:]
	}
}
