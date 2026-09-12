// Package logview reads the panel's own log tables.
//
// The rows are written by internal/logsink and were only reachable with a MySQL
// client until now, which meant an operator asking "what did this request do"
// had to leave the panel to answer it. These endpoints are ADMIN ONLY: the rows
// cover every operator's requests and the panel's own failures, which is not a
// reseller's or a customer's data.
package logview

import (
	"database/sql"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Handlers reads the log tables.
type Handlers struct {
	DB *sql.DB
}

// The row cap. The screens answer "what happened recently", so a limit is the
// right control rather than a date range, and the cap keeps one careless
// request from reading a month of traffic into memory.
const (
	defaultLimit = 200
	maxLimit     = 1000
)

// parseLimit turns ?limit into the effective cap. A missing, malformed or
// non-positive value takes the default; anything above the cap clamps to it,
// because a limit is a display choice and not a policy an operator can get
// wrong.
func parseLimit(raw string) int {
	limit := defaultLimit
	if n, err := strconv.Atoi(raw); err == nil && n > 0 {
		limit = n
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	return limit
}

// filter collects the WHERE predicates and their bound arguments.
//
// Every value is bound as a placeholder. No caller's string ever reaches the
// statement text, which is what makes these filters safe to accept from a query
// string.
type filter struct {
	cond []string
	arg  []any
}

// eq adds `column = ?` unless the value is empty.
func (f *filter) eq(column, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	f.cond = append(f.cond, column+" = ?")
	f.arg = append(f.arg, value)
}

// oneOf adds `column = ?` only when the value is in the allowed set.
//
// An unknown value is DROPPED rather than refused: the column is an ENUM, so a
// value outside the set matches nothing, and answering an empty list to a typo
// reads as "there are none" when there are.
func (f *filter) oneOf(column, value string, allowed ...string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	if !slices.Contains(allowed, value) {
		return false
	}
	f.cond = append(f.cond, column+" = ?")
	f.arg = append(f.arg, value)
	return true
}

// since adds a lower bound on ts. An empty value adds nothing; an unparsable
// one is reported, so a mistyped date is not silently ignored.
func (f *filter) since(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return true
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		if parsed, err := time.Parse(layout, raw); err == nil {
			f.cond = append(f.cond, "ts >= ?")
			f.arg = append(f.arg, parsed.UTC())
			return true
		}
	}
	return false
}

// where renders the collected predicates.
func (f *filter) where() string {
	if len(f.cond) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(f.cond, " AND ")
}

// query assembles the full statement for one table and its arguments.
func (f *filter) query(columns, table string, limit int) (string, []any) {
	statement := "SELECT " + columns + " FROM " + table + f.where() + " ORDER BY id DESC LIMIT ?"
	return statement, append(append([]any{}, f.arg...), limit)
}

// badFilter reports a filter value the caller has to correct.
const badFilter = "invalid filter"

// numeric adds `column = ?` for a value that must be a number.
func (f *filter) numeric(column, value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return false
	}
	f.cond = append(f.cond, column+" = ?")
	f.arg = append(f.arg, parsed)
	return true
}
