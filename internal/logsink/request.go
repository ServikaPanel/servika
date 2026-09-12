package logsink

import (
	"context"
	"database/sql"
	"strings"

	"servika/internal/logx"
)

// RequestRow is one row of request_logs.
//
// The nullable columns are held as their zero value and converted at INSERT
// time, so a caller assembles a plain struct and does not deal with sql.Null*.
type RequestRow struct {
	RequestID      string
	UserID         int64 // 0 when the request carried no session
	Username       string
	IP             string
	UserAgent      string
	Method         string
	Endpoint       string
	Module         string
	Action         string
	QueryParams    string // JSON, empty for none
	RequestBody    string // JSON, empty for none
	ResponseStatus int
	ResponseMS     int64
	ErrorMessage   string
}

// Column limits, matching migrations/0140_central_logging.sql. A value longer
// than its column makes MariaDB refuse the whole batch under a strict sql_mode,
// so one oversized user agent would drop 255 unrelated rows.
const (
	maxUserAgent    = 255
	maxEndpoint     = 255
	maxErrorMessage = 512
	maxName         = 64
)

// clip shortens a value to what its column accepts, on a rune boundary so a
// multi-byte character is never cut in half.
func clip(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	runes := []rune(value)
	for len(string(runes)) > limit {
		runes = runes[:len(runes)-1]
	}
	return string(runes)
}

const requestInsertPrefix = `INSERT INTO request_logs
	(request_id, user_id, username, ip, user_agent, method, endpoint, module, action,
	 query_params, request_body, response_status, response_ms, error_message)
	VALUES `

const requestInsertRow = `(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

// requestArgs renders one row's placeholders.
func requestArgs(row RequestRow) []any {
	var userID any
	if row.UserID > 0 {
		userID = row.UserID
	}
	return []any{
		clip(row.RequestID, maxName), userID, clip(row.Username, maxName), clip(row.IP, 45),
		clip(row.UserAgent, maxUserAgent), clip(row.Method, 8), clip(row.Endpoint, maxEndpoint),
		clip(row.Module, maxName), clip(row.Action, maxName),
		nullString(row.QueryParams), nullString(row.RequestBody),
		row.ResponseStatus, row.ResponseMS, clip(row.ErrorMessage, maxErrorMessage),
	}
}

// nullString turns an empty string into a SQL NULL, because a JSON column
// refuses "" but accepts NULL.
func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// writeRequests inserts one batch as a single multi-row statement.
func writeRequests(ctx context.Context, db *sql.DB, batch []RequestRow) {
	if db == nil || len(batch) == 0 {
		return
	}
	var statement strings.Builder
	statement.WriteString(requestInsertPrefix)
	args := make([]any, 0, len(batch)*14)
	for i, row := range batch {
		if i > 0 {
			statement.WriteString(",")
		}
		statement.WriteString(requestInsertRow)
		args = append(args, requestArgs(row)...)
	}
	// #nosec G202 -- the statement is built from two constants and one comma; every value is a placeholder.
	if _, err := db.ExecContext(ctx, statement.String(), args...); err != nil {
		logx.Errorf("request log write: %d row(s) lost: %v", len(batch), err)
	}
}

// requests is the process-wide request_logs sink.
var requests = newSink("request log", writeRequests)

// Request queues one request_logs row. It never blocks.
func Request(row RequestRow) { requests.Send(row) }

// RequestsDropped reports how many request rows the buffer has thrown away.
func RequestsDropped() int64 { return requests.Dropped() }

// StartRequests runs the request_logs writer until ctx ends.
func StartRequests(ctx context.Context, db *sql.DB) { requests.Start(ctx, db) }
