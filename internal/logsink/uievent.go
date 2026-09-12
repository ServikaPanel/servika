package logsink

import (
	"context"
	"database/sql"
	"strings"

	"servika/internal/logx"
)

// UIRow is one row of ui_events.
//
// It lives beside RequestRow rather than in the handler package, because the
// buffered writer, the drop accounting and the batch INSERT are the same
// machinery and there is no reason to have two of them.
type UIRow struct {
	UserID    int64 // 0 when the event carried no session
	Username  string
	SessionID string
	RequestID string
	EventType string
	Path      string
	EventData string // JSON, empty for none
}

// maxEventType matches the ui_events.event_type column.
const maxEventType = 32

const uiInsertPrefix = `INSERT INTO ui_events
	(user_id, username, session_id, request_id, event_type, path, event_data)
	VALUES `

const uiInsertRow = `(?,?,?,?,?,?,?)`

// uiArgs renders one row's placeholders.
func uiArgs(row UIRow) []any {
	var userID any
	if row.UserID > 0 {
		userID = row.UserID
	}
	return []any{
		userID, clip(row.Username, maxName), clip(row.SessionID, maxName),
		clip(row.RequestID, maxName), clip(row.EventType, maxEventType),
		clip(row.Path, maxEndpoint), nullString(row.EventData),
	}
}

// writeUIEvents inserts one batch as a single multi-row statement.
func writeUIEvents(ctx context.Context, db *sql.DB, batch []UIRow) {
	if db == nil || len(batch) == 0 {
		return
	}
	var statement strings.Builder
	statement.WriteString(uiInsertPrefix)
	args := make([]any, 0, len(batch)*7)
	for i, row := range batch {
		if i > 0 {
			statement.WriteString(",")
		}
		statement.WriteString(uiInsertRow)
		args = append(args, uiArgs(row)...)
	}
	// #nosec G202 -- the statement is built from two constants and one comma; every value is a placeholder.
	if _, err := db.ExecContext(ctx, statement.String(), args...); err != nil {
		logx.Errorf("interface event write: %d row(s) lost: %v", len(batch), err)
	}
}

// uiEvents is the process-wide ui_events sink.
var uiEvents = newSink("interface event log", writeUIEvents)

// UIEvent queues one ui_events row. It never blocks.
func UIEvent(row UIRow) { uiEvents.Send(row) }

// UIEventsDropped reports how many interface rows the buffer has thrown away.
func UIEventsDropped() int64 { return uiEvents.Dropped() }

// StartUIEvents runs the ui_events writer until ctx ends.
func StartUIEvents(ctx context.Context, db *sql.DB) { uiEvents.Start(ctx, db) }
