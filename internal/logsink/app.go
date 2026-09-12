package logsink

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// AppRow is one row of app_logs.
type AppRow struct {
	Level      string // INFO, WARN or ERROR
	LoggerName string
	Message    string
	Context    string // JSON, empty for none
	RequestID  string
}

const maxMessage = 8 << 10

const appInsertPrefix = `INSERT INTO app_logs
	(level, logger_name, message, context, request_id) VALUES `

const appInsertRow = `(?,?,?,?,?)`

// writeApp inserts one batch of application log lines.
//
// A failure here does NOT go through logx: logx feeds this sink, so reporting
// the failure that way would queue another row, fail again and keep going. It
// goes straight to stderr, which journald already collects, at most once per
// complainInterval.
func writeApp(ctx context.Context, db *sql.DB, batch []AppRow) {
	if db == nil || len(batch) == 0 {
		return
	}
	var statement strings.Builder
	statement.WriteString(appInsertPrefix)
	args := make([]any, 0, len(batch)*5)
	for i, row := range batch {
		if i > 0 {
			statement.WriteString(",")
		}
		statement.WriteString(appInsertRow)
		args = append(args,
			row.Level, clip(row.LoggerName, 128), clip(row.Message, maxMessage),
			nullString(row.Context), clip(row.RequestID, maxName))
	}
	// #nosec G202 -- the statement is built from two constants and one comma; every value is a placeholder.
	if _, err := db.ExecContext(ctx, statement.String(), args...); err != nil {
		complainToStderr(fmt.Sprintf("app log write: %d row(s) lost: %v", len(batch), err))
	}
}

var (
	stderrMu   sync.Mutex
	stderrLast time.Time
)

// complainToStderr reports a failure of the application-log sink itself.
//
// It bypasses logx on purpose. logx is what fills this sink, so a failure
// reported through it would produce another row, another failure and an endless
// loop that ends in a full disk rather than in a message anybody reads.
func complainToStderr(message string) {
	stderrMu.Lock()
	defer stderrMu.Unlock()
	if now().Sub(stderrLast) < complainInterval {
		return
	}
	stderrLast = now()
	fmt.Fprintf(os.Stderr, "<3>%s\n", message)
}

// app is the process-wide app_logs sink.
var app = newSink("app log", writeApp)

// App queues one app_logs row. It never blocks.
func App(row AppRow) { app.Send(row) }

// AppDropped reports how many application log rows the buffer has thrown away.
func AppDropped() int64 { return app.Dropped() }

// StartApp runs the app_logs writer until ctx ends.
func StartApp(ctx context.Context, db *sql.DB) { app.Start(ctx, db) }
