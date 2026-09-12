package logsink

import (
	"context"
	"database/sql"
	"runtime"
	"strings"

	"servika/internal/logx"
)

// The syslog prefixes logx puts on a line, and the level each one names.
var levelOfPrefix = map[string]string{
	"<3>": "ERROR",
	"<4>": "WARN",
	"<6>": "INFO",
}

// requestPrefix is what httpx.LogR and httpx.WarnR put at the front of a line
// written while serving a request.
const requestPrefix = "reqid="

// splitRequestID takes the correlation id back out of the message.
//
// httpx.LogR writes it into the text rather than passing it as a field, because
// journald has no field to put it in. Reading it back here is what lets an
// app_logs line join the request_logs row for the same call, and it costs the
// panel nothing: no caller changes and no id is required.
func splitRequestID(message string) (requestID, rest string) {
	if !strings.HasPrefix(message, requestPrefix) {
		return "", message
	}
	after := message[len(requestPrefix):]
	space := strings.IndexByte(after, ' ')
	if space <= 0 {
		return "", message
	}
	return after[:space], after[space+1:]
}

// loggerName reports the package that logged the line.
//
// The name is taken from the call stack rather than passed in, so no caller
// changes and no caller can get it wrong. Frames inside logx and this package
// are skipped: they are the plumbing, not the origin.
func loggerName() string {
	programCounters := make([]uintptr, 12)
	depth := runtime.Callers(3, programCounters)
	frames := runtime.CallersFrames(programCounters[:depth])
	for {
		frame, more := frames.Next()
		if name := packageOf(frame.Function); name != "" {
			return name
		}
		if !more {
			return ""
		}
	}
}

// packageOf returns the import path of a frame's function, or "" when the frame
// belongs to the logging plumbing itself.
func packageOf(function string) string {
	slash := strings.LastIndexByte(function, '/')
	dot := strings.IndexByte(function[slash+1:], '.')
	if dot < 0 {
		return ""
	}
	path := function[:slash+1+dot]
	if path == "servika/internal/logx" || path == "servika/internal/logsink" {
		return ""
	}
	return path
}

// StartApplicationLog sends every line logx writes to app_logs as well.
//
// journald keeps its copy: logx writes there first and unconditionally, so a
// line survives the database being down, which is exactly the incident the
// interesting lines describe.
func StartApplicationLog(ctx context.Context, db *sql.DB) {
	StartApp(ctx, db)
	logx.SetSink(func(prefix, message string) {
		level, known := levelOfPrefix[prefix]
		if !known {
			level = "INFO"
		}
		requestID, text := splitRequestID(message)
		App(AppRow{
			Level:      level,
			LoggerName: loggerName(),
			Message:    text,
			RequestID:  requestID,
		})
	})
}
