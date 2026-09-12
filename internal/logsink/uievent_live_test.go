package logsink

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// The multi-row statement is assembled by hand, so a real server is the only
// thing that proves it parses and that every value lands in its own column.
func TestABatchOfInterfaceRowsIsWritten(t *testing.T) {
	handle := liveDB(t)
	const sessionID = "logsink-ui-test"
	t.Cleanup(func() {
		_, _ = handle.Exec(`DELETE FROM ui_events WHERE session_id=?`, sessionID)
	})

	writeUIEvents(context.Background(), handle, []UIRow{
		{
			UserID: 1, Username: "root", SessionID: sessionID, RequestID: "req-1",
			EventType: "page_view", Path: "/domains", EventData: `{"from":"/"}`,
		},
		{
			SessionID: sessionID, EventType: "client_error", Path: "/domains",
		},
	})

	read := readUIEvents(t, handle, sessionID)
	if len(read) != 2 {
		t.Fatalf("%d row(s) were written, expected 2", len(read))
	}
	if read[0].UserID != 1 || read[0].EventType != "page_view" {
		t.Errorf("the first row came back as %+v", read[0])
	}
	if !strings.Contains(read[0].EventData, `"from"`) {
		t.Errorf("the payload column lost its content: %q", read[0].EventData)
	}
	// An event with no session stores NULL, not 0: a JSON column refuses "" and
	// a user_id of 0 names no account.
	if read[1].UserID != 0 || read[1].EventData != "" {
		t.Errorf("the anonymous row came back as %+v", read[1])
	}
}

// readUIEvents reads back the rows one test wrote, by the session it named.
func readUIEvents(t *testing.T, handle *sql.DB, sessionID string) []UIRow {
	t.Helper()
	cursor, err := handle.Query(
		`SELECT COALESCE(user_id,0), username, request_id, event_type, path,
		        COALESCE(event_data,'')
		   FROM ui_events WHERE session_id=? ORDER BY id`, sessionID)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	defer func() { _ = cursor.Close() }()

	var read []UIRow
	for cursor.Next() {
		var row UIRow
		if err := cursor.Scan(&row.UserID, &row.Username, &row.RequestID,
			&row.EventType, &row.Path, &row.EventData); err != nil {
			t.Fatalf("scan: %v", err)
		}
		read = append(read, row)
	}
	if err := cursor.Err(); err != nil {
		t.Fatalf("read: %v", err)
	}
	return read
}
