package logview

import (
	"database/sql"
	"os"
	"testing"

	"servika/internal/db"
)

// liveDB opens the shared test database, or skips.
func liveDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("SERVIKA_TEST_DSN")
	if dsn == "" {
		t.Skip("SERVIKA_TEST_DSN is unset, so there is no server to ask")
	}
	handle, err := db.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = handle.Close() })
	return handle
}

// The statements are assembled by hand from a projection, a WHERE and a LIMIT,
// so a real server is the only thing that proves they parse and that the
// projection matches what the handler scans.
func TestTheRequestQueryRunsAndScans(t *testing.T) {
	handle := liveDB(t)
	const reqID = "logview-live-test"
	t.Cleanup(func() {
		_, _ = handle.Exec(`DELETE FROM request_logs WHERE request_id=?`, reqID)
	})
	if _, err := handle.Exec(
		`INSERT INTO request_logs (request_id, username, ip, user_agent, method, endpoint,
			module, action, request_body, response_status, response_ms)
		 VALUES (?, 'root', '203.0.113.9', 'curl/8.0', 'POST', '/api/v1/auth/login',
			'auth', 'login', '{"password":"[REDACTED]"}', 401, 12)`, reqID); err != nil {
		t.Fatalf("insert: %v", err)
	}

	statement, arg, ok := buildRequestQuery(map[string]string{
		"request_id": reqID, "method": "POST", "status": "401", "since": "2000-01-01",
	}, 10)
	if !ok {
		t.Fatal("the query was refused")
	}
	matched := readRequests(t, handle, statement, arg)
	if len(matched) != 1 {
		t.Fatalf("%d row(s) matched every filter, expected 1", len(matched))
	}
	e := matched[0]
	if e.Status != 401 || e.Method != "POST" || e.Endpoint != "/api/v1/auth/login" {
		t.Errorf("the row came back as %+v", e)
	}
	if e.QueryParams != "" {
		t.Errorf("a NULL JSON column did not scan as empty: %q", e.QueryParams)
	}
}

// readRequests runs one statement through the handler's own projection and
// scan, which is the pairing this test exists to prove.
func readRequests(t *testing.T, handle *sql.DB, statement string, arg []any) []RequestEntry {
	t.Helper()
	rows, err := handle.Query(statement, arg...)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var out []RequestEntry
	for rows.Next() {
		var e RequestEntry
		if err := rows.Scan(&e.ID, &e.Time, &e.RequestID, &e.UserID, &e.Username, &e.IP,
			&e.UserAgent, &e.Method, &e.Endpoint, &e.Module, &e.Action, &e.QueryParams,
			&e.RequestBody, &e.Status, &e.Milliseconds, &e.ErrorMessage); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read: %v", err)
	}
	return out
}

// The same for ui_events.
func TestTheInterfaceQueryRunsAndScans(t *testing.T) {
	handle := liveDB(t)
	const sessionID = "logview-ui-test"
	t.Cleanup(func() {
		_, _ = handle.Exec(`DELETE FROM ui_events WHERE session_id=?`, sessionID)
	})
	if _, err := handle.Exec(
		`INSERT INTO ui_events (session_id, event_type, path, event_data)
		 VALUES (?, 'page_view', '/domains', '{"from":"/"}')`, sessionID); err != nil {
		t.Fatalf("insert: %v", err)
	}

	statement, arg, ok := buildUIQuery(map[string]string{
		"session_id": sessionID, "event_type": "page_view",
	}, 10)
	if !ok {
		t.Fatal("the query was refused")
	}
	rows, err := handle.Query(statement, arg...)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var found int
	for rows.Next() {
		var e UIEntry
		if err := rows.Scan(&e.ID, &e.Time, &e.UserID, &e.Username, &e.SessionID,
			&e.RequestID, &e.EventType, &e.Path, &e.EventData); err != nil {
			t.Fatalf("scan: %v", err)
		}
		found++
		if e.Path != "/domains" || e.EventType != "page_view" {
			t.Errorf("the row came back as %+v", e)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read: %v", err)
	}
	if found != 1 {
		t.Errorf("%d row(s) matched every filter, expected 1", found)
	}
}

// The same for app_logs: the projection and the scan must agree.
func TestTheAppQueryRunsAndScans(t *testing.T) {
	handle := liveDB(t)
	const logger = "logview-live-test"
	t.Cleanup(func() {
		_, _ = handle.Exec(`DELETE FROM app_logs WHERE logger_name=?`, logger)
	})
	if _, err := handle.Exec(
		`INSERT INTO app_logs (level, logger_name, message, request_id)
		 VALUES ('ERROR', ?, 'the backup could not be uploaded', 'abc123')`, logger); err != nil {
		t.Fatalf("insert: %v", err)
	}

	statement, arg, ok := buildAppQuery(map[string]string{
		"logger_name": logger, "level": "ERROR", "request_id": "abc123",
	}, 10)
	if !ok {
		t.Fatal("the query was refused")
	}
	rows, err := handle.Query(statement, arg...)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var found int
	for rows.Next() {
		var e AppEntry
		if err := rows.Scan(&e.ID, &e.Time, &e.Level, &e.LoggerName, &e.Message,
			&e.Context, &e.RequestID); err != nil {
			t.Fatalf("scan: %v", err)
		}
		found++
		if e.Level != "ERROR" || e.RequestID != "abc123" {
			t.Errorf("the row came back as %+v", e)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read: %v", err)
	}
	if found != 1 {
		t.Errorf("%d row(s) matched every filter, expected 1", found)
	}
}
