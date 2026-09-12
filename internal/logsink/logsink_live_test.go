package logsink

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"servika/internal/db"
	"servika/internal/logx"
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

// The multi-row statement is assembled by hand, so a real server is the only
// thing that proves it parses and that every value lands in its own column.
func TestABatchOfRequestRowsIsWritten(t *testing.T) {
	handle := liveDB(t)
	const reqID = "logsink-batch-test"
	t.Cleanup(func() {
		_, _ = handle.Exec(`DELETE FROM request_logs WHERE request_id=?`, reqID)
	})

	batch := []RequestRow{
		{
			RequestID: reqID, UserID: 0, Username: "", IP: "203.0.113.7",
			UserAgent: "curl/8.0", Method: "POST", Endpoint: "/api/v1/auth/login",
			Module: "auth", Action: "login",
			QueryParams: `{"page":"2"}`, RequestBody: `{"username":"root","password":"[REDACTED]"}`,
			ResponseStatus: 401, ResponseMS: 12, ErrorMessage: "invalid credentials",
		},
		{
			RequestID: reqID, UserID: 1, Username: "root", IP: "203.0.113.7",
			Method: "GET", Endpoint: "/api/v1/domains", Module: "domains",
			ResponseStatus: 200, ResponseMS: 3,
		},
	}

	writeRequests(context.Background(), handle, batch)

	rows := readRequests(t, handle, reqID)
	if len(rows) != 2 {
		t.Fatalf("%d row(s) were written, expected 2", len(rows))
	}
	first := rows[0]
	if first.Method != "POST" || first.Endpoint != "/api/v1/auth/login" || first.ResponseStatus != 401 {
		t.Errorf("the first row came back as %+v", first)
	}
	if first.UserID != 0 {
		t.Errorf("an anonymous request stored user_id=%d, expected NULL", first.UserID)
	}
	if !strings.Contains(first.RequestBody, "[REDACTED]") {
		t.Errorf("the body column lost its content: %q", first.RequestBody)
	}
	if rows[1].UserID != 1 || rows[1].Username != "root" {
		t.Errorf("the authenticated row lost its actor: %+v", rows[1])
	}
}

// readRequests reads back the rows one test wrote, by the id it named.
func readRequests(t *testing.T, handle *sql.DB, requestID string) []RequestRow {
	t.Helper()
	cursor, err := handle.Query(
		`SELECT COALESCE(user_id,0), username, method, endpoint, response_status,
		        COALESCE(request_body,''), COALESCE(query_params,'')
		   FROM request_logs WHERE request_id=? ORDER BY id`, requestID)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	defer func() { _ = cursor.Close() }()

	var rows []RequestRow
	for cursor.Next() {
		var row RequestRow
		if err := cursor.Scan(&row.UserID, &row.Username, &row.Method, &row.Endpoint,
			&row.ResponseStatus, &row.RequestBody, &row.QueryParams); err != nil {
			t.Fatalf("scan: %v", err)
		}
		rows = append(rows, row)
	}
	if err := cursor.Err(); err != nil {
		t.Fatalf("read: %v", err)
	}
	return rows
}

// The application log has no request to hang from on most of its lines, so an
// empty request_id must be a valid row rather than a refused one.
func TestAnApplicationLineIsWrittenWithoutARequest(t *testing.T) {
	handle := liveDB(t)
	const logger = "logsink-live-test"
	t.Cleanup(func() {
		_, _ = handle.Exec(`DELETE FROM app_logs WHERE logger_name=?`, logger)
	})

	writeApp(context.Background(), handle, []AppRow{
		{Level: "ERROR", LoggerName: logger, Message: "the backup could not be uploaded"},
		{Level: "INFO", LoggerName: logger, Message: "started", Context: `{"version":"1.2.3"}`},
	})

	var errors, total int
	if err := handle.QueryRow(
		`SELECT SUM(level='ERROR'), COUNT(*) FROM app_logs WHERE logger_name=? AND request_id=''`,
		logger).Scan(&errors, &total); err != nil {
		t.Fatalf("count: %v", err)
	}
	if total != 2 {
		t.Errorf("%d row(s) were written, expected 2", total)
	}
	if errors != 1 {
		t.Errorf("%d row(s) came back at ERROR, expected 1", errors)
	}
}

// The whole app_logs path, end to end and off the HTTP path: a plain logx call
// from ordinary code must reach the table on its own, because that is where the
// panel writes almost everything it has to say.
func TestALogxCallReachesTheTableWithoutARequest(t *testing.T) {
	handle := liveDB(t)
	const message = "logsink live test: the nightly sweep finished"
	t.Cleanup(func() {
		_, _ = handle.Exec(`DELETE FROM app_logs WHERE message=?`, message)
	})

	ctx, cancel := context.WithCancel(t.Context())
	StartApplicationLog(ctx, handle)
	t.Cleanup(func() { logx.SetSink(nil) })

	logx.Infof("%s", message)
	// Cancelling the context makes the writer drain what it is holding, so the
	// test reads a written row rather than waiting out the flush interval.
	cancel()

	level, requestID := waitForAppRow(t, handle, message)
	if level != "INFO" {
		t.Errorf("the row came back at %q, want INFO", level)
	}
	if requestID != "" {
		t.Errorf("a line with no request stored request_id=%q", requestID)
	}
}

// waitForAppRow polls for the row the sink is writing in another goroutine.
func waitForAppRow(t *testing.T, handle *sql.DB, message string) (level, requestID string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := handle.QueryRow(
			`SELECT level, request_id FROM app_logs WHERE message=?`, message).Scan(&level, &requestID)
		if err == nil {
			return level, requestID
		}
		if !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("read: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("the line never reached app_logs")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// A JSON column refuses "", so an empty body must reach it as NULL. Without
// this the whole batch fails and every row in it is lost.
func TestAnEmptyBodyIsStoredAsNull(t *testing.T) {
	handle := liveDB(t)
	const reqID = "logsink-null-test"
	t.Cleanup(func() {
		_, _ = handle.Exec(`DELETE FROM request_logs WHERE request_id=?`, reqID)
	})

	writeRequests(context.Background(), handle, []RequestRow{
		{RequestID: reqID, Method: "GET", Endpoint: "/api/v1/me", ResponseStatus: 200},
	})

	var nulls int
	if err := handle.QueryRow(
		`SELECT COUNT(*) FROM request_logs
		  WHERE request_id=? AND request_body IS NULL AND query_params IS NULL`,
		reqID).Scan(&nulls); err != nil {
		t.Fatalf("count: %v", err)
	}
	if nulls != 1 {
		t.Errorf("%d row(s) stored NULL for the empty JSON columns, expected 1", nulls)
	}
}
