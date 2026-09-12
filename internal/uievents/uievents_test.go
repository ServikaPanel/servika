package uievents

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"servika/internal/logsink"
)

// captured collects what the handler queued, instead of a database.
func captured(t *testing.T) *[]logsink.UIRow {
	t.Helper()
	var rows []logsink.UIRow
	previous := queue
	queue = func(row logsink.UIRow) { rows = append(rows, row) }
	t.Cleanup(func() { queue = previous })
	return &rows
}

// post runs one batch through the handler and returns the response.
func post(t *testing.T, body string) (*httptest.ResponseRecorder, *[]logsink.UIRow) {
	t.Helper()
	rows := captured(t)
	handlers := &Handlers{}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/ui-events", strings.NewReader(body))
	response := httptest.NewRecorder()
	handlers.Collect(response, request)
	return response, rows
}

// The reason the table exists: a route change is not an HTTP request, so this
// is the only place it is ever recorded.
func TestAReportedEventBecomesARow(t *testing.T) {
	response, rows := post(t, `{"session_id":"s1","events":[
		{"type":"page_view","path":"/domains","data":{"from":"/"}},
		{"type":"click_action","path":"/domains","data":{"action":"create"}}
	]}`)

	if response.Code != http.StatusNoContent {
		t.Fatalf("the handler answered %d, want 204", response.Code)
	}
	if len(*rows) != 2 {
		t.Fatalf("%d row(s) were queued, expected 2", len(*rows))
	}
	first := (*rows)[0]
	if first.EventType != "page_view" || first.Path != "/domains" || first.SessionID != "s1" {
		t.Errorf("the first row came back as %+v", first)
	}
	if !strings.Contains(first.EventData, `"from":"/"`) {
		t.Errorf("the payload was lost: %q", first.EventData)
	}
}

// The same redaction request_logs uses. A password must never reach the table
// whichever surface reported it.
func TestASecretInThePayloadIsRedacted(t *testing.T) {
	_, rows := post(t, `{"session_id":"s1","events":[
		{"type":"form_submit","path":"/login","data":{"username":"root","password":"hunter2"}}
	]}`)

	stored := (*rows)[0].EventData
	if strings.Contains(stored, "hunter2") {
		t.Errorf("the password reached the row: %q", stored)
	}
	if !strings.Contains(stored, "[REDACTED]") {
		t.Errorf("the field was dropped instead of redacted: %q", stored)
	}
}

// A payload the panel cannot parse is stored as NULL, because it cannot know
// which field of an unknown shape is a secret.
func TestAnUnparsablePayloadIsNotStored(t *testing.T) {
	_, rows := post(t, `{"session_id":"s1","events":[
		{"type":"page_view","path":"/","data":"not an object"}
	]}`)

	if got := (*rows)[0].EventData; got != "" {
		t.Errorf("a payload that is not a JSON object was stored: %q", got)
	}
}

// An unknown type is recorded as client_error rather than dropped: the event
// still says the interface did something the panel does not model.
func TestAnUnknownTypeIsRecordedAsAnError(t *testing.T) {
	_, rows := post(t, `{"session_id":"s1","events":[{"type":"whatever","path":"/"}]}`)

	if got := (*rows)[0].EventType; got != "client_error" {
		t.Errorf("an unknown type became %q, want client_error", got)
	}
}

// A batch far larger than the browser ever flushes is not a busy operator.
func TestAnOversizedBatchIsRefused(t *testing.T) {
	var builder strings.Builder
	builder.WriteString(`{"session_id":"s1","events":[`)
	for i := 0; i <= maxBatch; i++ {
		if i > 0 {
			builder.WriteString(",")
		}
		builder.WriteString(`{"type":"page_view","path":"/"}`)
	}
	builder.WriteString(`]}`)

	response, rows := post(t, builder.String())
	if response.Code != http.StatusBadRequest {
		t.Errorf("the handler answered %d, want 400", response.Code)
	}
	if len(*rows) != 0 {
		t.Errorf("%d row(s) were queued from a refused batch", len(*rows))
	}
}

// A malformed body must not queue anything.
func TestAMalformedBatchQueuesNothing(t *testing.T) {
	response, rows := post(t, `{"events":`)
	if response.Code != http.StatusBadRequest {
		t.Errorf("the handler answered %d, want 400", response.Code)
	}
	if len(*rows) != 0 {
		t.Errorf("%d row(s) were queued from a malformed body", len(*rows))
	}
}
