package logs

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"servika/internal/httpx"

	"github.com/go-chi/chi/v5"
)

// The live tail is what an operator watches while a site misbehaves. It streams
// for ever, opens a host path and reopens the file when nginx rotates it, so
// nothing in it was reachable in a test. A seam carries the log directory.

// domainRow answers the one query the lookup runs.
type domainRow struct {
	domain string
	user   string
	err    error
}

func (s domainRow) Connect(context.Context) (driver.Conn, error) { return s, nil }
func (s domainRow) Driver() driver.Driver                        { return s }
func (s domainRow) Open(string) (driver.Conn, error)             { return s, nil }
func (s domainRow) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (s domainRow) Close() error                                 { return nil }
func (s domainRow) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (s domainRow) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &twoColumns{values: []driver.Value{s.domain, s.user}}, nil
}

type twoColumns struct {
	values []driver.Value
	done   bool
}

func (r *twoColumns) Columns() []string { return make([]string, len(r.values)) }
func (r *twoColumns) Close() error      { return nil }
func (r *twoColumns) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	copy(dest, r.values)
	return nil
}

// stream is a response writer the handler can flush into while a test reads it.
type stream struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	header http.Header
	status int
}

func newStream() *stream { return &stream{header: http.Header{}} }

func (s *stream) Header() http.Header { return s.header }

func (s *stream) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(b)
}

func (s *stream) WriteHeader(status int) { s.status = status }
func (s *stream) Flush()                 {}

// A real connection carries these, and http.NewResponseController needs them
// for the socket half of an extension.
func (s *stream) SetReadDeadline(time.Time) error  { return nil }
func (s *stream) SetWriteDeadline(time.Time) error { return nil }

func (s *stream) text() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// notAFlusher is a response writer with no Flush method.
type notAFlusher struct{ recorder *httptest.ResponseRecorder }

func (w notAFlusher) Header() http.Header         { return w.recorder.Header() }
func (w notAFlusher) Write(b []byte) (int, error) { return w.recorder.Write(b) }
func (w notAFlusher) WriteHeader(status int)      { w.recorder.WriteHeader(status) }

// tailRequest builds a request for domain 7 with the given query.
func tailRequest(ctx context.Context, query string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/domains/7/logs/tail"+query, nil)
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("id", "7")
	return request.WithContext(context.WithValue(ctx, chi.RouteCtxKey, routeCtx))
}

// logHandlers points the package at a directory the test owns and returns the
// handlers plus that directory.
func logHandlers(t *testing.T, script domainRow) (*Handlers, string) {
	t.Helper()
	directory := t.TempDir()
	previous := logDir
	logDir = directory
	t.Cleanup(func() { logDir = previous })

	db := sql.OpenDB(script)
	t.Cleanup(func() { _ = db.Close() })
	return &Handlers{DB: db}, directory
}

// A domain that is not there, or cannot be read, is answered before any file is
// opened.
func TestAnUnusableDomainStopsTheTail(t *testing.T) {
	missing, _ := logHandlers(t, domainRow{err: sql.ErrNoRows})
	recorder := httptest.NewRecorder()
	missing.Tail(recorder, tailRequest(context.Background(), ""))
	if recorder.Code != http.StatusNotFound {
		t.Errorf("a missing domain answered %d, want 404: %s", recorder.Code, recorder.Body)
	}

	unreadable, _ := logHandlers(t, domainRow{err: errors.New("read failed")})
	recorder = httptest.NewRecorder()
	unreadable.Tail(recorder, tailRequest(context.Background(), ""))
	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("an unreadable domain answered %d, want 500: %s", recorder.Code, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), "domain logs could not be accessed") {
		t.Errorf("message = %s", recorder.Body)
	}
}

// Only the two files the panel writes may be tailed, because the key reaches a
// host path.
func TestOnlyTheTwoKnownFilesMayBeTailed(t *testing.T) {
	handlers, _ := logHandlers(t, domainRow{domain: "site.example.com", user: "c_shop"})

	recorder := httptest.NewRecorder()
	handlers.Tail(recorder, tailRequest(context.Background(), "?file=../../etc/passwd"))

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", recorder.Code, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), "invalid file key") {
		t.Errorf("message = %s", recorder.Body)
	}
}

// A writer that cannot flush cannot stream, and saying so beats a response that
// never arrives.
func TestAWriterThatCannotFlushIsRefused(t *testing.T) {
	handlers, _ := logHandlers(t, domainRow{domain: "site.example.com", user: "c_shop"})
	recorder := httptest.NewRecorder()

	handlers.Tail(notAFlusher{recorder: recorder}, tailRequest(context.Background(), ""))

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", recorder.Code, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), "streaming is not supported") {
		t.Errorf("message = %s", recorder.Body)
	}
}

// The stream announces itself, then sends the backlog. A caller that is already
// gone gets that much and no more.
func TestTheStreamAnnouncesItselfAndSendsTheBacklog(t *testing.T) {
	handlers, directory := logHandlers(t, domainRow{domain: "site.example.com", user: "c_shop"})
	writeLog(t, filepath.Join(directory, "site.example.com.access.log"), "first line\nsecond line\n")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	answer := newStream()
	done := make(chan struct{})
	go func() {
		handlers.Tail(answer, tailRequest(ctx, ""))
		close(done)
	}()
	if !waitFor(answer, "data: second line") {
		t.Fatalf("the backlog never arrived: %q", answer.text())
	}
	cancel()
	<-done

	if answer.header.Get("Content-Type") != "text/event-stream" {
		t.Errorf("content type = %q", answer.header.Get("Content-Type"))
	}
	if answer.header.Get("X-Accel-Buffering") != "no" {
		t.Errorf("the stream is not exempt from nginx buffering: %v", answer.header)
	}
	text := answer.text()
	for _, want := range []string{": tail access started", "data: first line", "data: second line"} {
		if !strings.Contains(text, want) {
			t.Errorf("the stream does not carry %q: %q", want, text)
		}
	}
}

// A log file that is not there yet is reported in the stream rather than as a
// status code: the headers are already sent.
func TestAMissingFileIsReportedInTheStream(t *testing.T) {
	handlers, _ := logHandlers(t, domainRow{domain: "site.example.com", user: "c_shop"})
	answer := newStream()

	handlers.Tail(answer, tailRequest(context.Background(), "?file=error"))

	if !strings.Contains(answer.text(), "event: error\ndata: log file could not be opened") {
		t.Errorf("stream = %q", answer.text())
	}
}

// writeLog creates a log file with the given content.
func writeLog(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// appendLog adds a line to an existing log file.
func appendLog(t *testing.T, path, line string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(line); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
}

// waitFor waits until the stream carries the text, and reports whether it did.
func waitFor(answer *stream, want string) bool {
	for range 60 {
		if strings.Contains(answer.text(), want) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// A line written after the stream started reaches the reader, which is the
// whole point of a tail.
func TestALineWrittenAfterTheStartIsDelivered(t *testing.T) {
	handlers, directory := logHandlers(t, domainRow{domain: "site.example.com", user: "c_shop"})
	path := filepath.Join(directory, "site.example.com.access.log")
	writeLog(t, path, "backlog\n")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	answer := newStream()
	done := make(chan struct{})
	go func() {
		handlers.Tail(answer, tailRequest(ctx, ""))
		close(done)
	}()

	if !waitFor(answer, "data: backlog") {
		t.Fatalf("the backlog never arrived: %q", answer.text())
	}
	appendLog(t, path, "live line\n")
	if !waitFor(answer, "data: live line") {
		t.Fatalf("a line written during the tail never arrived: %q", answer.text())
	}
	cancel()
	<-done
}

// The router gives every request a bounded budget, and a tail outlives it by
// design. Without a renewal the stream ends while the client is still reading
// and the screen keeps claiming it is live, so the tail buys its own budget
// while the client is there.
func TestTheTailRenewsItsRequestBudget(t *testing.T) {
	handlers, directory := logHandlers(t, domainRow{domain: "site.example.com", user: "c_shop"})
	path := filepath.Join(directory, "site.example.com.access.log")
	writeLog(t, path, "backlog\n")

	previousBudget, previousInterval := tailBudget, tailRenewInterval
	tailBudget, tailRenewInterval = 2*time.Second, 10*time.Millisecond
	t.Cleanup(func() { tailBudget, tailRenewInterval = previousBudget, previousInterval })

	// Shorter than the line that arrives below, so an unrenewed budget ends the
	// stream before it.
	ctx, release := httpx.WithHandlerTimeout(context.Background(), 300*time.Millisecond)
	defer release()

	answer := newStream()
	done := make(chan struct{})
	go func() {
		handlers.Tail(answer, tailRequest(ctx, ""))
		close(done)
	}()
	if !waitFor(answer, "data: backlog") {
		t.Fatalf("the backlog never arrived: %q", answer.text())
	}

	time.Sleep(700 * time.Millisecond) // past the budget the router handed out
	appendLog(t, path, "after the budget\n")
	if !waitFor(answer, "data: after the budget") {
		t.Fatalf("the stream died at the router's budget: %q", answer.text())
	}
	release()
	<-done
}

// nginx rotation truncates the file. The tail reopens it rather than sitting
// past the new end for ever.
func TestARotatedFileIsReopened(t *testing.T) {
	handlers, directory := logHandlers(t, domainRow{domain: "site.example.com", user: "c_shop"})
	path := filepath.Join(directory, "site.example.com.access.log")
	writeLog(t, path, strings.Repeat("old line\n", 50))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	answer := newStream()
	done := make(chan struct{})
	go func() {
		handlers.Tail(answer, tailRequest(ctx, ""))
		close(done)
	}()

	if !waitFor(answer, "data: old line") {
		t.Fatalf("the backlog never arrived: %q", answer.text())
	}
	writeLog(t, path, "after rotation\n")
	if !waitFor(answer, "data: after rotation") {
		t.Fatalf("the rotated file was not reopened: %q", answer.text())
	}
	cancel()
	<-done
}
