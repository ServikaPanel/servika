// Package logs provides per-domain nginx log files and live SSE tailing.
package logs

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"servika/internal/httpx"
	"servika/internal/subdomain"

	"github.com/go-chi/chi/v5"
)

// Handlers provides domain log HTTP handlers.
type Handlers struct {
	DB *sql.DB
}

// LogFile describes an available domain log file.
type LogFile struct {
	Key     string `json:"key"` // "access" | "error"
	Label   string `json:"label"`
	Path    string `json:"path"`
	SizeB   int64  `json:"size_b"`
	Changed string `json:"changed"`
	Current bool   `json:"current"`
}

// lookup resolves the log name for the request. A {sid} URL parameter selects that
// subdomain, whose vhost logs under its own FQDN, so the returned name addresses the
// subdomain's files rather than the parent domain's.
func (h *Handlers) lookup(r *http.Request) (string, string, error) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var domainName, systemUser string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT domain_name, system_user FROM domains WHERE id=?`, id).
		Scan(&domainName, &systemUser)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", os.ErrNotExist
	}
	if err != nil {
		return "", "", err
	}
	if raw := chi.URLParam(r, "sid"); raw != "" {
		sid, convErr := strconv.ParseInt(raw, 10, 64)
		if convErr != nil {
			return "", "", os.ErrNotExist
		}
		scope, ok := subdomain.ResolveScope(r.Context(), h.DB, id, sid)
		if !ok {
			return "", "", os.ErrNotExist
		}
		return scope.FQDN, systemUser, nil
	}
	return domainName, systemUser, nil
}

// logDir is where nginx writes the per-domain files. It is a variable so a test
// can point the handlers at a directory it owns instead of the host's.
var logDir = "/var/log/nginx"

func filePath(domainName, key string) string {
	switch key {
	case "access":
		return filepath.Join(logDir, domainName+".access.log")
	case "error":
		return filepath.Join(logDir, domainName+".error.log")
	}
	return ""
}

// List returns available log files for a domain.
func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	domainName, _, err := h.lookup(r)
	if err != nil {
		status := http.StatusInternalServerError
		message := "logs could not be listed"
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
			message = "domain not found"
		}
		httpx.WriteError(w, status, message)
		return
	}
	out := []LogFile{}
	for _, logType := range []struct{ Key, Label string }{
		{"access", "Access"},
		{"error", "Error"},
	} {
		path := filePath(domainName, logType.Key)
		entry := LogFile{Key: logType.Key, Label: logType.Label, Path: path}
		// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
		if info, err := os.Stat(path); err == nil {
			entry.Current = true
			entry.SizeB = info.Size()
			entry.Changed = info.ModTime().UTC().Format("2006-01-02T15:04:05Z")
		}
		out = append(out, entry)
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// requestedFile resolves the log file the request asks for, and answers the
// request itself when the domain or the key is not one this endpoint serves.
func (h *Handlers) requestedFile(w http.ResponseWriter, r *http.Request) (key, path string, ok bool) {
	domainName, _, err := h.lookup(r)
	if err != nil {
		writeLookupError(w, err)
		return "", "", false
	}
	key = r.URL.Query().Get("file")
	if key == "" {
		key = "access"
	}
	path = filePath(domainName, key)
	if path == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid file key")
		return "", "", false
	}
	return key, path, true
}

// Read returns the last N lines, defaulting to 200 with a maximum of 2000.
func (h *Handlers) Read(w http.ResponseWriter, r *http.Request) {
	key, path, ok := h.requestedFile(w, r)
	if !ok {
		return
	}
	last, _ := strconv.Atoi(r.URL.Query().Get("last"))
	if last <= 0 {
		last = 200
	}
	if last > 2000 {
		last = 2000
	}

	lines, err := lastNLines(path, last)
	if err != nil {
		if os.IsNotExist(err) {
			httpx.WriteJSON(w, http.StatusOK, map[string]any{
				"file": key, "path": path, "lines": []string{}, "current": false,
			})
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "log file could not be read")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"file": key, "path": path, "lines": lines, "current": true,
	})
}

// openStream writes the event-stream headers and announces the tail. It
// answers the request itself when the writer cannot stream.
func openStream(w http.ResponseWriter, key string) (http.Flusher, bool) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		httpx.WriteError(w, http.StatusInternalServerError, "streaming is not supported")
		return nil, false
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	// #nosec G705 -- response is text/event-stream (not HTML); the browser EventSource treats payloads as opaque data, and key is validated above.
	_, _ = fmt.Fprintf(w, ": tail %s started\n\n", key)
	flusher.Flush()
	return flusher, true
}

// sendLine writes one log line as an SSE data event.
func sendLine(w http.ResponseWriter, line string) {
	// #nosec G705 -- response is text/event-stream (not HTML); newlines are stripped so SSE framing stays intact.
	_, _ = fmt.Fprintf(w, "data: %s\n\n", strings.ReplaceAll(line, "\n", " "))
}

// reopenIfRotated answers the same file, or a freshly opened one when rotation
// truncated it below the current position. It reports false when the rotated
// file cannot be opened, which ends the stream.
func reopenIfRotated(f *os.File, path string) (*os.File, bool) {
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	st, err := os.Stat(path)
	if err != nil {
		return f, true
	}
	if cur, _ := f.Seek(0, io.SeekCurrent); cur <= st.Size() {
		return f, true
	}
	_ = f.Close()
	// #nosec G703 G304 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	rotated, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	return rotated, true
}

// streamLines sends every new line until the caller goes away. renew lengthens
// the request's own budget and is called on every keepalive.
func streamLines(ctx context.Context, w http.ResponseWriter, flusher http.Flusher, f *os.File, path string, renew func()) {
	reader := bufio.NewReader(f)
	tick := time.NewTicker(15 * time.Second) // keepalive
	defer tick.Stop()

	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return
		}
		if line != "" {
			// A log busy enough never to reach EOF renews here instead of on the
			// keepalive, which only runs while the reader is waiting.
			renew()
			sendLine(w, strings.TrimRight(line, "\n\r"))
			flusher.Flush()
		}
		if err != io.EOF {
			continue
		}
		rotated, ok := waitForMore(ctx, w, flusher, tick, f, path, renew)
		if !ok {
			return
		}
		if rotated != f {
			f = rotated
			reader = bufio.NewReader(f)
		}
	}
}

// waitForMore waits at the end of the file for the next line, sending a
// keepalive on the ticker. It reports false when the stream must end.
func waitForMore(ctx context.Context, w http.ResponseWriter, flusher http.Flusher,
	tick *time.Ticker, f *os.File, path string, renew func()) (*os.File, bool) {
	// A tail is long-lived by design, so it buys its next budget here rather
	// than dying at the router's default. Renewing on the poll rather than on
	// the keepalive keeps it independent of how quiet the log is.
	renew()
	select {
	case <-ctx.Done():
		return f, false
	case <-tick.C:
		_, _ = fmt.Fprintln(w, ": keepalive")
		flusher.Flush()
		return f, true
	case <-time.After(500 * time.Millisecond):
		return reopenIfRotated(f, path)
	}
}

// Tail seeks to the end of a log file and streams new lines as SSE data events.
func (h *Handlers) Tail(w http.ResponseWriter, r *http.Request) {
	key, path, ok := h.requestedFile(w, r)
	if !ok {
		return
	}
	flusher, ok := openStream(w, key)
	if !ok {
		return
	}

	// #nosec G703 G304 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	f, err := os.Open(path)
	if err != nil {
		_, _ = fmt.Fprint(w, "event: error\ndata: log file could not be opened\n\n")
		flusher.Flush()
		return
	}
	defer func() { _ = f.Close() }()
	// Send approximately the last 200 lines first.
	if existing, err := lastNLines(path, 200); err == nil {
		for _, ln := range existing {
			sendLine(w, ln)
		}
		flusher.Flush()
	}
	// Seek to the end.
	_, _ = f.Seek(0, io.SeekEnd)

	streamLines(r.Context(), w, flusher, f, path, tailRenewal(w, r))
}

var (
	// tailBudget is how far ahead each renewal pushes the tail's deadline. The
	// stream lives as long as the client reads it and still ends promptly once
	// the client goes away, because the parent request context is unchanged.
	tailBudget = 5 * time.Minute
	// tailRenewInterval bounds how often the two deadline syscalls run, so a
	// busy log costs no syscall per line.
	tailRenewInterval = 15 * time.Second
)

// tailRenewal returns the function the tail calls to buy its next budget. A
// failed extension is logged and the stream continues on the budget it has: the
// router ends it, which is the behaviour that existed before.
func tailRenewal(w http.ResponseWriter, r *http.Request) func() {
	var last time.Time
	return func() {
		if time.Since(last) < tailRenewInterval {
			return
		}
		last = time.Now()
		if err := httpx.ExtendDeadline(w, r, tailBudget); err != nil {
			httpx.LogR(r, "log tail deadline extension: %v", err)
		}
	}
}

// lastNLines reads N lines from the end of a file.
func lastNLines(path string, n int) ([]string, error) {
	// #nosec G703 G304 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	const blockSize = 8192
	var buf []byte
	var read int64
	// Read backward from the end of the file in 8 KB chunks.
	for read < size && countLines(buf) < n+1 {
		read += blockSize
		if read > size {
			read = size
		}
		_, _ = f.Seek(-read, io.SeekEnd)
		tmp := make([]byte, read)
		_, _ = f.ReadAt(tmp, size-read)
		buf = tmp
	}
	// Split into lines.
	lines := strings.Split(strings.TrimRight(string(buf), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, nil
}

func countLines(b []byte) int {
	n := 0
	for _, c := range b {
		if c == '\n' {
			n++
		}
	}
	return n
}

func writeLookupError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	message := "domain logs could not be accessed"
	if errors.Is(err, os.ErrNotExist) {
		status = http.StatusNotFound
		message = "domain not found"
	}
	httpx.WriteError(w, status, message)
}
