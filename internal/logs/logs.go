// Package logs provides per-domain nginx log files and live SSE tailing.
package logs

import (
	"bufio"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
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

func filePath(domainName, key string) string {
	switch key {
	case "access":
		return "/var/log/nginx/" + domainName + ".access.log"
	case "error":
		return "/var/log/nginx/" + domainName + ".error.log"
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

// Read returns the last N lines, defaulting to 200 with a maximum of 2000.
func (h *Handlers) Read(w http.ResponseWriter, r *http.Request) {
	domainName, _, err := h.lookup(r)
	if err != nil {
		writeLookupError(w, err)
		return
	}
	key := r.URL.Query().Get("file")
	if key == "" {
		key = "access"
	}
	path := filePath(domainName, key)
	if path == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid file key")
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

// Tail seeks to the end of a log file and streams new lines as SSE data events.
func (h *Handlers) Tail(w http.ResponseWriter, r *http.Request) {
	domainName, _, err := h.lookup(r)
	if err != nil {
		writeLookupError(w, err)
		return
	}
	key := r.URL.Query().Get("file")
	if key == "" {
		key = "access"
	}
	path := filePath(domainName, key)
	if path == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid file key")
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		httpx.WriteError(w, http.StatusInternalServerError, "streaming is not supported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	// #nosec G705 -- response is text/event-stream (not HTML); the browser EventSource treats payloads as opaque data, and key is validated above.
	_, _ = fmt.Fprintf(w, ": tail %s started\n\n", key)
	flusher.Flush()

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
			// #nosec G705 -- response is text/event-stream (not HTML); newlines are stripped so SSE framing stays intact.
			_, _ = fmt.Fprintf(w, "data: %s\n\n", strings.ReplaceAll(ln, "\n", " "))
		}
		flusher.Flush()
	}
	// Seek to the end.
	_, _ = f.Seek(0, io.SeekEnd)

	reader := bufio.NewReader(f)
	ctx := r.Context()
	tick := time.NewTicker(15 * time.Second) // keepalive
	defer tick.Stop()

	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return
		}
		if line != "" {
			ln := strings.TrimRight(line, "\n\r")
			// #nosec G705 -- response is text/event-stream (not HTML); newlines are stripped so SSE framing stays intact.
			_, _ = fmt.Fprintf(w, "data: %s\n\n", strings.ReplaceAll(ln, "\n", " "))
			flusher.Flush()
		}
		if err == io.EOF {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				_, _ = fmt.Fprintln(w, ": keepalive")
				flusher.Flush()
			case <-time.After(500 * time.Millisecond):
				// Reopen the file when rotation truncates its size.
				// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
				if st, err := os.Stat(path); err == nil {
					if cur, _ := f.Seek(0, io.SeekCurrent); cur > st.Size() {
						_ = f.Close()
						// #nosec G703 G304 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
						f, err = os.Open(path)
						if err != nil {
							return
						}
						reader = bufio.NewReader(f)
					}
				}
			}
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
