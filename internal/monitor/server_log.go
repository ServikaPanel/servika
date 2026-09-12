package monitor

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"servika/internal/httpx"
)

// logCommand runs the log readers. It is a variable so a test can stand in for
// the host's journalctl and tail; nothing outside tests changes it.
var logCommand = exec.CommandContext

// logBudget bounds one log read.
//
// journalctl walks the journal files, and tail reads a log an active nginx is
// still writing; on a host with a damaged journal or a stalled disk either can
// sit there. The handler timeout cancels r.Context() and nothing else, so an
// uncontexted command held the handler and its connection until the socket
// write deadline dropped the client with no response. The budget hangs off the
// request context, so a client that goes away also ends the command.
var logBudget = 20 * time.Second

// logSources maps allowed source keys to systemd units.
// User input never reaches the command directly and must pass through this allowlist.
var logSources = map[string]string{
	"panel":   "servika.service",
	"mariadb": "mariadb.service",
	"named":   "named.service",
	"sshd":    "sshd.service",
	"cron":    "crond.service",
}

// nginx logs to a file rather than journald, so it uses a file-based source.
var fileSources = map[string]string{
	"nginx": "/var/log/nginx/error.log",
}

var logSourceOrder = []string{"panel", "nginx", "mariadb", "named", "sshd", "cron", "system"}

// errUnknownLogSource marks a source that is not in either allowlist.
var errUnknownLogSource = errors.New("invalid log source")

// ServerLog returns server logs from journald or an allowed log file.
func (h *Handlers) ServerLog(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("source")
	if source == "" {
		source = "panel"
	}
	ctx, cancel := context.WithTimeout(r.Context(), logBudget)
	defer cancel()

	output, err := readLogSource(ctx, source, boundedLines(r.URL.Query().Get("last")))
	if errors.Is(err, errUnknownLogSource) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid log source")
		return
	}
	// A read that could not be PERFORMED is not an empty log.
	//
	// The reader's error used to be discarded, so a journalctl that never ran
	// (absent from PATH, refused by SELinux, killed at the budget) answered 200
	// with no lines, which is what a unit that has genuinely logged nothing
	// looks like. This is the screen an operator opens when the panel is
	// misbehaving, and it reported a quiet, healthy server.
	//
	// Output that arrived is served whatever the exit status: a command that
	// ran and complained (tail on a missing file) has told the operator
	// something, and that message is worth more than a refusal.
	if err != nil && len(bytes.TrimSpace(output)) == 0 {
		httpx.LogR(r, "server log %q could not be read: %v", source, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the log could not be read")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"source":  source,
		"lines":   logLines(output),
		"sources": logSourceOrder,
	})
}

// boundedLines folds the requested line count into the range the readers serve.
func boundedLines(raw string) int {
	last, _ := strconv.Atoi(raw)
	if last < 50 {
		return 200
	}
	if last > 1000 {
		return 1000
	}
	return last
}

// readLogSource runs the reader one source needs and returns what it wrote,
// together with the reason it could not be run.
func readLogSource(ctx context.Context, source string, last int) ([]byte, error) {
	if file, ok := fileSources[source]; ok {
		// Tail a file-based source such as nginx error.log.
		// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
		return logCommand(ctx, "tail", "-n", strconv.Itoa(last), file).CombinedOutput()
	}
	args := []string{"--no-pager", "-o", "short-iso", "-n", strconv.Itoa(last)}
	if source != "system" {
		unit, ok := logSources[source]
		if !ok {
			return nil, errUnknownLogSource
		}
		args = append(args, "-u", unit)
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	return logCommand(ctx, "journalctl", args...).CombinedOutput()
}

// logLines splits the reader's output into the lines the screen draws.
func logLines(output []byte) []string {
	text := strings.TrimRight(string(output), "\n")
	if text == "" {
		return []string{}
	}
	return strings.Split(text, "\n")
}
