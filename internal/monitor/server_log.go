package monitor

import (
	"context"
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

// ServerLog returns server logs from journald or an allowed log file.
func (h *Handlers) ServerLog(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("source")
	if source == "" {
		source = "panel"
	}
	last, _ := strconv.Atoi(r.URL.Query().Get("last"))
	if last < 50 {
		last = 200
	}
	if last > 1000 {
		last = 1000
	}
	ctx, cancel := context.WithTimeout(r.Context(), logBudget)
	defer cancel()
	var output []byte
	if file, ok := fileSources[source]; ok {
		// Tail a file-based source such as nginx error.log.
		// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
		output, _ = logCommand(ctx, "tail", "-n", strconv.Itoa(last), file).CombinedOutput()
	} else {
		args := []string{"--no-pager", "-o", "short-iso", "-n", strconv.Itoa(last)}
		if source != "system" {
			unit, ok := logSources[source]
			if !ok {
				httpx.WriteError(w, http.StatusBadRequest, "invalid log source")
				return
			}
			args = append(args, "-u", unit)
		}
		// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
		output, _ = logCommand(ctx, "journalctl", args...).CombinedOutput()
	}
	text := strings.TrimRight(string(output), "\n")
	lines := []string{}
	if text != "" {
		lines = strings.Split(text, "\n")
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"source":  source,
		"lines":   lines,
		"sources": logSourceOrder,
	})
}
