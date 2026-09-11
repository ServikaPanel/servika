package mail

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"servika/internal/httpx"
)

type QueueRecipient struct {
	Address     string `json:"address"`
	DelayReason string `json:"delay_reason,omitempty"`
}

type QueueMessage struct {
	QueueID     string           `json:"queue_id"`
	QueueName   string           `json:"queue_name"`
	ArrivalTime int64            `json:"arrival_time"`
	MessageSize int64            `json:"message_size"`
	Sender      string           `json:"sender"`
	Recipients  []QueueRecipient `json:"recipients"`
}

var queueIDPattern = regexp.MustCompile(`^[A-Za-z0-9]{5,64}$`)

// QueueList returns the Postfix mail queue. GET /admin/mail/queue
func (h *Handlers) QueueList(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "postqueue", "-j")
	cmd.Env = subprocessEnv
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		httpx.LogR(r, "mail queue stdout pipe: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the Postfix queue")
		return
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		// #nosec G706 -- the exec error names the binary, not a tenant string.
		httpx.LogR(r, "mail queue start: %v", err)
		httpx.WriteError(w, http.StatusServiceUnavailable, "could not read the Postfix queue")
		return
	}
	out := make([]QueueMessage, 0)
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var item QueueMessage
		if err := json.Unmarshal(scanner.Bytes(), &item); err == nil {
			out = append(out, item)
		}
	}
	waitErr := cmd.Wait()
	if scanner.Err() != nil || waitErr != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" && waitErr != nil {
			detail = waitErr.Error()
		}
		httpx.WriteError(w, http.StatusServiceUnavailable, "could not read the Postfix queue: "+detail)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"messages": out, "count": len(out)})
}

// QueueAction runs a Postfix queue operation. POST /admin/mail/queue {action, queue_id?}
func (h *Handlers) QueueAction(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action  string `json:"action"`
		QueueID string `json:"queue_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var name string
	var args []string
	switch req.Action {
	case "flush":
		name, args = "postqueue", []string{"-f"}
	case "delete", "hold", "release", "requeue":
		if !queueIDPattern.MatchString(req.QueueID) {
			httpx.WriteError(w, http.StatusBadRequest, "invalid queue id")
			return
		}
		flag := map[string]string{"delete": "-d", "hold": "-h", "release": "-H", "requeue": "-r"}[req.Action]
		name, args = "postsuper", []string{flag, req.QueueID}
	default:
		httpx.WriteError(w, http.StatusBadRequest, "action must be flush|delete|hold|release|requeue")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = subprocessEnv
	out, err := cmd.CombinedOutput()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError,
			fmt.Sprintf("queue operation failed: %s", strings.TrimSpace(string(out))))
		return
	}
	h.audit(r, "mail.queue."+req.Action, req.QueueID, true)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "action": req.Action, "queue_id": req.QueueID,
	})
}
