package panelport

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"servika/internal/httpx"
	"servika/internal/middleware"
)

// Handlers serves the panel port screen.
type Handlers struct {
	DB *sql.DB
}

// changing serialises port changes against each other AND against
// internal/serverip.
//
// Both packages change how this server is reached, and the failure they share
// is losing that access entirely. Two of them at once could take an address
// away while a port is being verified on it, and the verification would then
// blame the port for a change it did not make.
var changing sync.Mutex

// Lock and Unlock let the address package take the same lock. It is exported
// rather than shared through a third package because there are exactly two
// callers and a package whose only content is a mutex explains less than this
// comment does.
func Lock()   { changing.Lock() }
func Unlock() { changing.Unlock() }

func actorOf(r *http.Request) any {
	if claims := middleware.ClaimsFrom(r); claims != nil && claims.UserID > 0 {
		return claims.UserID
	}
	return nil
}

func writeRefusal(w http.ResponseWriter, status int, reason, message string) {
	httpx.WriteJSON(w, status, map[string]string{"error": message, "reason": reason})
}

func (h *Handlers) fail(w http.ResponseWriter, err error, fallback string) {
	if reason := ReasonOf(err); reason != "" {
		writeRefusal(w, http.StatusConflict, reason, err.Error())
		return
	}
	complain("%v", err)
	httpx.WriteError(w, http.StatusInternalServerError, fallback)
}

// Status — GET /system/panel-port (AdminOnly).
//
// The ports come off the FILES, so the screen can never show a port the server
// is not on. The in-flight outcome is reported beside them, because a backend
// change is the one operation here whose result arrives after the panel has
// restarted and the request that started it is long gone.
func (h *Handlers) Status(w http.ResponseWriter, r *http.Request) {
	ports, err := Current()
	if err != nil {
		h.fail(w, err, "the panel's ports could not be read")
		return
	}
	body := map[string]any{
		"backend":  ports.Backend,
		"external": ports.External,
		"host":     ports.BackendHost,
	}
	if outcome, ok := ReadOutcome(); ok {
		body["last_change"] = outcome
	}
	httpx.WriteJSON(w, http.StatusOK, body)
}

// Change — POST /system/panel-port (AdminOnly).
func (h *Handlers) Change(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Kind string `json:"kind"`
		Port int    `json:"port"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !ValidKind(body.Kind) {
		writeRefusal(w, http.StatusBadRequest, ReasonUnknownKind, "unknown port kind")
		return
	}
	if err := ValidatePort(body.Port); err != nil {
		h.fail(w, err, "that port cannot be used")
		return
	}

	// A change already in flight must not be joined by a second one: the first
	// one's rollback restores files the second one just rewrote.
	if outcome, ok := ReadOutcome(); ok && outcome.State == StateRunning {
		writeRefusal(w, http.StatusConflict, ReasonBusy,
			"a port change is already running")
		return
	}

	changing.Lock()
	defer changing.Unlock()

	current, err := Current()
	if err != nil {
		h.fail(w, err, "the panel's ports could not be read")
		return
	}
	old := current.External
	if body.Kind == KindBackend {
		old = current.Backend
	}
	if old == body.Port {
		writeRefusal(w, http.StatusConflict, ReasonSamePort, "the panel is already on that port")
		return
	}

	historyID, err := h.record(r.Context(), body.Kind, old, body.Port, actorOf(r))
	if err != nil {
		complain("record history: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database write failed")
		return
	}

	if body.Kind == KindExternal {
		// In process: this change does not restart the panel, so the request
		// that asked for it is still here to be told what happened.
		err := ApplyExternal(r.Context(), current, body.Port)
		h.finish(r.Context(), historyID, err)
		if err != nil {
			h.fail(w, err, "the port could not be changed")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"kind": body.Kind, "port": body.Port, "verified": true,
		})
		return
	}

	// Detached: this restarts the panel, so the verdict arrives through the
	// outcome file rather than through this response.
	if err := StartBackendChange(r.Context(), current, body.Port, historyID); err != nil {
		h.finish(r.Context(), historyID, err)
		h.fail(w, err, "the port change could not be started")
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{
		"kind": body.Kind, "port": body.Port, "verified": false,
		"note": "the panel is restarting; this screen will report the result once it is back",
	})
}

func (h *Handlers) record(ctx context.Context, kind string, oldPort, newPort int, actor any) (int64, error) {
	result, err := h.DB.ExecContext(ctx,
		`INSERT INTO panel_port_history (kind, old_port, new_port, actor_uid)
		 VALUES (?,?,?,?)`, kind, oldPort, newPort, actor)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// finish closes a history row from an in-process result.
func (h *Handlers) finish(ctx context.Context, id int64, err error) {
	succeeded, rolledBack, message := 1, 0, ""
	if err != nil {
		succeeded, message = 0, err.Error()
		if reason := ReasonOf(err); reason == ReasonRolledBack {
			rolledBack = 1
		}
	}
	if len(message) > 512 {
		message = message[:512]
	}
	if _, execErr := h.DB.ExecContext(ctx,
		`UPDATE panel_port_history
		    SET succeeded=?, rolled_back=?, last_error=?, finished_at=NOW()
		  WHERE id=?`, succeeded, rolledBack, message, id); execErr != nil {
		complain("close history row %d: %v", id, execErr)
	}
}

// FoldOutcome folds a detached change's verdict into the history table.
//
// It runs at STARTUP, because a backend change ends with this process being
// replaced: the panel that started the change is not the panel that learns how
// it went. Anything still marked running when the panel is up again is a helper
// that died without writing a verdict, and it is recorded as a failure rather
// than left looking like it is still working.
func FoldOutcome(db *sql.DB) {
	outcome, ok := ReadOutcome()
	if !ok || outcome.HistoryID <= 0 {
		return
	}
	if outcome.State == StateRunning {
		if !helperStillRunning() {
			outcome.State = StateRollbackFailed
			outcome.Error = "the change helper stopped without reporting a result"
		} else {
			// It really is still working; leave the file for the next start.
			return
		}
	}

	succeeded, rolledBack := 0, 0
	switch outcome.State {
	case StateSucceeded:
		succeeded = 1
	case StateRolledBack:
		rolledBack = 1
	}
	message := outcome.Error
	if len(message) > 512 {
		message = message[:512]
	}
	if _, err := db.Exec(
		`UPDATE panel_port_history
		    SET succeeded=?, rolled_back=?, last_error=?, finished_at=NOW()
		  WHERE id=? AND finished_at IS NULL`,
		succeeded, rolledBack, message, outcome.HistoryID); err != nil {
		complain("fold outcome into history: %v", err)
		return
	}
	// The file is only cleared once the row has it, so a database that was
	// briefly unreachable does not lose the verdict.
	ClearOutcome()
}

// helperStillRunning asks systemd rather than guessing from the file's age.
func helperStillRunning() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, _ := run(ctx, "systemctl", "is-active", helperUnit)
	state := trimSpace(out)
	return state == "active" || state == "activating"
}

// History — GET /system/panel-port/history (AdminOnly).
func (h *Handlers) History(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, kind, old_port, new_port, succeeded, rolled_back, last_error, created_at
		   FROM panel_port_history ORDER BY id DESC LIMIT 50`)
	if err != nil {
		complain("history: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	defer func() { _ = rows.Close() }()

	type entry struct {
		ID         int64  `json:"id"`
		Kind       string `json:"kind"`
		OldPort    int    `json:"old_port"`
		NewPort    int    `json:"new_port"`
		Succeeded  bool   `json:"succeeded"`
		RolledBack bool   `json:"rolled_back"`
		LastError  string `json:"last_error,omitempty"`
		CreatedAt  string `json:"created_at"`
	}
	out := []entry{}
	for rows.Next() {
		var item entry
		var created time.Time
		if err := rows.Scan(&item.ID, &item.Kind, &item.OldPort, &item.NewPort,
			&item.Succeeded, &item.RolledBack, &item.LastError, &created); err != nil {
			complain("history scan: %v", err)
			httpx.WriteError(w, http.StatusInternalServerError, "database query failed")
			return
		}
		item.CreatedAt = created.UTC().Format(time.RFC3339)
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		complain("history rows: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"changes": out})
}
