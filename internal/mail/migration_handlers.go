package mail

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"servika/internal/httpx"
	"servika/internal/middleware"
)

// migrationRequestLimit bounds the decoded body. Nothing here is large, and the
// password field means the body must not be spooled anywhere either.
const migrationRequestLimit = 8 << 10

// Discover proposes servers the old mailbox might live on.
// POST /domains/{id}/mail/migration/discover
func (h *Handlers) Discover(w http.ResponseWriter, r *http.Request) {
	id, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if !middleware.EnforceCustomerNotSuspended(w, r, id) {
		return
	}

	var request struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, migrationRequestLimit)).Decode(&request); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request")
		return
	}
	address := strings.TrimSpace(request.Email)
	if addressDomain(address) == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid email address")
		return
	}

	candidates := DiscoverCandidates(r.Context(), address)
	if candidates == nil {
		candidates = []Candidate{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"candidates": candidates,
		// Present even when discovery found nothing, because a Microsoft address
		// cannot be migrated with a password whatever the server list says.
		"provider_notice": providerHint(addressDomain(address), address),
	})
}

// Verify signs in to the remote server so a wrong password is refused now
// rather than after hours of copying.
// POST /domains/{id}/mail/migration/verify
func (h *Handlers) Verify(w http.ResponseWriter, r *http.Request) {
	id, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if !middleware.EnforceCustomerNotSuspended(w, r, id) {
		return
	}

	var request struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Security string `json:"security"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, migrationRequestLimit)).Decode(&request); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request")
		return
	}

	host := strings.ToLower(strings.TrimSpace(request.Host))
	if !isDiscoverableDomain(host) || !validPort(request.Port) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid server address")
		return
	}
	if request.Username == "" || request.Password == "" {
		httpx.WriteError(w, http.StatusBadRequest, "credentials are required")
		return
	}

	accepted, reason := VerifyLogin(r.Context(), host, request.Port, request.Security, request.Username, request.Password)

	// The audit line records the attempt and the remote account, never the
	// password and never the reason, which can name the customer's provider.
	h.audit(r, "mail.migration.verify", request.Username+" @ "+host, accepted)

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":     accepted,
		"reason": reason,
	})
}

// migrationJob is what the screen polls while a copy runs.
type migrationJob struct {
	ID            int64  `json:"id"`
	Status        string `json:"status"`
	RemoteHost    string `json:"remote_host"`
	RemoteUser    string `json:"remote_user"`
	FoldersTotal  int    `json:"folders_total"`
	FoldersDone   int    `json:"folders_done"`
	MessagesTotal int    `json:"messages_total"`
	MessagesDone  int    `json:"messages_done"`
	BytesDone     int64  `json:"bytes_done"`
	ErrorCode     string `json:"error_code"`
	StartedAt     string `json:"started_at"`
	FinishedAt    string `json:"finished_at"`
}

// StartMigration begins copying a mailbox in from another server.
// POST /domains/{id}/mail/{mid}/migration
func (h *Handlers) StartMigration(w http.ResponseWriter, r *http.Request) {
	id, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if !middleware.EnforceCustomerNotSuspended(w, r, id) {
		return
	}
	mailboxID, ok := h.scopedMailbox(w, r, id)
	if !ok {
		return
	}

	var request struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Security string `json:"security"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, migrationRequestLimit)).Decode(&request); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request")
		return
	}
	host := strings.ToLower(strings.TrimSpace(request.Host))
	if !isDiscoverableDomain(host) || !validPort(request.Port) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid server address")
		return
	}
	if request.Username == "" || request.Password == "" {
		httpx.WriteError(w, http.StatusBadRequest, "credentials are required")
		return
	}

	// The login is proved here as well as in the wizard, because the wizard's
	// verification is a separate request and nothing stops this one arriving on
	// its own with a password that was never checked.
	if accepted, reason := VerifyLogin(r.Context(), host, request.Port, request.Security, request.Username, request.Password); !accepted {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "the remote server refused the sign-in", "reason": reason})
		return
	}

	jobID, err := startMigrationJob(h.DB, mailboxID, RemoteAccount{
		Host: host, Port: request.Port, Security: request.Security,
		Username: request.Username, Password: request.Password,
	})
	switch {
	case errors.Is(err, ErrMigrationRunning):
		httpx.WriteJSON(w, http.StatusConflict, map[string]any{
			"error": "a migration is already running for this mailbox", "reason": "migration_already_running",
		})
		return
	case errors.Is(err, ErrTooManyMigrations):
		httpx.WriteJSON(w, http.StatusTooManyRequests, map[string]any{
			"error": "too many migrations are already waiting", "reason": "too_many_migrations",
		})
		return
	case err != nil:
		// #nosec G706 -- integer ids only; the remote host is not logged here.
		httpx.LogR(r, "start mail migration mailbox=%d: %v", mailboxID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not start the migration")
		return
	}

	h.audit(r, "mail.migration.start", request.Username+" @ "+host, true)
	// 202: the copy has been ACCEPTED, not started. Only four run at a time, so
	// saying "running" here would be a guess the status endpoint then contradicts.
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"id": jobID, "status": "queued"})
}

// MigrationStatus reports the latest job for a mailbox.
// GET /domains/{id}/mail/{mid}/migration
func (h *Handlers) MigrationStatus(w http.ResponseWriter, r *http.Request) {
	id, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	mailboxID, ok := h.scopedMailbox(w, r, id)
	if !ok {
		return
	}

	var (
		job                   migrationJob
		startedAt, finishedAt sql.NullString
	)
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT id, status, remote_host, remote_user, folders_total, folders_done,
		        messages_total, messages_done, bytes_done, error_code,
		        DATE_FORMAT(started_at,'%Y-%m-%d %H:%i'), DATE_FORMAT(finished_at,'%Y-%m-%d %H:%i')
		   FROM mail_migration_jobs WHERE mailbox_id=? ORDER BY id DESC LIMIT 1`, mailboxID).
		Scan(&job.ID, &job.Status, &job.RemoteHost, &job.RemoteUser, &job.FoldersTotal, &job.FoldersDone,
			&job.MessagesTotal, &job.MessagesDone, &job.BytesDone, &job.ErrorCode, &startedAt, &finishedAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"job": nil})
		return
	case err != nil:
		// #nosec G706 -- integer id only.
		httpx.LogR(r, "read mail migration mailbox=%d: %v", mailboxID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the migration")
		return
	}
	job.StartedAt = startedAt.String
	job.FinishedAt = finishedAt.String
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"job": job})
}

// CancelMigration stops a running copy.
// DELETE /domains/{id}/mail/{mid}/migration
func (h *Handlers) CancelMigration(w http.ResponseWriter, r *http.Request) {
	id, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if !middleware.EnforceCustomerNotSuspended(w, r, id) {
		return
	}
	mailboxID, ok := h.scopedMailbox(w, r, id)
	if !ok {
		return
	}

	var jobID int64
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT id FROM mail_migration_jobs
		  WHERE mailbox_id=? AND status IN ('queued','running') ORDER BY id DESC LIMIT 1`, mailboxID).Scan(&jobID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		httpx.WriteError(w, http.StatusNotFound, "no migration is running")
		return
	case err != nil:
		// #nosec G706 -- integer id only.
		httpx.LogR(r, "cancel mail migration mailbox=%d: %v", mailboxID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not cancel the migration")
		return
	}

	// The goroutine writes the final row itself when it notices the
	// cancellation. When there is none, this process did not start the job, so
	// the row is closed here instead of being left running for ever.
	if !cancelMigrationJob(jobID) {
		if _, err := h.DB.ExecContext(r.Context(),
			`UPDATE mail_migration_jobs
			    SET status='cancelled', finished_at=NOW(),
			        remote_password=NULL, credentials_cleared=1
			  WHERE id=?`, jobID); err != nil {
			// #nosec G706 -- integer id only.
			httpx.LogR(r, "cancel mail migration job=%d: %v", jobID, err)
			httpx.WriteError(w, http.StatusInternalServerError, "could not cancel the migration")
			return
		}
	}
	h.audit(r, "mail.migration.cancel", strconv.FormatInt(jobID, 10), true)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// scopedMailbox resolves {mid} and refuses one that belongs to another domain.
func (h *Handlers) scopedMailbox(w http.ResponseWriter, r *http.Request, domainID int64) (int64, bool) {
	mailboxID, _ := strconv.ParseInt(chi.URLParam(r, "mid"), 10, 64)
	if mailboxID <= 0 || !h.mailboxBelongs(r.Context(), domainID, mailboxID) {
		httpx.WriteError(w, http.StatusNotFound, "mailbox not found")
		return 0, false
	}
	return mailboxID, true
}
