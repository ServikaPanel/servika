package mail

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"servika/internal/diskusage"
	"servika/internal/files"
	"servika/internal/httpx"
	"servika/internal/middleware"
)

// maildirsizeName is the file Dovecot keeps its own running total in.
//
// The quota backend is `maildir:User quota` (assets/mail/dovecot), which means
// Dovecot does not walk the Maildir to answer a quota question: it reads this
// cached total and adjusts it as it delivers. Anything that adds messages by
// another route leaves the total behind, and a migration writing straight into
// the Maildir is exactly that route.
const maildirsizeName = "maildirsize"

// QuotaRecalc measures a mailbox and repairs Dovecot's cached total.
// POST /domains/{id}/mail/{mid}/quota-recalc
//
// Two separate numbers are being fixed. The panel's own figure is measured here
// and stored, so a list page can draw fifty mailboxes without walking fifty
// trees. Dovecot's figure is not measured at all: removing its cache file is
// what makes it recount, which is the same repair doveadm performs.
func (h *Handlers) QuotaRecalc(w http.ResponseWriter, r *http.Request) {
	id, _, _, ok := h.domain(r)
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

	layout, err := layoutFor(r.Context(), h.DB, mailboxID)
	if err != nil {
		// #nosec G706 -- integer id only.
		httpx.LogR(r, "locate mailbox=%d: %v", mailboxID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the mailbox could not be located on disk")
		return
	}

	used, err := diskusage.Bytes(r.Context(), layout.home+"/"+layout.root)
	if err != nil {
		// #nosec G706 -- integer id only.
		httpx.LogR(r, "measure mailbox=%d: %v", mailboxID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the mailbox could not be measured")
		return
	}

	quota, err := storeUsage(r.Context(), h.DB, mailboxID, used)
	if err != nil {
		// #nosec G706 -- integer id only.
		httpx.LogR(r, "store usage mailbox=%d: %v", mailboxID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the measurement could not be saved")
		return
	}

	// Dovecot rebuilds the file on its next access. A failure here is reported
	// rather than swallowed: the panel's number would be right while Dovecot kept
	// refusing deliveries against a stale one, and nothing on the page would say
	// so.
	reset := true
	if err := files.RemoveAllBeneath(layout.home, layout.root+"/"+maildirsizeName); err != nil {
		// #nosec G706 -- integer id and a filesystem error.
		httpx.LogR(r, "reset dovecot quota cache mailbox=%d: %v", mailboxID, err)
		reset = false
	}

	h.audit(r, "mail.quota.recalc", "", true)
	response := map[string]any{
		"ok":          true,
		"used_bytes":  used,
		"quota_bytes": quota,
		"checked_at":  time.Now().UTC().Format(time.RFC3339),
		// Named for what it means rather than for the file it removes, so a screen
		// can say the panel is right but the mail server has not caught up.
		"dovecot_recount": reset,
	}
	if !reset {
		response["reason"] = "dovecot_cache_not_reset"
	}
	httpx.WriteJSON(w, http.StatusOK, response)
}

// storeUsage records the measurement and returns the mailbox's limit, so one
// round trip answers both halves of what a quota bar draws.
func storeUsage(ctx context.Context, db *sql.DB, mailboxID, used int64) (int64, error) {
	if _, err := db.ExecContext(ctx,
		`UPDATE mailboxes SET used_bytes=?, usage_checked_at=NOW() WHERE id=?`,
		used, mailboxID); err != nil {
		return 0, err
	}
	var quota int64
	if err := db.QueryRowContext(ctx,
		`SELECT quota_bytes FROM mailboxes WHERE id=?`, mailboxID).Scan(&quota); err != nil {
		return 0, err
	}
	return quota, nil
}
