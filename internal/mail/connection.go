package mail

import (
	"errors"
	"net/http"

	"servika/internal/autoconfig"
	"servika/internal/httpx"
)

// ConnectionSettings returns what a person would otherwise be told by hand.
// GET /domains/{id}/mail/{mid}/connection
//
// The values come from internal/autoconfig rather than being written again here,
// because the two would drift and a customer copying a port off this card would
// then disagree with what Thunderbird was told by the discovery endpoint. That
// package also decides the hostname by measuring which names an active
// certificate covers, so this card cannot suggest a name the client will warn
// about.
func (h *Handlers) ConnectionSettings(w http.ResponseWriter, r *http.Request) {
	id, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	mailboxID, ok := h.scopedMailbox(w, r, id)
	if !ok {
		return
	}

	var email, domainName string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT m.email, d.domain_name
		   FROM mailboxes m
		   JOIN mail_domains d ON d.id = m.mail_domain_id
		  WHERE m.id = ?`, mailboxID).Scan(&email, &domainName); err != nil {
		// #nosec G706 -- integer id only.
		httpx.LogR(r, "read mailbox=%d for connection settings: %v", mailboxID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the mailbox could not be read")
		return
	}

	settings, err := autoconfig.SettingsFor(r.Context(), h.DB, domainName)
	if errors.Is(err, autoconfig.ErrNoMailHost) {
		// Not a failure to log. The certificate simply is not issued yet, and
		// saying which part is missing is more useful than an error: the ports are
		// already correct and only the name is pending. The covered list separates
		// the two ways of being pending: names present but none usable means DNS,
		// an empty list means the certificate was never issued.
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"username": email,
			"reason":   "no_mail_hostname",
			"covered":  settings.Covered,
		})
		return
	}
	if err != nil {
		// #nosec G706 -- integer id only.
		httpx.LogR(r, "read mail settings for mailbox=%d: %v", mailboxID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the connection settings could not be read")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"hostname":        settings.Hostname,
		"imap_port":       settings.IMAPPort,
		"submission_port": settings.SubmissionPort,
		"security":        settings.Security,
		// Dovecot's userdb matches on the full address, so a bare local part
		// cannot sign in and printing one would produce a failing account.
		"username": email,
		// Which names the certificate carries, so the announced hostname can be
		// seen to be one of them rather than taken on trust.
		"covered": settings.Covered,
	})
}
