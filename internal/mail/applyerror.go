package mail

import (
	"errors"
	"log"
	"net/http"

	"servika/internal/httpx"
)

// applyErrorLogLimit caps one logged apply failure. sievec echoes the offending
// part of the script, so the text is bounded by the mailbox owner's own filter
// values rather than by anything the panel controls.
const applyErrorLogLimit = 2000

// writeApplyFailure answers the caller with a fixed reason and keeps the
// underlying text in the server log.
//
// The apply step's error is NOT a validation message. It is the text of a
// root-run subprocess and of the panel's own database connection: the
// go-sql-driver error carries panel table and column identifiers, os.WriteFile
// carries the absolute Maildir path, sievec and `rspamadm configtest` carry the
// daemon's own output, and the rspamd generator spans every enabled domain on
// the server, so its "invalid domain" branch names a domain the caller may not
// own. Every route that reaches here is mounted with middleware.CustomerScope,
// which is the lowest-privilege role.
func writeApplyFailure(w http.ResponseWriter, operation string, id int64, message string, err error) {
	if errors.Is(err, ErrSieveUnavailable) || errors.Is(err, ErrRspamdUnavailable) {
		// The host does not have the component at all. Saying so is not
		// internal detail, and it is the difference between a customer who
		// opens a ticket and one who retries a save that can never work.
		httpx.WriteError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	// #nosec G706 -- sanitize strips the control characters, which is required
	// here rather than optional: sievec quotes the generated script back, and
	// the script carries the mailbox owner's own filter match values.
	log.Printf("%s=%d: %s", operation, id, sanitize(err.Error(), applyErrorLogLimit))
	httpx.WriteError(w, http.StatusServiceUnavailable, message)
}
