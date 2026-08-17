package domainblock

import (
	"database/sql"
	"log"
	"net/http"

	"servika/internal/httpx"
)

// ReasonBlocked is the stable code a refused creation answers with. The screen
// renders the sentence in twelve languages, so it matches on this rather than
// on prose.
const ReasonBlocked = "domain_name_is_blocked"

// ReasonUnreadable is what a failed read of the list answers with. It is a
// separate code from ReasonBlocked because the two mean different things to
// whoever is looking at the screen: one says "not this name", the other says
// "ask again".
const ReasonUnreadable = "domain_block_list_unreadable"

// RefuseIfBlocked answers the request itself when the hostname may not be
// added, and reports whether the caller must stop.
//
// Every HTTP creation path calls this one function rather than writing its own
// three lines, because a list that is enforced on three of four paths is not
// enforced at all, and drift between hand-written copies is how the fourth one
// goes missing.
//
// A read failure refuses. See Blocked for why that costs nothing.
func RefuseIfBlocked(w http.ResponseWriter, r *http.Request, db *sql.DB, hostname string) bool {
	blocked, _, err := Blocked(r.Context(), db, hostname)
	if err != nil {
		log.Printf("banned domain list read: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, ReasonUnreadable)
		return true
	}
	if blocked {
		httpx.WriteError(w, http.StatusForbidden, ReasonBlocked)
		return true
	}
	return false
}
