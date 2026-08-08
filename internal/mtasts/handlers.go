package mtasts

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"servika/internal/httpx"
)

// Handlers serves the public policy file and the per-domain controls.
type Handlers struct {
	DB *sql.DB
	// IPv4 is the address the policy host is pointed at.
	IPv4 string
}

// The domain id is parsed inline in each handler rather than through a shared
// helper. gosec's taint analysis follows the raw URL parameter across a function
// boundary but not across strconv.ParseInt within one function, so a helper
// turns every log line mentioning the id into a G706 report. The value is an
// int64 rendered with %d and cannot carry a newline either way; parsing it
// locally lets the analyzer see that, instead of fourteen suppressions asserting
// it.

// policyHostDomain turns the requested host into the domain whose policy is
// being fetched, or "" when the host is not a policy host at all.
//
// RFC 8461 fixes the hostname to mta-sts.<domain>, so the mapping is exact and
// there is no fallback: answering for any other name would serve one domain's
// policy under another domain's identity.
func policyHostDomain(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if index := strings.LastIndex(host, ":"); index != -1 && !strings.Contains(host[index:], "]") {
		host = host[:index]
	}
	host = strings.Trim(host, ".")
	rest, found := strings.CutPrefix(host, "mta-sts.")
	if !found || rest == "" || !strings.Contains(rest, ".") {
		return ""
	}
	if strings.ContainsAny(rest, " \t\r\n\x00/\\") {
		return ""
	}
	return rest
}

// Policy serves https://mta-sts.<domain>/.well-known/mta-sts.txt.
//
// It is generated rather than written to disk because the file must name the
// domain's CURRENT MX set and match the id the TXT record advertises. A stale
// file on disk would be worse than none: a sender caches what it fetched, and in
// enforce mode it refuses to deliver to any server the cached policy omits.
func (h *Handlers) Policy(w http.ResponseWriter, r *http.Request) {
	domain := policyHostDomain(r.Host)
	if domain == "" {
		httpx.WriteError(w, http.StatusNotFound, "unknown host")
		return
	}

	var id int64
	var mode string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT d.id, md.mtasts_mode
		   FROM mail_domains md
		   JOIN domains d ON d.id = md.domain_id
		  WHERE d.domain_name = ? AND md.status = 'active'`, domain).Scan(&id, &mode)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		httpx.WriteError(w, http.StatusNotFound, "no MTA-STS policy is published for this host")
		return
	case err != nil:
		// #nosec G706 -- domain came through policyHostDomain, which rejects control characters and separators; err is a database driver error.
		log.Printf("mtasts: look up the policy for %s: %v", domain, err)
		httpx.WriteError(w, http.StatusServiceUnavailable, "the policy is temporarily unavailable")
		return
	}
	if !Published(Mode(mode)) {
		httpx.WriteError(w, http.StatusNotFound, "no MTA-STS policy is published for this host")
		return
	}

	hosts, err := MXHosts(r.Context(), h.DB, id)
	if err != nil {
		log.Printf("mtasts: read the MX hosts for domain %d: %v", id, err)
		httpx.WriteError(w, http.StatusServiceUnavailable, "the policy is temporarily unavailable")
		return
	}
	body, err := PolicyFile(Mode(mode), hosts)
	if err != nil {
		// The only way here is a publishable mode with no MX host, which
		// PolicyFile refuses to render rather than serve a policy that matches
		// no server. Answering 404 leaves the domain unprotected; serving that
		// file would reject its mail outright.
		log.Printf("mtasts: render the policy for domain %d: %v", id, err)
		httpx.WriteError(w, http.StatusNotFound, "no MTA-STS policy is published for this host")
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(body)); err != nil {
		log.Printf("mtasts: write the policy for domain %d: %v", id, err)
	}
}

// Get returns the publication state and which step it waits on.
func (h *Handlers) Get(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	state, err := Read(r.Context(), h.DB, id)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "this domain does not host mail here")
		return
	}
	if err != nil {
		log.Printf("mtasts: read the state for domain %d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, state)
}

type modeRequest struct {
	Mode string `json:"mode"`
}

// Post starts the publication sequence or, for a domain that has soaked in
// testing, moves it to enforce.
func (h *Handlers) Post(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var request modeRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	requested := Mode(strings.ToLower(strings.TrimSpace(request.Mode)))
	if !ValidMode(string(requested)) {
		httpx.WriteError(w, http.StatusBadRequest, "mode must be testing or enforce")
		return
	}

	row, err := loadDomain(r.Context(), h.DB, id)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "this domain does not host mail here")
		return
	}
	if err != nil {
		log.Printf("mtasts: load domain %d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if requested == ModeEnforce {
		hosts, err := MXHosts(r.Context(), h.DB, id)
		if err != nil {
			log.Printf("mtasts: read the MX hosts for domain %d: %v", id, err)
			httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		// The lock is checked HERE, on the write path, not only on the read path
		// that renders the button. A screen can be stale or bypassed entirely;
		// this is the boundary.
		if blocked, reason := enforceLock(r.Context(), h.DB, id, row, hosts); blocked {
			httpx.WriteJSON(w, http.StatusForbidden, map[string]string{
				"error":  "enforce is not available yet",
				"reason": reason,
			})
			return
		}
		if _, err := setMode(r.Context(), h.DB, id, ModeEnforce, true); err != nil {
			log.Printf("mtasts: set enforce for domain %d: %v", id, err)
			httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		if err := h.republish(r, id); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "the mode was saved but DNS could not be updated")
			return
		}
		h.respondState(w, r, id)
		return
	}

	// testing: start the sequence. The heal takes it the rest of the way, because
	// each remaining step waits on the world rather than on the panel.
	if Published(row.mode) {
		httpx.WriteError(w, http.StatusConflict, "a policy is already published for this domain")
		return
	}
	if err := WriteEnableRecords(r.Context(), h.DB, id, row.domainName, h.IPv4); err != nil {
		log.Printf("mtasts: write the enable records for domain %d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the DNS records could not be written")
		return
	}
	if _, err := setMode(r.Context(), h.DB, id, ModePendingDNS, false); err != nil {
		log.Printf("mtasts: set pending_dns for domain %d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	h.respondState(w, r, id)
}

// Delete withdraws the publication.
//
// It does NOT remove the records. Withdrawal publishes `mode: none` and keeps
// serving it until every sender's cached copy has expired; deleting the records
// now would leave a sender applying a cached enforce policy against a host that
// has stopped answering, which is exactly the mail loss this whole sequence
// exists to prevent (K3).
func (h *Handlers) Delete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	row, err := loadDomain(r.Context(), h.DB, id)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "this domain does not host mail here")
		return
	}
	if err != nil {
		log.Printf("mtasts: load domain %d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if row.mode == ModeOff {
		httpx.WriteError(w, http.StatusConflict, "no policy is published for this domain")
		return
	}
	if !Published(row.mode) {
		// The sequence never got as far as publishing anything senders could
		// cache, so there is nothing to age out and the records can go now.
		if err := RemoveRecords(r.Context(), h.DB, id); err != nil {
			log.Printf("mtasts: remove the records for domain %d: %v", id, err)
			httpx.WriteError(w, http.StatusInternalServerError, "the DNS records could not be updated")
			return
		}
		if _, err := setMode(r.Context(), h.DB, id, ModeOff, false); err != nil {
			log.Printf("mtasts: set off for domain %d: %v", id, err)
			httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		h.respondState(w, r, id)
		return
	}
	if _, err := setMode(r.Context(), h.DB, id, ModeWithdrawing, true); err != nil {
		log.Printf("mtasts: set withdrawing for domain %d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if err := h.republish(r, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the mode was saved but DNS could not be updated")
		return
	}
	h.respondState(w, r, id)
}

// republish rewrites the policy TXT so senders notice the new policy (K4).
func (h *Handlers) republish(r *http.Request, id int64) error {
	var policyID string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT mtasts_id FROM mail_domains WHERE domain_id=?`, id).Scan(&policyID); err != nil {
		log.Printf("mtasts: read the policy id for domain %d: %v", id, err)
		return err
	}
	if err := WritePolicyTXT(r.Context(), h.DB, id, policyID); err != nil {
		log.Printf("mtasts: write the policy TXT for domain %d: %v", id, err)
		return err
	}
	return nil
}

func (h *Handlers) respondState(w http.ResponseWriter, r *http.Request, id int64) {
	state, err := Read(r.Context(), h.DB, id)
	if err != nil {
		log.Printf("mtasts: read the state for domain %d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, state)
}
