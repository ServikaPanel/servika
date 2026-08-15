package mail

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"servika/internal/httpx"
	"servika/internal/middleware"
)

// maxForwardingDestinations bounds one mailbox's fan-out. A forward that
// explodes into dozens of addresses is a relay, not a forward, and the outbound
// limits are counted per mailbox.
const maxForwardingDestinations = 10

// Forwarding is what a mailbox sends on and whether it keeps a copy.
type Forwarding struct {
	Enabled      bool     `json:"enabled"`
	Destinations []string `json:"destinations"`
	KeepCopy     bool     `json:"keep_copy"`
}

// ForwardingGet returns a mailbox's forwarding.
// GET /domains/{id}/mail/{mid}/forwarding
func (h *Handlers) ForwardingGet(w http.ResponseWriter, r *http.Request) {
	id, _, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	mailboxID, ok := h.scopedMailbox(w, r, id)
	if !ok {
		return
	}

	forwarding, err := readForwarding(r.Context(), h.DB, mailboxID)
	if err != nil {
		// #nosec G706 -- integer id only.
		log.Printf("read forwarding mailbox=%d: %v", mailboxID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the forwarding")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, forwarding)
}

// ForwardingPut saves a mailbox's forwarding and recompiles its Sieve script.
// PUT /domains/{id}/mail/{mid}/forwarding
func (h *Handlers) ForwardingPut(w http.ResponseWriter, r *http.Request) {
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

	var request struct {
		Enabled      bool     `json:"enabled"`
		Destinations []string `json:"destinations"`
		KeepCopy     bool     `json:"keep_copy"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, migrationRequestLimit)).Decode(&request); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if !request.Enabled || len(request.Destinations) == 0 {
		if _, err := h.DB.ExecContext(r.Context(),
			`DELETE FROM mail_forwarding WHERE mailbox_id=?`, mailboxID); err != nil {
			// #nosec G706 -- integer id only.
			log.Printf("clear forwarding mailbox=%d: %v", mailboxID, err)
			httpx.WriteError(w, http.StatusInternalServerError, "could not save the forwarding")
			return
		}
		h.applyForwardingSieve(r.Context(), w, mailboxID, Forwarding{})
		h.audit(r, "mail.forwarding.clear", "", true)
		return
	}

	destinations, reason := normalizeDestinations(request.Destinations)
	if reason != "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{
			"error": "the destinations are not usable", "reason": reason,
		})
		return
	}

	// Forwarding to the mailbox's own address is a loop, and the panel is the
	// only place that can see it before the mail server does.
	var email string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT email FROM mailboxes WHERE id=?`, mailboxID).Scan(&email); err != nil {
		// #nosec G706 -- integer id only.
		log.Printf("read mailbox=%d: %v", mailboxID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not save the forwarding")
		return
	}
	for _, destination := range destinations {
		if strings.EqualFold(destination, email) {
			httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{
				"error": "a mailbox cannot forward to itself", "reason": "forwarding_loop",
			})
			return
		}
	}

	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO mail_forwarding (mailbox_id, destinations, keep_copy) VALUES (?,?,?)
		 ON DUPLICATE KEY UPDATE destinations=VALUES(destinations), keep_copy=VALUES(keep_copy)`,
		mailboxID, strings.Join(destinations, ","), boolToInt(request.KeepCopy)); err != nil {
		// #nosec G706 -- integer id only.
		log.Printf("save forwarding mailbox=%d: %v", mailboxID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not save the forwarding")
		return
	}

	h.applyForwardingSieve(r.Context(), w, mailboxID,
		Forwarding{Enabled: true, Destinations: destinations, KeepCopy: request.KeepCopy})
	h.audit(r, "mail.forwarding.set", strings.Join(destinations, ","), true)
}

// applyForwardingSieve recompiles the script and answers.
//
// The row is already written, so a compile failure is reported rather than
// hidden: the panel would otherwise show forwarding that the mail server is not
// actually performing.
func (h *Handlers) applyForwardingSieve(ctx context.Context, w http.ResponseWriter, mailboxID int64, forwarding Forwarding) {
	if err := ApplyMailboxSieve(ctx, h.DB, mailboxID); err != nil {
		// #nosec G706 -- integer id and the compiler's own output.
		log.Printf("apply sieve mailbox=%d: %v", mailboxID, err)
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"enabled": forwarding.Enabled, "destinations": forwarding.Destinations,
			"keep_copy": forwarding.KeepCopy,
			// Saved, but not yet running. Saying so is the difference between a
			// customer waiting for mail that never comes and one who knows.
			"applied": false, "reason": "sieve_not_applied",
		})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"enabled": forwarding.Enabled, "destinations": forwarding.Destinations,
		"keep_copy": forwarding.KeepCopy, "applied": true,
	})
}

// readForwarding returns a mailbox's forwarding, or an empty one when there is
// none. A missing row means forwarding is off; there is no flag to disagree.
func readForwarding(ctx context.Context, db *sql.DB, mailboxID int64) (Forwarding, error) {
	var (
		destinations string
		keepCopy     int
	)
	err := db.QueryRowContext(ctx,
		`SELECT destinations, keep_copy FROM mail_forwarding WHERE mailbox_id=?`, mailboxID).
		Scan(&destinations, &keepCopy)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Forwarding{Destinations: []string{}, KeepCopy: true}, nil
	case err != nil:
		return Forwarding{}, err
	}
	return Forwarding{
		Enabled:      true,
		Destinations: strings.Split(destinations, ","),
		KeepCopy:     keepCopy == 1,
	}, nil
}

// normalizeDestinations trims, lower-cases and checks each address, returning a
// reason code rather than a sentence when one is unusable.
func normalizeDestinations(input []string) ([]string, string) {
	var out []string
	seen := make(map[string]bool, len(input))
	for _, raw := range input {
		for candidate := range strings.SplitSeq(raw, ",") {
			address := strings.ToLower(strings.TrimSpace(candidate))
			if address == "" {
				continue
			}
			// The address is written into a Sieve script, so a line break or a
			// quote would end the statement and start another one.
			if strings.ContainsAny(address, "\r\n\"\\ ") || !destinationEmailPattern.MatchString(address) {
				return nil, "invalid_destination"
			}
			if seen[address] {
				continue
			}
			seen[address] = true
			out = append(out, address)
		}
	}
	if len(out) == 0 {
		return nil, "invalid_destination"
	}
	if len(out) > maxForwardingDestinations {
		return nil, "too_many_destinations"
	}
	return out, ""
}
