// Per-domain IPv6 address assignment.
package domains

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	"servika/internal/config"
	"servika/internal/dns"
	"servika/internal/httpx"

	"github.com/go-chi/chi/v5"
)

// Refusal reasons. The screen renders twelve languages, so it matches on the
// code and never on the English message.
const (
	reasonIPv6NotLocal = "ipv6_not_local"
	reasonIPv6NotV6    = "ipv6_not_v6"
	reasonIPv6Invalid  = "ipv6_invalid"
)

// SetIPv6 assigns the address this domain answers on over IPv6.
// PUT /domains/{id}/ipv6  body: {"ipv6": "2001:db8::5"}  ("" clears it)
//
// Administrator-only, and not because the value is dangerous to compute: the
// address must genuinely exist on this server, and the operator is the only
// party who knows which addresses those are.
func (h *Handlers) SetIPv6(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)

	var request struct {
		IPv6 string `json:"ipv6"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	value := strings.TrimSpace(request.IPv6)

	if value != "" {
		parsed := net.ParseIP(value)
		if parsed == nil {
			writeReason(w, http.StatusBadRequest, "that is not a valid address", reasonIPv6Invalid)
			return
		}
		if parsed.To4() != nil {
			writeReason(w, http.StatusBadRequest, "that is an IPv4 address", reasonIPv6NotV6)
			return
		}
		// FAIL-CLOSED. An address this server does not answer on, published as a
		// AAAA record, makes the site dead for every IPv6 client while the panel
		// shows a healthy domain, and it stops certificate renewal because
		// Let's Encrypt tries the AAAA first. Both failures are silent.
		if !config.AddressIsLocal(value) {
			writeReason(w, http.StatusBadRequest,
				"that address is not configured on this server", reasonIPv6NotLocal)
			return
		}
		// Stored in the canonical form so the AAAA records the panel writes and
		// the value the verification screen compares against cannot differ by
		// spelling alone.
		value = parsed.String()
	}

	var (
		domainName string
		previous   string
	)
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT domain_name, COALESCE(ipv6,'') FROM domains WHERE id=?`, id).Scan(&domainName, &previous); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			httpx.WriteError(w, http.StatusNotFound, "domain not found")
		} else {
			httpx.WriteError(w, http.StatusInternalServerError, "database operation failed")
		}
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE domains SET ipv6=? WHERE id=?`, value, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not save the address")
		return
	}

	changed, err := dns.RepointIPv6(r.Context(), h.DB, id, domainName, previous, value)
	if err != nil {
		log.Printf("repoint AAAA records for domain %d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError,
			"the address was saved but its DNS records could not be updated")
		return
	}
	// The zone is rewritten even when no record changed: a domain whose zone was
	// edited by hand is brought back into line, and named-checkzone is the gate
	// that refuses a zone this would have broken.
	if err := dns.WriteZone(r.Context(), h.DB, id); err != nil {
		log.Printf("write DNS zone after IPv6 change for domain %d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError,
			"the records were updated but the DNS zone could not be written")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "ipv6": value, "records": changed})
}

// ServerIPv6Addresses lists the globally routable IPv6 addresses of this
// server. GET /system/ipv6-addresses
//
// Without it an operator has to read `ip -6 addr` over SSH and retype an
// address the panel will then refuse, with no way to see what it would accept.
func ServerIPv6Addresses(w http.ResponseWriter, r *http.Request) {
	addresses := config.GlobalIPv6Addresses()
	if addresses == nil {
		addresses = []string{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"addresses":  addresses,
		"has_ipv6":   config.HasIPv6(),
		"server_ip6": config.PublicIPv6(),
	})
}
