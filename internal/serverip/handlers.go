package serverip

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"servika/internal/httpx"
	"servika/internal/middleware"

	"github.com/go-chi/chi/v5"
)

// Handlers serves the server address screen.
type Handlers struct {
	DB *sql.DB
}

// writing serialises every change to this server's addresses.
//
// It is a PACKAGE-level lock rather than a field, because the thing being
// protected is the host, not a handler instance. Two adds at once would both
// read the same free label off the host and hand one name to two addresses,
// which is the state the whole remove path depends on being impossible.
var writing sync.Mutex

func actorOf(r *http.Request) int64 {
	if claims := middleware.ClaimsFrom(r); claims != nil {
		return claims.UserID
	}
	return 0
}

// writeRefusal answers with a stable reason CODE beside the English message,
// because the screen writes the sentence in twelve languages.
func writeRefusal(w http.ResponseWriter, status int, reason, message string) {
	httpx.WriteJSON(w, status, map[string]string{"error": message, "reason": reason})
}

func (h *Handlers) fail(w http.ResponseWriter, err error, fallback string) {
	if reason := ReasonOf(err); reason != "" {
		writeRefusal(w, http.StatusConflict, reason, err.Error())
		return
	}
	log.Printf("server ip: %v", err)
	httpx.WriteError(w, http.StatusInternalServerError, fallback)
}

// record is what the panel's table remembers about an address it added.
type record struct {
	ID    int64  `json:"id"`
	Note  string `json:"note"`
	Added string `json:"added_at"`
}

// listed is one row of the screen: what the host has, plus what the panel knows
// about it, plus whether it can be removed and why not.
type listed struct {
	Address
	Record        *record `json:"record,omitempty"`
	Removable     bool    `json:"removable"`
	RefusalReason string  `json:"refusal_reason,omitempty"`
}

// List — GET /system/ips (AdminOnly).
//
// The list comes off the HOST and is annotated from the table, never the other
// way round. An address configured outside the panel is the one that must be
// shown and must not be removable, and it exists in no table this owns.
func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	addresses, err := HostAddresses(r.Context())
	if err != nil {
		h.fail(w, err, "the host's addresses could not be read")
		return
	}
	bound, err := BoundAddresses()
	if err != nil {
		// FAIL CLOSED. An unreadable socket table is not evidence that nothing
		// is bound, and "nothing is bound" is the answer that permits every
		// removal.
		h.fail(w, err, "the listening sockets could not be read")
		return
	}

	records, err := h.records(r)
	if err != nil {
		log.Printf("server ip records: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database query failed")
		return
	}

	out := make([]listed, 0, len(addresses))
	for _, address := range addresses {
		if !Assignable(net.ParseIP(address.IP)) {
			continue
		}
		row := listed{Address: address}
		if known, ok := records[address.IP]; ok {
			copied := known
			row.Record = &copied
		}
		if err := Removable(address, bound); err != nil {
			row.RefusalReason = ReasonOf(err)
		} else {
			row.Removable = true
		}
		out = append(out, row)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"addresses": out})
}

func (h *Handlers) records(r *http.Request) (map[string]record, error) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, ip, note, created_at FROM server_ips`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := map[string]record{}
	for rows.Next() {
		var found record
		var ip string
		if err := rows.Scan(&found.ID, &ip, &found.Note, &found.Added); err != nil {
			return nil, err
		}
		out[ip] = found
	}
	return out, rows.Err()
}

// Add — POST /system/ips (AdminOnly).
func (h *Handlers) Add(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP        string `json:"ip"`
		Prefix    int    `json:"prefix"`
		Interface string `json:"interface"`
		Note      string `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Prefix == 0 {
		body.Prefix = 32
	}
	ip, err := ValidateNew(body.IP, body.Prefix)
	if err != nil {
		h.fail(w, err, "the address was refused")
		return
	}
	if len(body.Note) > 255 {
		body.Note = body.Note[:255]
	}

	writing.Lock()
	defer writing.Unlock()

	// The HOST is scanned, not the table. An address somebody added by hand is
	// absent from the table and present on the server, and adding it again
	// would either fail at the kernel or, worse, succeed and leave the panel
	// believing it owns an address it did not put there.
	existing, err := HostAddresses(r.Context())
	if err != nil {
		h.fail(w, err, "the host's addresses could not be read")
		return
	}
	device := strings.TrimSpace(body.Interface)
	if device == "" {
		device = defaultInterface(existing)
	}
	if !knownInterface(existing, device) {
		writeRefusal(w, http.StatusConflict, ReasonUnknownIface,
			"this server has no interface named "+device)
		return
	}
	for _, address := range existing {
		if address.IP == ip.String() {
			writeRefusal(w, http.StatusConflict, ReasonAlreadyOnHost,
				ip.String()+" is already configured on this server")
			return
		}
	}

	label, err := NextLabel(existing)
	if err != nil {
		h.fail(w, err, "no address label is available")
		return
	}

	var actor any
	if uid := actorOf(r); uid > 0 {
		actor = uid
	}
	result, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO server_ips (ip, interface, prefix_length, label, note, created_by)
		 VALUES (?,?,?,?,?,?)`,
		ip.String(), device, body.Prefix, label, body.Note, actor)
	if err != nil {
		log.Printf("server ip insert: %v", err)
		httpx.WriteError(w, http.StatusConflict, "this address is already recorded")
		return
	}
	id, _ := result.LastInsertId()

	// The row is written first so the label is claimed, then the host change,
	// then the boot script. A failure after this point takes the row back out,
	// because a row for an address the server does not have would put that
	// address on at the next reboot.
	if err := AddToHost(r.Context(), ip, body.Prefix, device, label); err != nil {
		h.forget(r, id)
		h.fail(w, err, "the address could not be added")
		return
	}
	if err := WritePersistence(r.Context(), h.DB); err != nil {
		log.Printf("server ip persistence: %v", err)
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"id": id, "ip": ip.String(), "interface": device, "label": label,
			// The address IS live; it is the reboot that is not covered. Saying
			// so is the whole point, because the alternative is an operator who
			// finds out at the next restart.
			"warning": "the address is active but could not be recorded for the next reboot",
		})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"id": id, "ip": ip.String(), "interface": device, "label": label,
	})
}

func (h *Handlers) forget(r *http.Request, id int64) {
	if _, err := h.DB.ExecContext(r.Context(), `DELETE FROM server_ips WHERE id=?`, id); err != nil {
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		log.Printf("server ip rollback %d: %v", id, err)
	}
}

// Remove — DELETE /system/ips/{id} (AdminOnly).
func (h *Handlers) Remove(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid address id")
		return
	}

	writing.Lock()
	defer writing.Unlock()

	var ip, device string
	var prefix int
	err = h.DB.QueryRowContext(r.Context(),
		`SELECT ip, interface, prefix_length FROM server_ips WHERE id=?`, id).
		Scan(&ip, &device, &prefix)
	if errors.Is(err, sql.ErrNoRows) {
		writeRefusal(w, http.StatusNotFound, ReasonNotFound, "no such address")
		return
	}
	if err != nil {
		log.Printf("server ip lookup %d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "database query failed")
		return
	}

	addresses, err := HostAddresses(r.Context())
	if err != nil {
		h.fail(w, err, "the host's addresses could not be read")
		return
	}
	bound, err := BoundAddresses()
	if err != nil {
		h.fail(w, err, "the listening sockets could not be read")
		return
	}

	// The address is checked as the HOST reports it, never as the row
	// describes it. The row says what the panel believes; the label on the host
	// is what proves the panel put it there, and only the second can be trusted
	// when the two disagree.
	found := Address{}
	for _, address := range addresses {
		if address.IP == ip && address.Interface == device {
			found = address
			break
		}
	}
	if found.IP == "" {
		// The host no longer has it. Removing the row and rewriting the boot
		// script is the whole remaining job, and it is the right one: the
		// alternative leaves a script that puts back an address somebody
		// already took away by hand.
		h.forget(r, id)
		if err := WritePersistence(r.Context(), h.DB); err != nil {
			log.Printf("server ip persistence: %v", err)
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"removed": id, "was_absent": true})
		return
	}
	if err := Removable(found, bound); err != nil {
		h.fail(w, err, "the address cannot be removed")
		return
	}
	if err := RemoveFromHost(r.Context(), found); err != nil {
		h.fail(w, err, "the address could not be removed")
		return
	}
	h.forget(r, id)
	if err := WritePersistence(r.Context(), h.DB); err != nil {
		log.Printf("server ip persistence: %v", err)
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"removed": id,
			"warning": "the address is gone but the reboot script could not be rewritten",
		})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"removed": id})
}

// defaultInterface picks the device carrying the first routable address, which
// is where an operator adding a second address almost always wants it.
func defaultInterface(addresses []Address) string {
	for _, address := range addresses {
		if address.Scope == "global" && Assignable(net.ParseIP(address.IP)) {
			return address.Interface
		}
	}
	return ""
}

func knownInterface(addresses []Address, device string) bool {
	if !ValidInterface(device) {
		return false
	}
	for _, address := range addresses {
		if address.Interface == device {
			return true
		}
	}
	return false
}
