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

	"servika/internal/httpx"
	"servika/internal/middleware"
	"servika/internal/panelport"

	"github.com/go-chi/chi/v5"
)

// Handlers serves the server address screen.
type Handlers struct {
	DB *sql.DB
}

// Every change to this server's addresses is serialised with panelport.Lock,
// NOT with a mutex of this package's own.
//
// Both packages change how this server is reached and share one failure: losing
// that access entirely. A port move verifies the new port on an address, so an
// address removed while that verification runs makes the port change look
// responsible for a failure it did not cause. panelport exports Lock and Unlock
// for exactly this and says so; this package held a private mutex instead, which
// left the cross-package guarantee absent and those two functions unreachable.
//
// The guarantee the private mutex did give still holds, because the lock is
// still exclusive: two adds at once would both read the same free label off the
// host and hand one name to two addresses, which is the state the whole remove
// path depends on being impossible.

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
	addresses, err := readHostAddresses(r.Context())
	if err != nil {
		h.fail(w, err, "the host's addresses could not be read")
		return
	}
	bound, err := readBoundAddresses()
	if err != nil {
		// FAIL CLOSED. An unreadable socket table is not evidence that nothing
		// is bound, and "nothing is bound" is the answer that permits every
		// removal.
		h.fail(w, err, "the listening sockets could not be read")
		return
	}

	records, err := h.records(r)
	if err != nil {
		httpx.LogR(r, "server ip records: %v", err)
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

// newAddress is the body POST /system/ips carries.
type newAddress struct {
	IP        string `json:"ip"`
	Prefix    int    `json:"prefix"`
	Interface string `json:"interface"`
	Note      string `json:"note"`
}

// plannedAddress is what the add path decided on: the address, where it goes
// and the panel label that will mark it as this panel's own.
type plannedAddress struct {
	ip     net.IP
	prefix int
	device string
	label  string
	note   string
}

// Add — POST /system/ips (AdminOnly).
func (h *Handlers) Add(w http.ResponseWriter, r *http.Request) {
	body, ok := decodeNewAddress(w, r)
	if !ok {
		return
	}
	ip, err := ValidateNew(body.IP, body.Prefix)
	if err != nil {
		h.fail(w, err, "the address was refused")
		return
	}

	panelport.Lock()
	defer panelport.Unlock()

	// The HOST is scanned, not the table. An address somebody added by hand is
	// absent from the table and present on the server, and adding it again
	// would either fail at the kernel or, worse, succeed and leave the panel
	// believing it owns an address it did not put there.
	existing, err := readHostAddresses(r.Context())
	if err != nil {
		h.fail(w, err, "the host's addresses could not be read")
		return
	}
	plan, ok := h.planAddress(w, existing, ip, body)
	if !ok {
		return
	}
	id, ok := h.recordAddress(w, r, plan)
	if !ok {
		return
	}
	h.activate(w, r, id, plan)
}

// decodeNewAddress reads the request body and fills in the defaults. A missing
// prefix is a single address, not a whole network, and a note longer than its
// column is cut rather than refused.
func decodeNewAddress(w http.ResponseWriter, r *http.Request) (newAddress, bool) {
	var body newAddress
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return newAddress{}, false
	}
	if body.Prefix == 0 {
		body.Prefix = 32
	}
	if len(body.Note) > 255 {
		body.Note = body.Note[:255]
	}
	return body, true
}

// planAddress decides where the address goes and under which label. It writes
// the refusal itself and answers false when the host cannot take the address.
func (h *Handlers) planAddress(w http.ResponseWriter, existing []Address,
	ip net.IP, body newAddress) (plannedAddress, bool) {
	device := strings.TrimSpace(body.Interface)
	if device == "" {
		device = defaultInterface(existing)
	}
	if !knownInterface(existing, device) {
		writeRefusal(w, http.StatusConflict, ReasonUnknownIface,
			"this server has no interface named "+device)
		return plannedAddress{}, false
	}
	for _, address := range existing {
		if address.IP == ip.String() {
			writeRefusal(w, http.StatusConflict, ReasonAlreadyOnHost,
				ip.String()+" is already configured on this server")
			return plannedAddress{}, false
		}
	}
	label, err := NextLabel(existing)
	if err != nil {
		h.fail(w, err, "no address label is available")
		return plannedAddress{}, false
	}
	return plannedAddress{
		ip: ip, prefix: body.Prefix, device: device, label: label, note: body.Note,
	}, true
}

// recordAddress writes the row that claims the label.
func (h *Handlers) recordAddress(w http.ResponseWriter, r *http.Request, plan plannedAddress) (int64, bool) {
	var actor any
	if uid := actorOf(r); uid > 0 {
		actor = uid
	}
	result, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO server_ips (ip, interface, prefix_length, label, note, created_by)
		 VALUES (?,?,?,?,?,?)`,
		plan.ip.String(), plan.device, plan.prefix, plan.label, plan.note, actor)
	if err != nil {
		httpx.LogR(r, "server ip insert: %v", err)
		httpx.WriteError(w, http.StatusConflict, "this address is already recorded")
		return 0, false
	}
	id, _ := result.LastInsertId()
	return id, true
}

// activate puts the recorded address on the host and writes the boot script.
//
// The row was written first so the label is claimed, then the host change, then
// the boot script. A failure at the host change takes the row back out, because
// a row for an address the server does not have would put that address on at
// the next reboot.
func (h *Handlers) activate(w http.ResponseWriter, r *http.Request, id int64, plan plannedAddress) {
	if err := addToHost(r.Context(), plan.ip, plan.prefix, plan.device, plan.label); err != nil {
		h.forget(r, id)
		h.fail(w, err, "the address could not be added")
		return
	}
	answer := map[string]any{
		"id": id, "ip": plan.ip.String(), "interface": plan.device, "label": plan.label,
	}
	if err := writePersistence(r.Context(), h.DB); err != nil {
		httpx.LogR(r, "server ip persistence: %v", err)
		// The address IS live; it is the reboot that is not covered. Saying so
		// is the whole point, because the alternative is an operator who finds
		// out at the next restart.
		answer["warning"] = "the address is active but could not be recorded for the next reboot"
	}
	httpx.WriteJSON(w, http.StatusOK, answer)
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

	panelport.Lock()
	defer panelport.Unlock()

	row, ok := h.addressRow(w, r, id)
	if !ok {
		return
	}

	addresses, err := readHostAddresses(r.Context())
	if err != nil {
		h.fail(w, err, "the host's addresses could not be read")
		return
	}
	bound, err := readBoundAddresses()
	if err != nil {
		h.fail(w, err, "the listening sockets could not be read")
		return
	}

	found := hostAddressOf(addresses, row)
	if found.IP == "" {
		// The host no longer has it. Removing the row and rewriting the boot
		// script is the whole remaining job, and it is the right one: the
		// alternative leaves a script that puts back an address somebody
		// already took away by hand.
		h.forget(r, id)
		if err := writePersistence(r.Context(), h.DB); err != nil {
			httpx.LogR(r, "server ip persistence: %v", err)
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"removed": id, "was_absent": true})
		return
	}
	if err := Removable(found, bound); err != nil {
		h.fail(w, err, "the address cannot be removed")
		return
	}
	if err := removeFromHost(r.Context(), found); err != nil {
		h.fail(w, err, "the address could not be removed")
		return
	}
	h.forget(r, id)
	h.reportRemoval(w, r, id)
}

// recorded is what the table says about one address.
type recorded struct {
	ip     string
	device string
	prefix int
}

// addressRow reads the row a removal names. A lookup that FAILED is reported as
// a failure rather than as a missing address: telling an operator their row is
// gone when it is not sends them looking in the wrong place.
func (h *Handlers) addressRow(w http.ResponseWriter, r *http.Request, id int64) (recorded, bool) {
	var row recorded
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT ip, interface, prefix_length FROM server_ips WHERE id=?`, id).
		Scan(&row.ip, &row.device, &row.prefix)
	if errors.Is(err, sql.ErrNoRows) {
		writeRefusal(w, http.StatusNotFound, ReasonNotFound, "no such address")
		return recorded{}, false
	}
	if err != nil {
		httpx.LogR(r, "server ip lookup %d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "database query failed")
		return recorded{}, false
	}
	return row, true
}

// hostAddressOf finds the row's address as the HOST reports it, never as the
// row describes it. The row says what the panel believes; the label on the host
// is what proves the panel put it there, and only the second can be trusted
// when the two disagree. An empty IP means the host no longer carries it.
func hostAddressOf(addresses []Address, row recorded) Address {
	for _, address := range addresses {
		if address.IP == row.ip && address.Interface == row.device {
			return address
		}
	}
	return Address{}
}

// reportRemoval writes the boot script and answers. The address is already
// gone, so a script that could not be rewritten is a warning beside a success
// rather than a failure.
func (h *Handlers) reportRemoval(w http.ResponseWriter, r *http.Request, id int64) {
	answer := map[string]any{"removed": id}
	if err := writePersistence(r.Context(), h.DB); err != nil {
		httpx.LogR(r, "server ip persistence: %v", err)
		answer["warning"] = "the address is gone but the reboot script could not be rewritten"
	}
	httpx.WriteJSON(w, http.StatusOK, answer)
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
