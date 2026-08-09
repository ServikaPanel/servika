// Per-domain maintenance mode: the switch, the page fields and the addresses
// that reach the real site while it is on.
package domains

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	"servika/internal/httpx"
	"servika/internal/provisioner"

	"github.com/go-chi/chi/v5"
)

// Refusal reasons. The screen renders twelve languages, so it matches on the
// code and never on the English message.
const (
	reasonMaintenanceCustomVhost  = "maintenance_custom_vhost"
	reasonMaintenanceRedirectOnly = "maintenance_redirect_only"
	reasonMaintenanceBadAddress   = "maintenance_bad_address"
	reasonMaintenanceTooManyIPs   = "maintenance_too_many_ips"
)

// maxMaintenanceIPs bounds the exception list. Every address ends up in one
// nginx regex, and an unbounded list would grow a configuration line without
// limit for no benefit the feature ever needs.
const maxMaintenanceIPs = 20

// Field ceilings match the column widths in migrations/0088_maintenance.sql.
const (
	maxMaintenanceTitle   = 160
	maxMaintenanceMessage = 600
	maxMaintenanceLogoURL = 512
)

type maintenanceIP struct {
	ID        int64  `json:"id"`
	IP        string `json:"ip"`
	Note      string `json:"note"`
	CreatedAt string `json:"created_at"`
}

type maintenanceStatus struct {
	Enabled bool   `json:"enabled"`
	Until   string `json:"until"` // MySQL-formatted, empty when open-ended
	Title   string `json:"title"`
	Message string `json:"message"`
	Accent  string `json:"accent"`
	LogoURL string `json:"logo_url"`
	// ClientIP is the address this request arrived from, so the screen can
	// offer it as a one-click exception instead of asking the customer to find
	// out what their own address is.
	ClientIP string `json:"client_ip"`
	// Available reports whether the mode can be turned on at all. A domain the
	// panel does not render the vhost for cannot carry the fragment, and saying
	// so up front is better than a refusal after the customer fills the form.
	Available bool            `json:"available"`
	Reason    string          `json:"reason,omitempty"`
	IPs       []maintenanceIP `json:"ips"`
}

// MaintenanceStatus reports the mode and its page fields.
// GET /domains/{id}/maintenance
func (h *Handlers) MaintenanceStatus(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)

	var (
		status  maintenanceStatus
		enabled int
		until   sql.NullString
	)
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT COALESCE(maintenance_enabled,0), DATE_FORMAT(maintenance_until,'%Y-%m-%d %H:%i'),
		        COALESCE(maintenance_title,''), COALESCE(maintenance_message,''),
		        COALESCE(maintenance_accent,''), COALESCE(maintenance_logo_url,'')
		   FROM domains WHERE id=?`, id).
		Scan(&enabled, &until, &status.Title, &status.Message, &status.Accent, &status.LogoURL); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			httpx.WriteError(w, http.StatusNotFound, "domain not found")
		} else {
			httpx.WriteError(w, http.StatusInternalServerError, "database operation failed")
		}
		return
	}
	status.Enabled = enabled == 1
	status.Until = until.String
	status.ClientIP = httpx.ClientIP(r)

	reason, err := maintenanceUnavailable(r, h.DB, id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database operation failed")
		return
	}
	status.Available = reason == ""
	status.Reason = reason

	list, err := maintenanceIPs(r, h.DB, id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database operation failed")
		return
	}
	status.IPs = list

	httpx.WriteJSON(w, http.StatusOK, status)
}

// MaintenanceSave turns the mode on or off and stores the page fields.
// PUT /domains/{id}/maintenance
func (h *Handlers) MaintenanceSave(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)

	var request struct {
		Enabled bool   `json:"enabled"`
		Title   string `json:"title"`
		Message string `json:"message"`
		Accent  string `json:"accent"`
		LogoURL string `json:"logo_url"`
		// DurationMinutes is a DURATION, never an absolute time. The value is
		// applied with DATE_ADD(NOW(), ...) so the deadline is computed by the
		// same clock and timezone that later compares it, which an absolute
		// timestamp from a browser would not be. 0 means open-ended.
		DurationMinutes int `json:"duration_minutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// The domain has to exist before anything is written: WriteMaintenancePage
	// would otherwise leave a file for an id that names nothing.
	var exists int
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT 1 FROM domains WHERE id=?`, id).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			httpx.WriteError(w, http.StatusNotFound, "domain not found")
		} else {
			httpx.WriteError(w, http.StatusInternalServerError, "database operation failed")
		}
		return
	}

	// Refused on the WRITE path, not only where the screen draws the switch.
	// Accepting it and rendering nothing would leave the panel reporting the
	// site as closed while it kept serving every visitor.
	if request.Enabled {
		reason, err := maintenanceUnavailable(r, h.DB, id)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "database operation failed")
			return
		}
		if reason != "" {
			writeReason(w, http.StatusConflict, maintenanceUnavailableMessage(reason), reason)
			return
		}
	}

	page := provisioner.MaintenancePage{
		Title:   sanitizeLine(request.Title, maxMaintenanceTitle),
		Message: sanitizeText(request.Message, maxMaintenanceMessage),
		Accent:  strings.TrimSpace(request.Accent),
		LogoURL: sanitizeLine(request.LogoURL, maxMaintenanceLogoURL),
	}

	// The page file is written BEFORE the vhost points at it. The other order
	// leaves a window in which nginx serves a location whose file is absent.
	if err := provisioner.WriteMaintenancePage(id, page); err != nil {
		log.Printf("write maintenance page for domain %d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the maintenance page could not be written")
		return
	}

	duration := request.DurationMinutes
	if duration < 0 {
		duration = 0
	}
	const maxDurationMinutes = 60 * 24 * 30 // a month; beyond that the mode is not a window
	if duration > maxDurationMinutes {
		duration = maxDurationMinutes
	}

	var err error
	switch {
	case !request.Enabled:
		_, err = h.DB.ExecContext(r.Context(),
			`UPDATE domains SET maintenance_enabled=0, maintenance_until=NULL,
			        maintenance_title=?, maintenance_message=?, maintenance_accent=?, maintenance_logo_url=?
			  WHERE id=?`,
			page.Title, page.Message, page.Accent, page.LogoURL, id)
	case duration == 0:
		_, err = h.DB.ExecContext(r.Context(),
			`UPDATE domains SET maintenance_enabled=1, maintenance_until=NULL,
			        maintenance_title=?, maintenance_message=?, maintenance_accent=?, maintenance_logo_url=?
			  WHERE id=?`,
			page.Title, page.Message, page.Accent, page.LogoURL, id)
	default:
		_, err = h.DB.ExecContext(r.Context(),
			`UPDATE domains SET maintenance_enabled=1,
			        maintenance_until=DATE_ADD(NOW(), INTERVAL ? MINUTE),
			        maintenance_title=?, maintenance_message=?, maintenance_accent=?, maintenance_logo_url=?
			  WHERE id=?`,
			duration, page.Title, page.Message, page.Accent, page.LogoURL, id)
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the maintenance settings could not be saved")
		return
	}

	if err := provisioner.RerenderVhost(h.DB, id); err != nil {
		log.Printf("rerender vhost after maintenance change for domain %d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError,
			"the settings were saved but the web server configuration could not be applied")
		return
	}

	h.MaintenanceStatus(w, r)
}

// MaintenanceIPAdd records an address that reaches the real site.
// POST /domains/{id}/maintenance/ips
//
// An empty ip field means "the address I am calling from", which is what the
// customer wants nearly every time and what they would otherwise have to look
// up elsewhere and retype.
func (h *Handlers) MaintenanceIPAdd(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)

	var request struct {
		IP   string `json:"ip"`
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	value := strings.TrimSpace(request.IP)
	if value == "" {
		value = httpx.ClientIP(r)
	}
	parsed := net.ParseIP(value)
	if parsed == nil {
		writeReason(w, http.StatusBadRequest, "that is not a valid IP address", reasonMaintenanceBadAddress)
		return
	}

	// Counted before the insert, and a count error DENIES rather than proceeds:
	// the ceiling exists to bound one nginx configuration line, and a guard that
	// passes on an unreadable count is not a ceiling.
	var count int
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM domain_maintenance_ips WHERE domain_id=?`, id).Scan(&count); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database operation failed")
		return
	}
	if count >= maxMaintenanceIPs {
		writeReason(w, http.StatusBadRequest,
			"the exception list already holds "+strconv.Itoa(maxMaintenanceIPs)+" addresses",
			reasonMaintenanceTooManyIPs)
		return
	}

	// Stored canonical, because the vhost compares it against $remote_addr as
	// text and nginx renders an address in its canonical form.
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT IGNORE INTO domain_maintenance_ips(domain_id, ip, note) VALUES(?,?,?)`,
		id, parsed.String(), sanitizeLine(request.Note, 120)); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the address could not be added")
		return
	}
	if err := provisioner.RerenderVhost(h.DB, id); err != nil {
		log.Printf("rerender vhost after maintenance ip add for domain %d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError,
			"the address was added but the web server configuration could not be applied")
		return
	}
	h.MaintenanceStatus(w, r)
}

// MaintenanceIPDelete removes one exception address.
// DELETE /domains/{id}/maintenance/ips/{ipid}
func (h *Handlers) MaintenanceIPDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ipID, _ := strconv.ParseInt(chi.URLParam(r, "ipid"), 10, 64)

	// The domain_id term is the scope check: an id alone would let one domain's
	// request delete another domain's row.
	if _, err := h.DB.ExecContext(r.Context(),
		`DELETE FROM domain_maintenance_ips WHERE id=? AND domain_id=?`, ipID, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the address could not be removed")
		return
	}
	if err := provisioner.RerenderVhost(h.DB, id); err != nil {
		log.Printf("rerender vhost after maintenance ip delete for domain %d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError,
			"the address was removed but the web server configuration could not be applied")
		return
	}
	h.MaintenanceStatus(w, r)
}

// maintenanceIPs reads one domain's exception list.
func maintenanceIPs(r *http.Request, db *sql.DB, domainID int64) ([]maintenanceIP, error) {
	rows, err := db.QueryContext(r.Context(),
		`SELECT id, ip, note, DATE_FORMAT(created_at,'%Y-%m-%d %H:%i')
		   FROM domain_maintenance_ips WHERE domain_id=? ORDER BY id`, domainID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	list := make([]maintenanceIP, 0)
	for rows.Next() {
		var entry maintenanceIP
		if err := rows.Scan(&entry.ID, &entry.IP, &entry.Note, &entry.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, entry)
	}
	return list, rows.Err()
}

// maintenanceUnavailable reports why the mode cannot be turned on, or "".
//
// Both shapes render a vhost the fragment never reaches: a custom vhost is
// written out verbatim, and a redirect-only domain uses a different template
// entirely. Storing the switch for either would leave the screen saying the
// site is closed while every visitor still gets through.
func maintenanceUnavailable(r *http.Request, db *sql.DB, domainID int64) (string, error) {
	var custom int
	if err := db.QueryRowContext(r.Context(),
		`SELECT COALESCE(custom_vhost_enabled,0) FROM domains WHERE id=?`, domainID).Scan(&custom); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil // the caller already reported the missing domain
		}
		return "", err
	}
	if custom == 1 {
		return reasonMaintenanceCustomVhost, nil
	}

	var redirects int
	if err := db.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM domain_redirects WHERE domain_id=?`, domainID).Scan(&redirects); err != nil {
		return "", err
	}
	if redirects > 0 {
		return reasonMaintenanceRedirectOnly, nil
	}
	return "", nil
}

// maintenanceUnavailableMessage is the English sentence beside the code.
func maintenanceUnavailableMessage(reason string) string {
	switch reason {
	case reasonMaintenanceCustomVhost:
		return "this domain serves a custom nginx configuration, which the panel does not modify"
	case reasonMaintenanceRedirectOnly:
		return "this domain only redirects, so it has no site to put into maintenance"
	}
	return "maintenance mode is not available for this domain"
}

// sanitizeLine trims a single-line field and cuts control characters.
func sanitizeLine(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || r < 0x20 {
			return -1
		}
		return r
	}, value)
	return truncateRunes(strings.TrimSpace(value), limit)
}

// sanitizeText keeps line breaks (the page renders them) but drops the other
// control characters and normalises CRLF, so a paste from a text editor does
// not change how the stored value compares to itself.
func sanitizeText(value string, limit int) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.Map(func(r rune) rune {
		if r == '\n' {
			return r
		}
		if r == '\r' || r == '\t' || r < 0x20 {
			return -1
		}
		return r
	}, value)
	return truncateRunes(strings.TrimSpace(value), limit)
}

// truncateRunes cuts to a rune count, never a byte count: the columns are
// utf8mb4 and cutting mid-rune would store a broken character.
func truncateRunes(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}
