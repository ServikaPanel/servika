package mail

import (
	"net/http"
	"strconv"
	"strings"

	"servika/internal/httpx"
)

// DeliveryEntry is one row as the panel shows it.
type DeliveryEntry struct {
	Timestamp string `json:"timestamp"`
	Direction string `json:"direction"`
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Status    string `json:"status"`
	Reason    string `json:"reason,omitempty"`
}

// deliveryPageSize bounds one response. A busy domain can accumulate tens of
// thousands of rows a day, and returning all of them would be a slow query and
// an unusable screen.
const deliveryPageSize = 200

// DeliveryLog returns a domain's recent deliveries.
// GET /domains/{id}/mail/delivery-log?status=&direction=&search=
//
// The query is scoped by domain_id, which the route's CustomerScope middleware
// has already tied to the caller. Nothing here widens that: every filter narrows
// an already-scoped query.
func (h *Handlers) DeliveryLog(w http.ResponseWriter, r *http.Request) {
	id, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}

	query := `SELECT DATE_FORMAT(ts,'%Y-%m-%d %H:%i:%s'), direction, sender, recipient, status, reason
	            FROM mail_delivery_log WHERE domain_id = ?`
	args := []any{id}

	if status := strings.TrimSpace(r.URL.Query().Get("status")); status != "" {
		if !knownStatuses[status] && status != "rejected" {
			httpx.WriteError(w, http.StatusBadRequest, "unknown status filter")
			return
		}
		query += ` AND status = ?`
		args = append(args, status)
	}
	if direction := strings.TrimSpace(r.URL.Query().Get("direction")); direction != "" {
		if direction != "in" && direction != "out" {
			httpx.WriteError(w, http.StatusBadRequest, "direction must be in or out")
			return
		}
		query += ` AND direction = ?`
		args = append(args, direction)
	}
	if search := strings.TrimSpace(r.URL.Query().Get("search")); search != "" {
		if len(search) > maxAddressLen {
			httpx.WriteError(w, http.StatusBadRequest, "search term is too long")
			return
		}
		// LIKE wildcards are escaped so a search for "%" means the character, not
		// "match everything", and cannot turn into a table scan by accident.
		pattern := "%" + escapeLike(search) + "%"
		query += ` AND (sender LIKE ? ESCAPE '\\' OR recipient LIKE ? ESCAPE '\\')`
		args = append(args, pattern, pattern)
	}

	limit := deliveryPageSize
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > deliveryPageSize {
			httpx.WriteError(w, http.StatusBadRequest, "limit must be between 1 and 200")
			return
		}
		limit = parsed
	}
	query += ` ORDER BY ts DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := h.DB.QueryContext(r.Context(), query, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the delivery log")
		return
	}
	defer func() { _ = rows.Close() }()

	out := make([]DeliveryEntry, 0, limit)
	for rows.Next() {
		var entry DeliveryEntry
		if err := rows.Scan(&entry.Timestamp, &entry.Direction, &entry.Sender,
			&entry.Recipient, &entry.Status, &entry.Reason); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not read the delivery log")
			return
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the delivery log")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// escapeLike neutralises the LIKE metacharacters so the term is matched
// literally. The backslash is escaped first, or it would escape the escapes.
func escapeLike(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "%", `\%`)
	return strings.ReplaceAll(value, "_", `\_`)
}
