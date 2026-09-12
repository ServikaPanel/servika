package mail

import (
	"context"
	"net/http"
	"net/url"
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

	query, args, limit, reason := deliveryLogQuery(id, r.URL.Query())
	if reason != "" {
		httpx.WriteError(w, http.StatusBadRequest, reason)
		return
	}

	out, err := h.readDeliveryEntries(r.Context(), query, args, limit)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the delivery log")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// deliveryLogQuery builds the domain-scoped query and its bound values from the
// filters, and returns the reason a filter is refused.
func deliveryLogQuery(domainID int64, values url.Values) (string, []any, int, string) {
	query := `SELECT DATE_FORMAT(ts,'%Y-%m-%d %H:%i:%s'), direction, sender, recipient, status, reason
	            FROM mail_delivery_log WHERE domain_id = ?`
	args := []any{domainID}

	clauses, clauseArgs, reason := deliveryLogFilters(values)
	if reason != "" {
		return "", nil, 0, reason
	}
	limit, reason := deliveryLogLimit(values.Get("limit"))
	if reason != "" {
		return "", nil, 0, reason
	}
	query += clauses + ` ORDER BY ts DESC, id DESC LIMIT ?`
	args = append(append(args, clauseArgs...), limit)
	return query, args, limit, ""
}

// deliveryLogFilters turns the status, direction and search parameters into
// clauses with bound values. Every clause narrows the already-scoped query.
func deliveryLogFilters(values url.Values) (string, []any, string) {
	var clauses string
	var args []any
	if status := strings.TrimSpace(values.Get("status")); status != "" {
		if !knownStatuses[status] && status != "rejected" {
			return "", nil, "unknown status filter"
		}
		clauses += ` AND status = ?`
		args = append(args, status)
	}
	if direction := strings.TrimSpace(values.Get("direction")); direction != "" {
		if direction != "in" && direction != "out" {
			return "", nil, "direction must be in or out"
		}
		clauses += ` AND direction = ?`
		args = append(args, direction)
	}
	if search := strings.TrimSpace(values.Get("search")); search != "" {
		if len(search) > maxAddressLen {
			return "", nil, "search term is too long"
		}
		// LIKE wildcards are escaped so a search for "%" means the character, not
		// "match everything", and cannot turn into a table scan by accident.
		pattern := "%" + escapeLike(search) + "%"
		clauses += ` AND (sender LIKE ? ESCAPE '\\' OR recipient LIKE ? ESCAPE '\\')`
		args = append(args, pattern, pattern)
	}
	return clauses, args, ""
}

// deliveryLogLimit reads the page size, one page when it is absent.
func deliveryLogLimit(raw string) (int, string) {
	if raw == "" {
		return deliveryPageSize, ""
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed < 1 || parsed > deliveryPageSize {
		return 0, "limit must be between 1 and 200"
	}
	return parsed, ""
}

// readDeliveryEntries runs the query and reads every row it answers.
func (h *Handlers) readDeliveryEntries(ctx context.Context, query string, args []any, limit int) ([]DeliveryEntry, error) {
	// #nosec G701 -- deliveryLogQuery pastes only constant clauses into the text; every filter value, including the LIKE pattern, is bound as a placeholder.
	rows, err := h.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := make([]DeliveryEntry, 0, limit)
	for rows.Next() {
		var entry DeliveryEntry
		if err := rows.Scan(&entry.Timestamp, &entry.Direction, &entry.Sender,
			&entry.Recipient, &entry.Status, &entry.Reason); err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// escapeLike neutralises the LIKE metacharacters so the term is matched
// literally. The backslash is escaped first, or it would escape the escapes.
func escapeLike(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "%", `\%`)
	return strings.ReplaceAll(value, "_", `\_`)
}
