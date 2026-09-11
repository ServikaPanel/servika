package mail

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"servika/internal/httpx"

	"github.com/go-chi/chi/v5"
)

// Alias is a domain-scoped mail forwarder row.
type Alias struct {
	ID          int64  `json:"id"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	CatchAll    bool   `json:"catch_all"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
}

var destinationEmailPattern = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// ListAliases returns mail aliases for a domain.
func (h *Handlers) ListAliases(w http.ResponseWriter, r *http.Request) {
	id, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, source, destination, status, DATE_FORMAT(created_at,'%Y-%m-%d %H:%i') FROM mail_aliases WHERE domain_id=? ORDER BY source`, id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list mail aliases")
		return
	}
	defer func() { _ = rows.Close() }()
	out := make([]Alias, 0)
	for rows.Next() {
		var alias Alias
		if err := rows.Scan(&alias.ID, &alias.Source, &alias.Destination, &alias.Status, &alias.CreatedAt); err == nil {
			alias.CatchAll = strings.HasPrefix(alias.Source, "@")
			out = append(out, alias)
		}
	}
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list mail aliases")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// CreateAlias creates a forwarder or catch-all alias for a domain.
func (h *Handlers) CreateAlias(w http.ResponseWriter, r *http.Request) {
	id, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	var req struct {
		LocalPart   string `json:"local_part"`
		Destination string `json:"destination"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var domainName string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT domain_name FROM mail_domains WHERE domain_id=? AND status='active'`, id).Scan(&domainName)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusBadRequest, "enable mail for this domain first")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read mail domain")
		return
	}

	localPart := strings.ToLower(strings.TrimSpace(req.LocalPart))
	var source string
	if localPart == "" {
		source = "@" + domainName
	} else {
		if !localPartPattern.MatchString(localPart) {
			httpx.WriteError(w, http.StatusBadRequest, "invalid alias name")
			return
		}
		source = localPart + "@" + domainName
	}

	destination, validationMessage := normalizeDestination(req.Destination)
	if validationMessage != "" {
		httpx.WriteError(w, http.StatusBadRequest, validationMessage)
		return
	}
	for item := range strings.SplitSeq(destination, ",") {
		if strings.EqualFold(item, source) {
			httpx.WriteError(w, http.StatusBadRequest, "destination cannot match the source address")
			return
		}
	}

	res, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO mail_aliases(domain_id, source, destination) VALUES(?,?,?)`, id, source, destination)
	if err != nil {
		httpx.WriteError(w, http.StatusConflict, "mail alias already exists or could not be created")
		return
	}
	aliasID, _ := res.LastInsertId()
	h.audit(r, "mail.alias.create", source+" -> "+destination, true)
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"id":          aliasID,
		"source":      source,
		"destination": destination,
		"catch_all":   localPart == "",
	})
}

// DeleteAlias removes a mail alias for a domain.
func (h *Handlers) DeleteAlias(w http.ResponseWriter, r *http.Request) {
	id, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	aliasID, _ := strconv.ParseInt(chi.URLParam(r, "aid"), 10, 64)
	var source string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT source FROM mail_aliases WHERE id=? AND domain_id=?`, aliasID, id).Scan(&source); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "mail alias not found")
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`DELETE FROM mail_aliases WHERE id=? AND domain_id=?`, aliasID, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete mail alias")
		return
	}
	h.audit(r, "mail.alias.delete", source, true)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// SetAliasStatus changes a mail alias status.
func (h *Handlers) SetAliasStatus(w http.ResponseWriter, r *http.Request) {
	id, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	aliasID, _ := strconv.ParseInt(chi.URLParam(r, "aid"), 10, 64)
	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req.Status != "active" && req.Status != "suspended") {
		httpx.WriteError(w, http.StatusBadRequest, "invalid status")
		return
	}
	res, err := h.DB.ExecContext(r.Context(),
		`UPDATE mail_aliases SET status=? WHERE id=? AND domain_id=?`, req.Status, aliasID, id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not update mail alias")
		return
	}
	if rowsAffected, _ := res.RowsAffected(); rowsAffected == 0 {
		httpx.WriteError(w, http.StatusNotFound, "mail alias not found")
		return
	}
	h.audit(r, "mail.alias.status", strconv.FormatInt(aliasID, 10), true)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func normalizeDestination(raw string) (string, string) {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]bool, len(parts))
	for _, part := range parts {
		email := strings.ToLower(strings.TrimSpace(part))
		if email == "" {
			continue
		}
		if !destinationEmailPattern.MatchString(email) {
			return "", "invalid destination email address"
		}
		if !seen[email] {
			seen[email] = true
			out = append(out, email)
		}
	}
	if len(out) == 0 {
		return "", "enter at least one destination email address"
	}
	return strings.Join(out, ","), ""
}
