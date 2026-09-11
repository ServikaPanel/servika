package domains

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"servika/internal/diskusage"
	"servika/internal/httpx"

	"github.com/go-chi/chi/v5"
)

// CalculateDisk measures the domain home directory and stores its size in kilobytes.
func (h *Handlers) CalculateDisk(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var systemUser string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user FROM domains WHERE id=?`, id).
		Scan(&systemUser)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database operation failed")
		return
	}
	if !strings.HasPrefix(systemUser, "c_") {
		httpx.WriteError(w, http.StatusBadRequest, "invalid system user")
		return
	}
	path := "/home/" + systemUser
	size, err := diskusage.Bytes(r.Context(), path)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "disk usage calculation failed")
		return
	}
	kb := size / 1024
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE domains SET size_kb=? WHERE id=?`, kb, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database update failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"id":      id,
		"size_kb": kb,
		"path":    path,
	})
}
