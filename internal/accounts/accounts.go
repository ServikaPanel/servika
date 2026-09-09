// Package accounts provides customer account CRUD handlers.
package accounts

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"servika/internal/httpx"
	"servika/internal/middleware"
	"servika/internal/quota"

	"github.com/go-chi/chi/v5"
)

// Customer describes a customer account.
type Customer struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	PlanID  *int64 `json:"plan_id"`
	Status  string `json:"status"`
	Notes   string `json:"notes"`
	Created string `json:"created_at"`
}

// customerListItem is what the list returns: a Customer plus the reseller that
// owns it.
//
// It is a separate type rather than a field on Customer because Customer is the
// DECODE target of create and update, where the owner is derived from the
// caller's own identity. A field there would be one a request body could set and
// the handler would silently drop.
type customerListItem struct {
	Customer
	// OwnerUserID is null for a customer that sits directly under an
	// administrator. The domain create form groups the list by this value.
	OwnerUserID *int64 `json:"owner_user_id"`
}

// Handlers provides customer account HTTP handlers.
type Handlers struct {
	DB *sql.DB
}

// ListCustomers returns all customer accounts.
func (h *Handlers) ListCustomers(w http.ResponseWriter, r *http.Request) {
	// A reseller sees only its own customers (customers.owner_user_id).
	q := `SELECT id, name, email, plan_id, status, notes, DATE_FORMAT(created_at,'%Y-%m-%d'), owner_user_id
	      FROM customers`
	var arg []any
	if c := middleware.ClaimsFrom(r); c != nil && c.Role == middleware.RoleReseller {
		q += ` WHERE owner_user_id = ?`
		arg = append(arg, c.UserID)
	}
	q += ` ORDER BY id`

	rows, err := h.DB.QueryContext(r.Context(), q, arg...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "customers could not be listed")
		return
	}
	defer func() { _ = rows.Close() }()
	out := make([]customerListItem, 0)
	for rows.Next() {
		var cs customerListItem
		if err := rows.Scan(&cs.ID, &cs.Name, &cs.Email, &cs.PlanID, &cs.Status, &cs.Notes, &cs.Created, &cs.OwnerUserID); err == nil {
			out = append(out, cs)
		}
	}
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "customer list failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// CreateCustomer creates a customer account.
func (h *Handlers) CreateCustomer(w http.ResponseWriter, r *http.Request) {
	var cs Customer
	if err := json.NewDecoder(r.Body).Decode(&cs); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if cs.Name == "" || cs.Email == "" {
		httpx.WriteError(w, http.StatusBadRequest, "name and email are required")
		return
	}
	if cs.Status == "" {
		cs.Status = "active"
	}

	// Ownership: a customer a reseller creates is bound to it; a customer an
	// admin creates is unowned (belongs directly to admin). A reseller's quota
	// is also enforced here.
	var owner any
	if c := middleware.ClaimsFrom(r); c != nil && c.Role == middleware.RoleReseller {
		if err := quota.CheckResellerCustomerAllowed(r.Context(), h.DB, c.UserID); err != nil {
			if le, ok := errors.AsType[*quota.LimitError](err); ok {
				httpx.WriteError(w, http.StatusForbidden, le.Message)
				return
			}
			httpx.WriteError(w, http.StatusInternalServerError, "could not verify reseller limit")
			return
		}
		owner = c.UserID
	}

	res, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO customers(name, email, plan_id, status, notes, owner_user_id) VALUES(?,?,?,?,?,?)`,
		cs.Name, cs.Email, cs.PlanID, cs.Status, cs.Notes, owner)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "customer could not be created")
		return
	}
	cs.ID, _ = res.LastInsertId()
	httpx.WriteJSON(w, http.StatusCreated, cs)
}

// UpdateCustomer updates a customer account.
// authorized reports whether the caller may act on this customer: admin on any,
// a reseller only on its own. A missing record is also false (so a reseller
// cannot probe existence by id).
func (h *Handlers) authorized(r *http.Request, customerID int64) bool {
	c := middleware.ClaimsFrom(r)
	if c == nil {
		return false
	}
	if c.Role == middleware.RoleAdmin {
		return true
	}
	if c.Role != middleware.RoleReseller {
		return false
	}
	return middleware.ResellerOwnsCustomer(r, c.UserID, customerID)
}

func (h *Handlers) UpdateCustomer(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if !h.authorized(r, id) {
		httpx.WriteError(w, http.StatusForbidden, "no access to this customer")
		return
	}
	var cs Customer
	if err := json.NewDecoder(r.Body).Decode(&cs); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE customers SET name=?, email=?, plan_id=?, status=?, notes=? WHERE id=?`,
		cs.Name, cs.Email, cs.PlanID, cs.Status, cs.Notes, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "customer could not be updated")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// DeleteCustomer deletes a customer account without assigned domains.
func (h *Handlers) DeleteCustomer(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if !h.authorized(r, id) {
		httpx.WriteError(w, http.StatusForbidden, "no access to this customer")
		return
	}
	var n int
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM domains WHERE customer_id=?`, id).Scan(&n); err != nil {
		// FAIL-CLOSED: a count error must not bypass the "has domains" guard and
		// orphan domains that still reference this customer.
		httpx.WriteError(w, http.StatusInternalServerError, "customer could not be deleted")
		return
	} else if n > 0 {
		httpx.WriteError(w, http.StatusConflict, "remove this customer's domains first")
		return
	}
	if _, err := h.DB.ExecContext(r.Context(), `DELETE FROM customers WHERE id=?`, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "customer could not be deleted")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}
