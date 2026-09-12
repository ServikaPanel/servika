// Package users provides authenticated user profile handlers.
package users

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"servika/internal/auth"
	"servika/internal/httpx"
	"servika/internal/middleware"
	"servika/internal/quota"
)

// Handlers provides user profile HTTP handlers.
type Handlers struct {
	DB *sql.DB
}

type meResp struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Role     string `json:"role"`
	Email    string `json:"email"`
	FullName string `json:"full_name"`
	Status   string `json:"status"`
	TwoFA    bool   `json:"two_fa"`
	Theme    string `json:"pref_theme"`
	Lang     string `json:"pref_lang"`
}

// Me returns the authenticated user's profile.
func (h *Handlers) Me(w http.ResponseWriter, r *http.Request) {
	c := middleware.ClaimsFrom(r)
	if c == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "no active session")
		return
	}
	var resp meResp
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT id, username, role, email, full_name, status, totp_enabled, pref_theme, pref_lang FROM users WHERE id=?`,
		c.UserID).Scan(&resp.ID, &resp.Name, &resp.Role, &resp.Email, &resp.FullName, &resp.Status, &resp.TwoFA, &resp.Theme, &resp.Lang)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "user profile could not be read")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// ---------- Panel accounts (admin + reseller) ----------
//
// The scope rules live in one place so each handler does not reinterpret them:
//
//   - admin    : sees / manages every account, may create reseller and admin.
//   - reseller : ONLY the accounts below it (users.reseller_id = its own id),
//                and may create accounts in the 'user' role only.
//   - root     : id=1 is untouchable. It cannot be deleted and its role/status
//                cannot change. Its password lives in /etc/shadow and cannot be
//                reset from these endpoints.
//
// Deleting your own account and disabling the last admin are also blocked; both
// lead to a permanent panel lockout.

const rootID = int64(1)

// UserRow is one panel account as returned by List.
type UserRow struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	FullName    string `json:"full_name"`
	Role        string `json:"role"`
	Status      string `json:"status"`
	ResellerID  *int64 `json:"reseller_id"`
	TwoFA       bool   `json:"two_fa"`
	LastLogin   string `json:"last_login"`
	LastLoginIP string `json:"last_login_ip"`
	CreatedAt   string `json:"created_at"`
	// Passwordless is true when password_hash is empty — the account exists but
	// CANNOT log in. Customer accounts produced by the backfill are born this way
	// (see datamigrate.BackfillCustomerAccounts); the FTP bridge used to cover
	// for them, and no longer does, so an admin must be able to spot these
	// accounts in the list. root is exempt (its password lives in /etc/shadow).
	Passwordless bool `json:"passwordless"`
}

// authorized reports whether the caller may act on the target user. A target
// that does not exist also returns false, so a reseller cannot probe with a
// nonexistent id to infer whether an account exists.
func (h *Handlers) authorized(r *http.Request, targetID int64) bool {
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
	var resellerID *int64
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT reseller_id FROM users WHERE id=?`, targetID).Scan(&resellerID); err != nil {
		return false
	}
	return resellerID != nil && *resellerID == c.UserID
}

// List: GET /users
func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	c := middleware.ClaimsFrom(r)
	if c == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "no active session")
		return
	}

	q := `SELECT id, username, email, full_name, role, status, reseller_id, totp_enabled,
	             COALESCE(DATE_FORMAT(last_login_at,'%Y-%m-%d %H:%i'),''), last_login_ip,
	             COALESCE(DATE_FORMAT(created_at,'%Y-%m-%d'),''),
	             CASE WHEN username = 'root' THEN 0
	                  WHEN COALESCE(password_hash,'') = '' THEN 1 ELSE 0 END
	      FROM users`
	var arg []any
	if c.Role == middleware.RoleReseller {
		q += ` WHERE reseller_id = ?`
		arg = append(arg, c.UserID)
	}
	q += ` ORDER BY id`

	rows, err := h.DB.QueryContext(r.Context(), q, arg...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list users")
		return
	}
	defer func() { _ = rows.Close() }() // read-only query: closing the result set has nothing to flush

	out := make([]UserRow, 0)
	for rows.Next() {
		var s UserRow
		var twoFA, passwordless int
		if err := rows.Scan(&s.ID, &s.Username, &s.Email, &s.FullName, &s.Role, &s.Status,
			&s.ResellerID, &twoFA, &s.LastLogin, &s.LastLoginIP, &s.CreatedAt, &passwordless); err != nil {
			// A dropped row is an account that exists and can sign in while the
			// screen that manages accounts does not show it.
			httpx.LogR(r, "user list: skipping an unreadable row: %v", err)
			continue
		}
		s.TwoFA = twoFA == 1
		s.Passwordless = passwordless == 1
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "user list failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

type createReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	FullName string `json:"full_name"`
	Role     string `json:"role"`
}

var usernamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,31}$`)

// Create: POST /users
func (h *Handlers) Create(w http.ResponseWriter, r *http.Request) {
	c := middleware.ClaimsFrom(r)
	if c == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "no active session")
		return
	}
	var b createReq
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	b.Username = strings.ToLower(strings.TrimSpace(b.Username))
	b.Role = strings.TrimSpace(b.Role)

	if !validNewAccount(w, c, b) {
		return
	}
	hash, err := auth.HashPassword(b.Password)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	resellerID, ok := h.resellerBinding(w, r, c)
	if !ok {
		return
	}
	id, ok := h.insertAccount(w, r, b, hash, resellerID)
	if !ok {
		return
	}
	if b.Role == middleware.RoleUser {
		h.writeCustomerRecord(r, c, b, id)
	}

	// Scope the entry to the affected account's owner, not the actor: a reseller
	// (or admin) creating an account is recorded in that account's own scope so
	// its managing reseller sees it.
	auth.WriteAuditScoped(h.DB, c.UserID, c.Username, httpx.AuditIP(r), "user.create", b.Username, true, auth.ScopeOf(h.DB, id))
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"id": id})
}

// resellerBinding returns the reseller_id a new account carries. An account a
// reseller creates is automatically bound to it; an account an admin creates is
// unowned (belongs directly to admin). It answers the caller itself when the
// reseller's customer quota refuses the account.
func (h *Handlers) resellerBinding(w http.ResponseWriter, r *http.Request, c *auth.Claims) (any, bool) {
	if c.Role != middleware.RoleReseller {
		return nil, true
	}
	// The reseller's customer quota counts customer accounts (role=user), so it
	// is enforced on the same path that creates one.
	if err := quota.CheckResellerCustomerAllowed(r.Context(), h.DB, c.UserID); err != nil {
		if le, ok := errors.AsType[*quota.LimitError](err); ok {
			httpx.WriteError(w, http.StatusForbidden, le.Message)
			return nil, false
		}
		httpx.WriteError(w, http.StatusInternalServerError, "could not verify reseller limit")
		return nil, false
	}
	return c.UserID, true
}

// insertAccount writes the login row and returns its id. It answers the caller
// itself on a failure, telling a taken username apart from a write that did not
// happen.
func (h *Handlers) insertAccount(w http.ResponseWriter, r *http.Request, b createReq, hash string, resellerID any) (int64, bool) {
	res, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO users(username, email, password_hash, role, reseller_id, full_name, status)
		 VALUES(?,?,?,?,?,?, 'active')`,
		b.Username, strings.TrimSpace(b.Email), hash, b.Role, resellerID, strings.TrimSpace(b.FullName))
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			httpx.WriteError(w, http.StatusConflict, "this username is already in use")
			return 0, false
		}
		httpx.WriteError(w, http.StatusInternalServerError, "could not create account")
		return 0, false
	}
	id, _ := res.LastInsertId()
	return id, true
}

// validNewAccount refuses a name or a role the caller may not open. It answers
// the caller itself and reports whether the creation may go on.
func validNewAccount(w http.ResponseWriter, c *auth.Claims, b createReq) bool {
	if !usernamePattern.MatchString(b.Username) {
		httpx.WriteError(w, http.StatusBadRequest,
			"username: 3-32 chars, must start with a letter, may contain letters/digits/_/-")
		return false
	}
	// "root" is defined in the system, not the panel DB; a second account with
	// the same name would make the login flow ambiguous.
	if auth.IsRootUser(b.Username) {
		httpx.WriteError(w, http.StatusBadRequest, "this username is reserved")
		return false
	}
	// Privilege-escalation guard: a reseller may only create customer accounts.
	switch c.Role {
	case middleware.RoleAdmin:
		if b.Role != middleware.RoleAdmin && b.Role != middleware.RoleReseller && b.Role != middleware.RoleUser {
			httpx.WriteError(w, http.StatusBadRequest, "invalid role")
			return false
		}
	case middleware.RoleReseller:
		if b.Role != middleware.RoleUser {
			httpx.WriteError(w, http.StatusForbidden, "a reseller may only create customer accounts")
			return false
		}
	default:
		httpx.WriteError(w, http.StatusForbidden, "insufficient permissions")
		return false
	}
	return true
}

// writeCustomerRecord gives a customer account its customers row, whoever
// opened it. The row is the middle link of the ownership chain, so without it
// the account signs in and sees nothing (ScopeSQL's RoleUser branch matches on
// customers.user_id), and no domain can be attached to it either, because the
// domain form lists customers. This used to run only on the reseller path,
// which left every administrator-created customer account stranded that way.
//
// owner_user_id is the reseller's only when a reseller opened the account: its
// customer list and quota are counted over that column. An administrator leaves
// it NULL, which means the customer sits directly under admin.
//
// Non-fatal: the login already exists, so a failure here is logged.
func (h *Handlers) writeCustomerRecord(r *http.Request, c *auth.Claims, b createReq, id int64) {
	displayName := strings.TrimSpace(b.FullName)
	if displayName == "" {
		displayName = b.Username
	}
	var owner any
	if c.Role == middleware.RoleReseller {
		owner = c.UserID
	}
	if _, e := h.DB.ExecContext(r.Context(),
		`INSERT INTO customers(name, email, status, notes, user_id, owner_user_id)
		 VALUES(?,?, 'active', '', ?, ?)`,
		displayName, strings.TrimSpace(b.Email), id, owner); e != nil {
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		httpx.LogR(r, "auto customer record for user %d failed: %v", id, e)
	}
}

type updateReq struct {
	Email    *string `json:"email"`
	FullName *string `json:"full_name"`
	Role     *string `json:"role"`
}

// Update: PUT /users/{id}
func (h *Handlers) Update(w http.ResponseWriter, r *http.Request) {
	c := middleware.ClaimsFrom(r)
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if c == nil || !h.authorized(r, id) {
		httpx.WriteError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var b updateReq
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if b.Role != nil && !h.roleChangeAllowed(w, r, c, id, *b.Role) {
		return
	}
	if !h.writeProfileFields(w, r, b, id) {
		return
	}
	auth.WriteAuditScoped(h.DB, c.UserID, c.Username, httpx.AuditIP(r), "user.update", strconv.FormatInt(id, 10), true, auth.ScopeOf(h.DB, id))
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// roleChangeAllowed decides whether this caller may move this account into that
// role. It answers the caller itself and reports whether the update may go on.
func (h *Handlers) roleChangeAllowed(w http.ResponseWriter, r *http.Request, c *auth.Claims, id int64, role string) bool {
	if id == rootID {
		httpx.WriteError(w, http.StatusForbidden, "the root account's role cannot be changed")
		return false
	}
	if c.Role != middleware.RoleAdmin {
		httpx.WriteError(w, http.StatusForbidden, "only an administrator may change roles")
		return false
	}
	if role != middleware.RoleAdmin && role != middleware.RoleReseller && role != middleware.RoleUser {
		httpx.WriteError(w, http.StatusBadRequest, "invalid role")
		return false
	}
	// The last admin cannot be demoted out of the admin role.
	if role != middleware.RoleAdmin {
		if only, err := h.lastAdmin(r, id); err != nil || only {
			httpx.WriteError(w, http.StatusForbidden, "the last administrator account cannot be changed")
			return false
		}
	}
	return true
}

// writeProfileFields writes each field the request named, and only those. It
// answers the caller itself on a failure and reports whether every write
// succeeded.
func (h *Handlers) writeProfileFields(w http.ResponseWriter, r *http.Request, b updateReq, id int64) bool {
	if b.Email != nil {
		if _, err := h.DB.ExecContext(r.Context(), `UPDATE users SET email=?, updated_at=NOW() WHERE id=?`, strings.TrimSpace(*b.Email), id); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not update")
			return false
		}
	}
	if b.FullName != nil {
		if _, err := h.DB.ExecContext(r.Context(), `UPDATE users SET full_name=?, updated_at=NOW() WHERE id=?`, strings.TrimSpace(*b.FullName), id); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not update")
			return false
		}
	}
	if b.Role != nil {
		// Bump token_version so any session carrying the old role is revoked; a
		// stale JWT must not keep the prior privileges after a role change.
		if _, err := h.DB.ExecContext(r.Context(), `UPDATE users SET role=?, token_version=token_version+1, updated_at=NOW() WHERE id=?`, *b.Role, id); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not update")
			return false
		}
	}
	return true
}

// lastAdmin reports whether the given user is the only active admin in the system.
func (h *Handlers) lastAdmin(r *http.Request, id int64) (bool, error) {
	var n int
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM users WHERE role='admin' AND status='active' AND id<>?`, id).Scan(&n)
	if err != nil {
		return false, err
	}
	return n == 0, nil
}

// ResetPassword: POST /users/{id}/password — admin/reseller reset (the current
// password is not asked for; to change your own use /me/password).
func (h *Handlers) ResetPassword(w http.ResponseWriter, r *http.Request) {
	c := middleware.ClaimsFrom(r)
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if c == nil || !h.authorized(r, id) {
		httpx.WriteError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	if id == rootID {
		httpx.WriteError(w, http.StatusForbidden,
			"the root password is the system password; change it from the Profile screen")
		return
	}
	var b struct {
		New string `json:"new"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	hash, err := auth.HashPassword(b.New)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE users SET password_hash=?, token_version=token_version+1, updated_at=NOW() WHERE id=?`, hash, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not reset password")
		return
	}
	auth.WriteAuditScoped(h.DB, c.UserID, c.Username, httpx.AuditIP(r), "user.password", strconv.FormatInt(id, 10), true, auth.ScopeOf(h.DB, id))
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// subAccountCascade returns the statement that carries a reseller's status down
// to its own sub-accounts. It takes ONE bound argument: the reseller's id.
//
// The two directions are not symmetric, which is the whole point. Suspending
// marks the rows this cascade closed and leaves the marker alone on a row that
// was already suspended. Resuming then opens ONLY the rows carrying that marker,
// so a customer login an administrator disabled individually for abuse or
// non-payment stays disabled while the reseller comes back.
//
// In the suspend statement the marker assignment must come BEFORE status. MariaDB
// evaluates SET assignments left to right and a later one sees what an earlier
// one wrote, so putting status first would make every row look already-suspended
// and nothing would ever be marked.
func subAccountCascade(status string) string {
	if status == "suspended" {
		return `UPDATE users
		   SET suspended_by_reseller = IF(status='suspended', COALESCE(suspended_by_reseller,0), 1),
		       status = 'suspended',
		       token_version = token_version+1,
		       updated_at = NOW()
		 WHERE reseller_id=?`
	}
	return `UPDATE users
	   SET status = 'active',
	       suspended_by_reseller = 0,
	       token_version = token_version+1,
	       updated_at = NOW()
	 WHERE reseller_id=? AND COALESCE(suspended_by_reseller,0)=1`
}

// SetStatus: POST /users/{id}/status
func (h *Handlers) SetStatus(w http.ResponseWriter, r *http.Request) {
	c := middleware.ClaimsFrom(r)
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if c == nil || !h.authorized(r, id) {
		httpx.WriteError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	status, ok := h.requestedStatus(w, r, c, id)
	if !ok {
		return
	}
	// Bump token_version so a suspended account's live session is revoked at once
	// rather than surviving until the JWT expires.
	//
	// suspended_by_reseller is cleared whichever direction this goes: an operator
	// naming one account has made an explicit decision about it, and that decision
	// takes ownership of the row's state from the reseller cascade.
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE users SET status=?, token_version=token_version+1, suspended_by_reseller=0, updated_at=NOW()
		 WHERE id=?`, status, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not change status")
		return
	}
	h.cascadeStatus(r, id, status)
	auth.WriteAuditScoped(h.DB, c.UserID, c.Username, httpx.AuditIP(r), "user.status", strconv.FormatInt(id, 10), true, auth.ScopeOf(h.DB, id))
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// requestedStatus reads the status a request asks for and refuses the accounts
// that must stay reachable. It answers the caller itself and reports whether
// the change may go on.
func (h *Handlers) requestedStatus(w http.ResponseWriter, r *http.Request, c *auth.Claims, id int64) (string, bool) {
	if id == rootID {
		httpx.WriteError(w, http.StatusForbidden, "the root account cannot be suspended")
		return "", false
	}
	if id == c.UserID {
		httpx.WriteError(w, http.StatusForbidden, "you cannot suspend your own account")
		return "", false
	}
	var b struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || (b.Status != "active" && b.Status != "suspended") {
		httpx.WriteError(w, http.StatusBadRequest, "status must be 'active' or 'suspended'")
		return "", false
	}
	if b.Status == "suspended" {
		if only, err := h.lastAdmin(r, id); err != nil || only {
			httpx.WriteError(w, http.StatusForbidden, "the last administrator cannot be suspended")
			return "", false
		}
	}
	return b.Status, true
}

// cascadeStatus carries a status change down to what the account owns. Both
// steps are non-fatal: the primary status change already succeeded, so a
// cascade failure is logged rather than reported.
func (h *Handlers) cascadeStatus(r *http.Request, id int64, status string) {
	// Cascade to the reseller's own sub-accounts: suspending a reseller must not
	// leave its customer logins active, and reactivating it restores them. The
	// cascade only touches rows bound to this reseller (reseller_id = id), so an
	// ordinary customer account (no sub-accounts) matches nothing.
	if _, err := h.DB.ExecContext(r.Context(), subAccountCascade(status), id); err != nil {
		httpx.LogR(r, "cascade status to sub-accounts of user %d failed: %v", id, err)
	}

	// Cascade to the reseller's actual hosting: without this, suspending a
	// reseller only revoked panel logins while its customers' sites, FTP and mail
	// stayed live. Suspend/resume every domain owned by this reseller's customers.
	// This is a no-op for a customer account (it owns no customers, so the sweep
	// matches nothing).
	if affected, failed, err := suspendResellerDomains(r.Context(), h.DB, id, status == "suspended"); err != nil {
		httpx.LogR(r, "hosting suspend cascade for reseller %d failed: %v", id, err)
	} else if affected > 0 || failed > 0 {
		httpx.LogR(r, "hosting suspend cascade for reseller %d: %d applied, %d failed", id, affected, failed)
	}
}

// ---------- Reseller limits (reseller_limits) ----------
//
// Both endpoints are ADMIN ONLY (see cmd/server/main.go). A reseller reading
// its own quota looks harmless, but writing it is privilege escalation and
// reading is the preparation for that escalation; keeping both AdminOnly avoids
// landing on the wrong side of a fragile "read open, write closed" split.

// ResellerLimit is the quota row plus the reseller's current usage. The limit
// is meaningless without usage beside it: an admin cannot decide what to grant
// without knowing how many customers and domains the reseller already has.
type ResellerLimit struct {
	UserID          int64 `json:"user_id"`
	MaxCustomer     int   `json:"max_customer"`
	MaxDomain       int   `json:"max_domain"`
	DiskQuotaMB     int64 `json:"disk_quota_mb"`
	TrafficQuotaMB  int64 `json:"traffic_quota_mb"`
	Defined         bool  `json:"defined"`          // whether a reseller_limits row exists
	CurrentCustomer int   `json:"current_customer"` // present usage
	CurrentDomain   int   `json:"current_domain"`
	CurrentDiskMB   int64 `json:"current_disk_mb"`
	CurrentTraffMB  int64 `json:"current_traffic_mb"`
}

// GetLimits: GET /users/{id}/limits
func (h *Handlers) GetLimits(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)

	var role string
	if err := h.DB.QueryRowContext(r.Context(), `SELECT role FROM users WHERE id=?`, id).Scan(&role); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "account not found")
		return
	}
	if role != middleware.RoleReseller {
		httpx.WriteError(w, http.StatusBadRequest, "limits can only be defined for reseller accounts")
		return
	}

	out := ResellerLimit{UserID: id}
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT max_customer, max_domain, disk_quota_mb, traffic_quota_mb
		 FROM reseller_limits WHERE user_id=?`, id).
		Scan(&out.MaxCustomer, &out.MaxDomain, &out.DiskQuotaMB, &out.TrafficQuotaMB)
	out.Defined = err == nil // no row means unlimited

	// Usage: shown beside the limit so the number is meaningful.
	_ = h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM customers WHERE owner_user_id=?`, id).Scan(&out.CurrentCustomer)
	_ = h.DB.QueryRowContext(r.Context(), `
		SELECT COUNT(*) FROM domains d JOIN customers c ON c.id = d.customer_id
		WHERE c.owner_user_id = ?`, id).Scan(&out.CurrentDomain)
	_ = h.DB.QueryRowContext(r.Context(), `
		SELECT COALESCE(SUM(d.size_kb),0) DIV 1024, COALESCE(SUM(d.traffic_kb),0) DIV 1024
		FROM domains d JOIN customers c ON c.id = d.customer_id
		WHERE c.owner_user_id = ?`, id).Scan(&out.CurrentDiskMB, &out.CurrentTraffMB)

	httpx.WriteJSON(w, http.StatusOK, out)
}

// SaveLimits: PUT /users/{id}/limits
//
// 0 = unlimited (same quota contract as service_plans). When both limits are 0
// the row is deleted, so "unlimited" has a single representation (no row)
// instead of two states (no row vs. zero-valued row).
func (h *Handlers) SaveLimits(w http.ResponseWriter, r *http.Request) {
	c := middleware.ClaimsFrom(r)
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)

	if !h.resellerAccount(w, r, id) {
		return
	}
	var b resellerLimitInput
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if b.negative() {
		httpx.WriteError(w, http.StatusBadRequest, "limits cannot be negative (0 = unlimited)")
		return
	}

	if b.unlimited() {
		if _, err := h.DB.ExecContext(r.Context(),
			`DELETE FROM reseller_limits WHERE user_id=?`, id); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not remove limits")
			return
		}
	} else if _, err := h.DB.ExecContext(r.Context(), `
		INSERT INTO reseller_limits(user_id, max_customer, max_domain, disk_quota_mb, traffic_quota_mb)
		VALUES(?,?,?,?,?)
		ON DUPLICATE KEY UPDATE max_customer=VALUES(max_customer), max_domain=VALUES(max_domain),
		                        disk_quota_mb=VALUES(disk_quota_mb), traffic_quota_mb=VALUES(traffic_quota_mb)`,
		id, b.MaxCustomer, b.MaxDomain, b.DiskQuotaMB, b.TrafficQuotaMB); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not save limits")
		return
	}

	auth.WriteAuditScoped(h.DB, c.UserID, c.Username, httpx.AuditIP(r), "user.limits", strconv.FormatInt(id, 10), true, auth.ScopeOf(h.DB, id))
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// resellerLimitInput is the quota a request asks to store.
type resellerLimitInput struct {
	MaxCustomer    int   `json:"max_customer"`
	MaxDomain      int   `json:"max_domain"`
	DiskQuotaMB    int64 `json:"disk_quota_mb"`
	TrafficQuotaMB int64 `json:"traffic_quota_mb"`
}

// negative reports whether any limit is below zero, which is neither a ceiling
// nor the unlimited value.
func (l resellerLimitInput) negative() bool {
	return l.MaxCustomer < 0 || l.MaxDomain < 0 || l.DiskQuotaMB < 0 || l.TrafficQuotaMB < 0
}

// unlimited reports whether every limit is zero, which is stored as no row.
func (l resellerLimitInput) unlimited() bool {
	return l.MaxCustomer == 0 && l.MaxDomain == 0 && l.DiskQuotaMB == 0 && l.TrafficQuotaMB == 0
}

// resellerAccount reports whether the named account exists and is a reseller,
// which is the only kind of account a limit row belongs to. It answers the
// caller itself when it is not.
func (h *Handlers) resellerAccount(w http.ResponseWriter, r *http.Request, id int64) bool {
	var role string
	if err := h.DB.QueryRowContext(r.Context(), `SELECT role FROM users WHERE id=?`, id).Scan(&role); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "account not found")
		return false
	}
	if role != middleware.RoleReseller {
		httpx.WriteError(w, http.StatusBadRequest, "limits can only be defined for reseller accounts")
		return false
	}
	return true
}

// Delete: DELETE /users/{id}
func (h *Handlers) Delete(w http.ResponseWriter, r *http.Request) {
	c := middleware.ClaimsFrom(r)
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if c == nil || !h.authorized(r, id) {
		httpx.WriteError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	if !h.deletable(w, r, c, id) {
		return
	}
	// If a reseller is being deleted, the accounts under it are kept (not
	// deleted): the link is cut so no data is lost, and those accounts become
	// owned directly by admin.
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE users SET reseller_id=NULL WHERE reseller_id=?`, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not reassign linked accounts")
		return
	}
	deletedScope := h.deletedAuditScope(r, id)
	if _, err := h.DB.ExecContext(r.Context(), `DELETE FROM users WHERE id=?`, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete")
		return
	}
	// Move any entries scoped to the deleted account to root-only: only resellers
	// own a scope, and once this id can be reassigned by AUTO_INCREMENT a future
	// reseller must not inherit the deleted one's history.
	if _, err := h.DB.ExecContext(r.Context(), `UPDATE audit_log SET reseller_id=0 WHERE reseller_id=?`, id); err != nil {
		httpx.LogR(r, "audit scope cleanup after deleting user %d failed: %v", id, err)
	}
	auth.WriteAuditScoped(h.DB, c.UserID, c.Username, httpx.AuditIP(r), "user.delete", strconv.FormatInt(id, 10), true, deletedScope)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// deletable refuses the accounts whose removal locks the panel out. It answers
// the caller itself and reports whether the deletion may go on.
func (h *Handlers) deletable(w http.ResponseWriter, r *http.Request, c *auth.Claims, id int64) bool {
	if id == rootID {
		httpx.WriteError(w, http.StatusForbidden, "the root account cannot be deleted")
		return false
	}
	if id == c.UserID {
		httpx.WriteError(w, http.StatusForbidden, "you cannot delete your own account")
		return false
	}
	if only, err := h.lastAdmin(r, id); err != nil || only {
		httpx.WriteError(w, http.StatusForbidden, "the last administrator cannot be deleted")
		return false
	}
	return true
}

// deletedAuditScope resolves the audit scope BEFORE the row is deleted (the
// users row is gone once the DELETE runs). A deleted RESELLER's own scope dies
// with it, so the deletion is scoped to root (0); deleting any other account is
// scoped to its owning reseller so that reseller sees the removal.
func (h *Handlers) deletedAuditScope(r *http.Request, id int64) int64 {
	var deletedRole string
	var deletedReseller sql.NullInt64
	_ = h.DB.QueryRowContext(r.Context(), `SELECT role, reseller_id FROM users WHERE id=?`, id).Scan(&deletedRole, &deletedReseller)
	if deletedRole != "reseller" && deletedReseller.Valid {
		return deletedReseller.Int64
	}
	return 0
}
