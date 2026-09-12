// Package customer provides domain-owner (customer) panel authentication.
//
// Identity lives only in the users table (role=user, bcrypt). The scope is NOT
// embedded in the token; it is resolved from the domains -> customers -> users
// chain on every request (see middleware.CustomerUserOwnsDomain), because a
// customer may own several domains and, when ownership changes, the old token
// must become invalid immediately.
//
// HISTORY: customers used to sign in with their FTP identity, and because the
// accounts produced by the backfill had an empty password, that legacy FTP path
// was kept as a "migration bridge". The bridge was removed: authentication is
// now single-token and role-based. A customer without a password can no longer
// log in — an admin or reseller must assign one from the Customer Accounts
// screen.
package customer

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"servika/internal/auth"
	"servika/internal/httpx"
	mw "servika/internal/middleware"
)

type Handlers struct {
	DB     *sql.DB
	Secret []byte
	// LifetimeSec is the session lifetime SERVIKA_JWT_LIFETIME_SEC configures,
	// the same value the management login uses. It was once hardcoded to 24
	// hours here, so an operator who shortened the panel session shortened it
	// for their own staff only and left every customer session running three
	// times longer than the policy they set.
	LifetimeSec int
}

// defaultCustomerLifetimeSec matches config.Load's own default and only applies
// when a caller leaves LifetimeSec unset. Issuing a token with a zero lifetime
// would hand out a session that has already expired.
const defaultCustomerLifetimeSec = 8 * 3600

// lifetimeSec reports the session lifetime to issue.
func (h *Handlers) lifetimeSec() int {
	if h.LifetimeSec <= 0 {
		return defaultCustomerLifetimeSec
	}
	return h.LifetimeSec
}

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// credentials reads the submitted username and password.
func credentials(w http.ResponseWriter, r *http.Request) (loginReq, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10) // login body over 64KB is abuse (DoS)
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return req, false
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		httpx.WriteError(w, http.StatusBadRequest, "username and password are required")
		return req, false
	}
	return req, true
}

// authenticate resolves the account behind the credentials, and answers the
// caller when it refuses one.
func (h *Handlers) authenticate(w http.ResponseWriter, r *http.Request,
	req loginReq, auditIP string) (uid, tokenVersion int64, role string, ok bool) {
	var hash, status string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT id, password_hash, role, status, token_version FROM users WHERE username=?`,
		req.Username).Scan(&uid, &hash, &role, &status, &tokenVersion)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusInternalServerError, "authentication failed")
		return 0, 0, "", false
	}
	// One and the same rejection so which usernames exist does not leak. Run
	// PasswordMatches unconditionally (even on a DB miss, where hash is empty, it
	// still spends the bcrypt time) so timing cannot distinguish a present from an
	// absent username. An empty password_hash never matches, so an account whose
	// password has not been assigned yet cannot pass here.
	matches := auth.PasswordMatches(hash, req.Password)
	if err != nil || role != mw.RoleUser || !matches {
		auth.WriteAudit(h.DB, 0, req.Username, auditIP, "customer.login", req.Username, false)
		httpx.WriteError(w, http.StatusUnauthorized, "invalid username or password")
		return 0, 0, "", false
	}
	if status != "active" {
		auth.WriteAudit(h.DB, uid, req.Username, auditIP, "customer.login", req.Username, false)
		httpx.WriteError(w, http.StatusForbidden, "account is suspended")
		return 0, 0, "", false
	}
	return uid, tokenVersion, role, true
}

// Login authenticates a customer with their panel account (users table,
// role=user) and, on success, sets the HttpOnly session cookie.
func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	req, ok := credentials(w, r)
	if !ok {
		return
	}
	ip := httpx.ClientIP(r)
	// last_login_ip keeps the real address; the audit log labels a genuinely
	// local (internal/automated) origin as "system" instead of 127.0.0.1.
	auditIP := httpx.AuditIP(r)

	uid, tokenVersion, role, ok := h.authenticate(w, r, req, auditIP)
	if !ok {
		return
	}

	// The account's first domain: the scope is not embedded in the token, it is
	// resolved from the chain on each request (see
	// middleware.CustomerUserOwnsDomain). This lookup only tells the UI where to
	// land on first load.
	var firstDomainID int64
	var firstDomainName string
	_ = h.DB.QueryRowContext(r.Context(), `
		SELECT d.id, d.domain_name
		FROM domains d
		JOIN customers c ON c.id = d.customer_id
		WHERE c.user_id = ?
		ORDER BY d.id LIMIT 1`, uid).Scan(&firstDomainID, &firstDomainName)

	// Account exists but has no service linked yet (e.g. a reseller created it
	// but has not assigned a domain). Issuing a token would send the UI to
	// /subscriptions/0 and end in a "domain not found" error; stating the reason
	// plainly is better.
	if firstDomainID == 0 {
		auth.WriteAudit(h.DB, uid, req.Username, auditIP, "customer.login", req.Username, false)
		httpx.WriteError(w, http.StatusForbidden,
			"no service is linked to your account — contact your provider")
		return
	}

	lifetime := h.lifetimeSec()
	tok, err := auth.Issue(h.Secret, lifetime, uid, req.Username, role, tokenVersion)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	auth.WriteAudit(h.DB, uid, req.Username, auditIP, "customer.login", req.Username, true)
	if _, err := h.DB.Exec(`UPDATE users SET last_login_at=NOW(), last_login_ip=? WHERE id=?`, ip, uid); err != nil {
		httpx.LogR(r, "customer login: last_login update failed for uid=%d: %v", uid, err)
	}

	// Deliver the token only in the HttpOnly session cookie, never in the body.
	httpx.SetSessionCookie(w, r, tok, lifetime)

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"expires_at":    time.Now().Add(time.Duration(lifetime) * time.Second).Unix(),
		"domain_id":     firstDomainID,
		"domain_name":   firstDomainName,
		"username":      req.Username,
		"panel_account": true,
	})
}
