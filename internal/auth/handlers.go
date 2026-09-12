package auth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	yescrypt "github.com/openwall/yescrypt-go"

	"servika/internal/httpx"
	"servika/internal/logx"
	"servika/internal/sessionrevoke"
	"servika/internal/system"
)

// Handlers provides HTTP handlers for administrator authentication.
type Handlers struct {
	DB          *sql.DB
	Secret      []byte
	LifetimeSec int
}

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Code     string `json:"code"`
}

type loginResp struct {
	// Token is intentionally omitted: the session JWT is delivered only via the
	// HttpOnly servika_session cookie (see httpx.SetSessionCookie) so JavaScript
	// cannot read it. The body carries only non-secret session metadata.
	ExpiresAt int64 `json:"expires_at"`
	User      struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		Role     string `json:"role"`
		FullName string `json:"full_name"`
	} `json:"user"`
}

// rootShadowHash reads the root password hash from /etc/shadow ("" = not found).
func rootShadowHash() string {
	data, err := os.ReadFile("/etc/shadow")
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if strings.HasPrefix(line, "root:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				return parts[1]
			}
			return ""
		}
	}
	return ""
}

// verifyRootPassword verifies password against the root hash in /etc/shadow.
//
// yescrypt ($y$) — AlmaLinux 10 default — is computed NATIVELY in Go
// (github.com/openwall/yescrypt-go: the yescrypt authors' own implementation).
// This removes the python3 crypt dependency from the PRIMARY path. That module
// was deprecated in Python 3.11 and REMOVED in 3.13 — when the server upgrades
// the panel login would break entirely.
//
// Legacy formats ($6$/$5$/$1$), which a host imaged from an older release can
// still carry, go through `openssl passwd`. That replaced a shell-out to python3's
// crypt module, which was removed in Python 3.13: on a server whose platform Python
// moved to 3.13 the panel login stopped working entirely. The openssl CLI is
// installed by servika-install.sh and used by it to generate every runtime secret,
// so it is already a hard dependency rather than a new one.
//
// Comparison uses subtle.ConstantTimeCompare on both paths.
func verifyRootPassword(password string) bool {
	hash := rootShadowHash()
	// Locked ("!", "!!", "*") or passwordless account — never accept.
	if len(hash) < 3 || !strings.HasPrefix(hash, "$") {
		return false
	}
	if strings.HasPrefix(hash, "$y$") { // yescrypt → native Go
		computed, err := yescrypt.Hash([]byte(password), []byte(hash))
		if err != nil {
			return false
		}
		return subtle.ConstantTimeCompare(computed, []byte(hash)) == 1
	}
	return legacyCryptVerify(password, hash)
}

// legacyCryptSalt splits "$id$[rounds=N$]salt$digest" into the format id and the
// exact string openssl expects for -salt. openssl generates its own random salt
// when handed something it cannot parse, which silently turns every login into a
// mismatch, so the segments are validated rather than trusted: everything except
// the "rounds=N" prefix must be within the crypt(3) alphabet (./0-9A-Za-z), which
// also rules out a salt that could look like a command-line option.
func legacyCryptSalt(hash string) (id, salt string, ok bool) {
	id, salt, ok = cryptIDAndSalt(strings.Split(hash, "$"))
	if !ok || id == "" || salt == "" {
		return "", "", false
	}
	if !cryptAlphabet(strings.TrimPrefix(salt, "rounds=")) {
		return "", "", false
	}
	return id, salt, true
}

// cryptIDAndSalt reads the format id and the salt out of the "$"-split hash,
// with or without a "rounds=N" segment.
func cryptIDAndSalt(parts []string) (id, salt string, ok bool) {
	switch {
	case len(parts) == 4: // ["", id, salt, digest]
		return parts[1], parts[2], true
	case len(parts) == 5 && strings.HasPrefix(parts[2], "rounds="): // ["", id, rounds=N, salt, digest]
		rounds := strings.TrimPrefix(parts[2], "rounds=")
		if rounds == "" || !allDigits(rounds) {
			return "", "", false
		}
		return parts[1], parts[2] + "$" + parts[3], true
	}
	return "", "", false
}

// allDigits reports whether every rune of s is 0-9.
func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// cryptAlphabet reports whether s stays inside the crypt(3) alphabet
// (./0-9A-Za-z plus the "$" that separates a rounds segment), which also rules
// out a salt that could look like a command-line option.
func cryptAlphabet(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '.', r == '/', r == '$':
		default:
			return false
		}
	}
	return true
}

// legacyCryptVerify recomputes a non-yescrypt crypt(3) hash with openssl and
// compares it in constant time.
func legacyCryptVerify(password, hash string) bool {
	id, salt, ok := legacyCryptSalt(hash)
	if !ok {
		return false
	}
	var flag string
	switch id {
	case "6": // SHA-512
		flag = "-6"
	case "5": // SHA-256
		flag = "-5"
	case "1": // MD5
		flag = "-1"
	default:
		return false // bcrypt, DES and anything else openssl passwd cannot recompute
	}

	// A hash carrying an absurd (but legal) rounds value makes openssl run for
	// minutes. Only root writes /etc/shadow, so this is not reachable by a caller,
	// but a login request must not be able to pin a process either way.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// #nosec G204 G702 -- fixed binary with separate args (no shell); the salt is validated above against the crypt(3) alphabet and the password goes over stdin, never argv.
	cmd := exec.CommandContext(ctx, "openssl", "passwd", flag, "-salt", salt, "-stdin")
	cmd.Stdin = strings.NewReader(password)
	out, err := cmd.Output()
	if err != nil {
		// Distinguishable from a wrong password in the log, because a missing or
		// failing openssl locks root out and must not look like a typo. The hash and
		// the password are never logged.
		logx.Errorf("root login: openssl passwd failed for a $%s$ hash: %v", id, err)
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(string(out))), []byte(hash)) == 1
}

func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10) // login body over 64KB is abuse (DoS)
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		httpx.WriteError(w, http.StatusBadRequest, "username and password are required")
		return
	}
	ip := httpx.ClientIP(r)
	// last_login_ip keeps the real address; the audit log labels a genuinely
	// local (internal/automated) origin as "system" instead of 127.0.0.1.
	auditIP := httpx.AuditIP(r)

	who, ok := h.identify(w, req, auditIP)
	if !ok {
		return
	}
	uid, username, role, fullName := who.uid, who.username, who.role, who.fullName

	if !h.secondFactorPassed(w, who, req.Code, auditIP) {
		return
	}

	var tokenVersion int64
	if err := h.DB.QueryRow(`SELECT token_version FROM users WHERE id=?`, uid).Scan(&tokenVersion); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	tok, err := Issue(h.Secret, h.LifetimeSec, uid, username, role, tokenVersion)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	WriteAudit(h.DB, uid, username, auditIP, "auth.login", username, true)
	// last_login_at uses the MySQL clock and is display-only (never compared to
	// a Go time value), so NOW() is safe here.
	if _, err := h.DB.Exec(`UPDATE users SET last_login_at=NOW(), last_login_ip=? WHERE id=?`, ip, uid); err != nil {
		httpx.LogR(r, "last_login update failed for uid=%d: %v", uid, err)
	}

	// Only an admin or reseller reaches this line; the customer role is refused
	// above, and /customer/login is a different handler. Refresh the update
	// manifest now rather than leaving the notice up to a poll period stale.
	system.TriggerVersionCheck()

	// Deliver the token only in the HttpOnly session cookie, never in the body.
	httpx.SetSessionCookie(w, r, tok, h.LifetimeSec)

	resp := loginResp{ExpiresAt: time.Now().Add(time.Duration(h.LifetimeSec) * time.Second).Unix()}
	resp.User.ID = uid
	resp.User.Name = username
	resp.User.Role = role
	resp.User.FullName = fullName
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// signedIn is the identity a login resolved.
type signedIn struct {
	uid      int64
	username string
	role     string
	fullName string
}

// identify resolves the caller against one of the two separate password worlds
// (see password.go).
//
//	root  -> /etc/shadow (yescrypt). This path was DELIBERATELY left
//	         unchanged when adding multi-user support; it is the only way to
//	         keep the risk of locking yourself out of the panel at zero.
//	other -> users.password_hash (bcrypt), status='active' accounts only.
//
// Both branches return the same failure response ("invalid username or
// password") so which usernames exist is never leaked. It answers the request
// itself on a refusal and reports false.
func (h *Handlers) identify(w http.ResponseWriter, req loginReq, auditIP string) (signedIn, bool) {
	if IsRootUser(req.Username) {
		return h.rootIdentity(w, req, auditIP)
	}
	return h.accountIdentity(w, req, auditIP)
}

// rootIdentity verifies root against /etc/shadow. Only the display name comes
// from the database.
func (h *Handlers) rootIdentity(w http.ResponseWriter, req loginReq, auditIP string) (signedIn, bool) {
	if !rootPasswordOK(req.Password) {
		WriteAudit(h.DB, 0, req.Username, auditIP, "auth.login", req.Username, false)
		httpx.WriteError(w, http.StatusUnauthorized, "invalid username or password")
		return signedIn{}, false
	}
	who := signedIn{uid: 1, username: "root", role: "admin"}
	_ = h.DB.QueryRow(`SELECT full_name FROM users WHERE id=1`).Scan(&who.fullName)
	return who, true
}

// accountIdentity verifies a panel account against users.password_hash.
func (h *Handlers) accountIdentity(w http.ResponseWriter, req loginReq, auditIP string) (signedIn, bool) {
	var who signedIn
	var hash, status string
	err := h.DB.QueryRow(
		`SELECT id, username, password_hash, role, status, full_name FROM users WHERE username=?`,
		req.Username).Scan(&who.uid, &who.username, &hash, &who.role, &status, &who.fullName)
	// A driver failure is a FAULT, not a wrong credential, and merging the two
	// cost twice during a database incident. It told an operator typing the
	// right password that their credentials were wrong, sending them to reset a
	// password instead of to the database; and every 401 records a failure
	// against the per-account and per-IP lockout counters, so retrying during
	// the outage locked a healthy account out for the quarter hour AFTER the
	// database came back.
	//
	// Answering 500 here leaks nothing, because it is not conditioned on
	// whether the account exists: only sql.ErrNoRows folds into the shared 401
	// below, which is what keeps username existence secret. This is what
	// internal/customer already does for the same credential check.
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusInternalServerError, "authentication failed")
		return signedIn{}, false
	}
	// Always run PasswordMatches (even on a DB miss, where hash is empty) so a
	// present and an absent username cannot be told apart by timing; do not let
	// the err check short-circuit it away.
	matches := PasswordMatches(hash, req.Password)
	if err != nil || !matches {
		WriteAudit(h.DB, 0, req.Username, auditIP, "auth.login", req.Username, false)
		httpx.WriteError(w, http.StatusUnauthorized, "invalid username or password")
		return signedIn{}, false
	}
	if status != "active" {
		WriteAudit(h.DB, who.uid, who.username, auditIP, "auth.login", who.username, false)
		httpx.WriteError(w, http.StatusForbidden, "account is suspended")
		return signedIn{}, false
	}
	// The customer role cannot open a management-panel session; customers
	// sign in at /customer/login to their own domain panels instead.
	if who.role != "admin" && who.role != "reseller" {
		WriteAudit(h.DB, who.uid, who.username, auditIP, "auth.login", who.username, false)
		httpx.WriteError(w, http.StatusForbidden, "this account cannot sign in to the management panel")
		return signedIn{}, false
	}
	return who, true
}

// secondFactorPassed requires a TOTP code when 2FA is enabled for this account.
// The state is read from the signing-in user's own record (it used to be
// hardcoded to id=1). FAIL-CLOSED: when 2FA state cannot be read (DB error)
// login is DENIED (previously the error was swallowed and 2FA was silently
// skipped = fail-open). It answers the request itself on a refusal and on the
// two_factor_required prompt, and reports false.
func (h *Handlers) secondFactorPassed(w http.ResponseWriter, who signedIn, code, auditIP string) bool {
	var en int
	var sec string
	var lastStep int64
	if err := h.DB.QueryRow(`SELECT totp_enabled, totp_secret, totp_last_step FROM users WHERE id=?`, who.uid).Scan(&en, &sec, &lastStep); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not verify 2FA state")
		return false
	}
	if en != 1 {
		return true
	}
	if strings.TrimSpace(sec) == "" {
		httpx.WriteError(w, http.StatusInternalServerError, "2FA configuration is invalid")
		return false
	}
	if strings.TrimSpace(code) == "" {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"two_factor_required": true})
		return false
	}
	// FAIL-CLOSED, like every other branch here: a seed that cannot be
	// opened denies the login rather than verifying the code against a
	// value this could not read.
	seed, err := OpenTOTPSecret(sec, who.uid)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "2FA configuration is invalid")
		return false
	}
	step, ok := TOTPVerifyStep(seed, code, lastStep)
	if !ok {
		WriteAudit(h.DB, who.uid, who.username, auditIP, "auth.2fa", who.username, false)
		httpx.WriteError(w, http.StatusUnauthorized, "invalid or reused 2FA code")
		return false
	}
	// Persist the accepted step for replay protection. FAIL-CLOSED: if this
	// write fails the code would remain replayable within its validity window,
	// so deny the login rather than issuing a token on unguaranteed protection.
	if _, err := h.DB.Exec(`UPDATE users SET totp_last_step=? WHERE id=?`, step, who.uid); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not update 2FA state")
		return false
	}
	return true
}

// Logout clears the session cookie AND ends that one session on the server.
//
// It used to clear only the cookie, so the token the browser had just stopped
// sending stayed valid for the rest of its lifetime. Anyone holding a captured
// copy kept a working session, and pressing "sign out" on a shared machine
// protected nothing server-side.
//
// Only the surrendered session is ended, by its jti claim. token_version stays
// untouched, because a logout on one device must not sign the same person out
// of the others; RevokeSessions is the control that does that deliberately.
//
// It remains a PUBLIC endpoint: expiring a cookie requires no authentication
// and must succeed even when the token is already invalid or absent. A token
// that does not parse, or that carries no jti because it predates the claim,
// leaves nothing to record and the cookie is still cleared.
func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	h.revokePresentedSession(r)
	httpx.ClearSessionCookie(w, r)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// revokePresentedSession records the jti of the token the request presented.
//
// A failure is logged and not reported to the caller: the cookie clear is the
// part the client can act on, and answering 500 would leave the browser holding
// a session it asked to end.
func (h *Handlers) revokePresentedSession(r *http.Request) {
	ck, err := r.Cookie(httpx.SessionCookie)
	if err != nil || ck.Value == "" {
		return
	}
	c, err := Parse(h.Secret, ck.Value)
	if err != nil || c.ID == "" || c.ExpiresAt == nil {
		return
	}
	if err := sessionrevoke.Revoke(r.Context(), h.DB, c.ID, c.ExpiresAt.Time); err != nil {
		httpx.LogR(r, "logout: the session could not be revoked for uid=%d: %v", c.UserID, err)
	}
}

// ScopeOf resolves the reseller scope a user belongs to for audit_log.reseller_id:
// a reseller is its own scope (its users.id), any other account maps to its
// managing reseller (users.reseller_id), and root/admin or an unreadable row map
// to 0 (root-only). FAIL-SAFE: on any error the scope is 0, so a lookup failure
// can never leak an entry into a reseller's log — it stays root-only.
func ScopeOf(db *sql.DB, uid int64) int64 {
	if db == nil || uid <= 0 {
		return 0
	}
	var role string
	var resellerID sql.NullInt64
	if err := db.QueryRow(`SELECT role, reseller_id FROM users WHERE id=?`, uid).Scan(&role, &resellerID); err != nil {
		return 0
	}
	if role == "reseller" {
		return uid
	}
	if resellerID.Valid && resellerID.Int64 > 0 {
		return resellerID.Int64
	}
	return 0
}

// WriteAudit records an audit entry scoped to the ACTOR's reseller (ScopeOf).
// Use WriteAuditScoped when the entry must be scoped to a DIFFERENT account than
// the actor (e.g. root changing a reseller's account: the reseller must see it).
func WriteAudit(db *sql.DB, uid int64, username, ip, action, target string, ok bool) {
	WriteAuditScoped(db, uid, username, ip, action, target, ok, ScopeOf(db, uid))
}

// WriteAuditScoped records an audit entry with an explicit reseller scope. The
// scope is the owning reseller's users.id (0 = root-only). Entries are scoped to
// the AFFECTED account's owner so a reseller sees changes made to its own
// accounts even when root performed them.
func WriteAuditScoped(db *sql.DB, uid int64, username, ip, action, target string, ok bool, resellerScope int64) {
	var uidVal any
	if uid > 0 {
		uidVal = uid
	}
	okv := 0
	if ok {
		okv = 1
	}
	if resellerScope < 0 {
		resellerScope = 0
	}
	if _, err := db.Exec(
		`INSERT INTO audit_log(actor_user_id, actor_username, ip, action, target, ok, reseller_id)
		 VALUES(?,?,?,?,?,?,?)`,
		uidVal, username, ip, action, target, okv, resellerScope); err != nil {
		logx.Errorf("audit log insert failed: %v", err)
	}
}

// AuditEntry — a security-log row (read-only).
type AuditEntry struct {
	ID       int64  `json:"id"`
	Time     string `json:"time"`
	Username string `json:"username"`
	IP       string `json:"ip"`
	Action   string `json:"action"`
	Target   string `json:"target"`
	OK       bool   `json:"ok"`
}

// AuditList returns audit_log newest-first.
//
// The table has been written to since the first release but there was no read
// endpoint — seeing failed login attempts meant SSHing into the server and
// querying MySQL by hand.
//
// Filters: ?limit=N (default 200, cap 1000), ?action=auth.login,
// ?only_failed=1. A limit is preferred over a date range — this screen's job is
// "what happened recently", not archive analysis.
// auditLimit parses ?limit into the effective row cap: default 200, values
// <=0 or non-numeric fall back to 200, and anything above 1000 clamps to 1000.
func auditLimit(raw string) int {
	limit := 200
	if raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 1000 {
		limit = 1000
	}
	return limit
}

// buildAuditQuery assembles the parameterized audit_log SELECT and its args
// from the filters. The action value is always bound as a `?` placeholder (never
// interpolated) and only_failed adds a constant predicate, so user input can
// never reach the SQL text. Kept pure so the filter/injection-safety logic is
// unit-testable without a database.
// scope < 0 means "all scopes" (root/admin); scope >= 0 restricts to that
// reseller_id (a reseller sees only its own entries). The value is always bound
// as a `?` placeholder, never interpolated.
func buildAuditQuery(action string, onlyFailed bool, limit int, scope int64) (string, []any) {
	q := `SELECT id, DATE_FORMAT(ts, '%Y-%m-%d %H:%i:%s'), actor_username, ip, action, target, ok
	      FROM audit_log`
	cond := make([]string, 0, 3)
	arg := make([]any, 0, 4)
	if scope >= 0 {
		cond = append(cond, "reseller_id = ?")
		arg = append(arg, scope)
	}
	if a := strings.TrimSpace(action); a != "" {
		cond = append(cond, "action = ?")
		arg = append(arg, a)
	}
	if onlyFailed {
		cond = append(cond, "ok = 0")
	}
	if len(cond) > 0 {
		q += " WHERE " + strings.Join(cond, " AND ")
	}
	q += " ORDER BY id DESC LIMIT ?"
	arg = append(arg, limit)
	return q, arg
}

// auditViewScope maps the requesting session to a query scope: an admin sees
// every entry (-1), a reseller sees only its own reseller_id, and anything else
// is confined to root-only entries (0) as a fail-safe.
func auditViewScope(r *http.Request) int64 {
	c := ClaimsFromContext(r.Context())
	if c == nil {
		return 0
	}
	switch c.Role {
	case "admin":
		return -1
	case "reseller":
		return c.UserID
	default:
		return 0
	}
}

func (h *Handlers) AuditList(w http.ResponseWriter, r *http.Request) {
	limit := auditLimit(r.URL.Query().Get("limit"))
	q, arg := buildAuditQuery(
		r.URL.Query().Get("action"),
		r.URL.Query().Get("only_failed") == "1",
		limit,
		auditViewScope(r),
	)

	rows, err := h.DB.QueryContext(r.Context(), q, arg...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "audit list failed")
		return
	}
	defer func() { _ = rows.Close() }() // read-only query: closing the result set has nothing to flush

	out := make([]AuditEntry, 0)
	for rows.Next() {
		var e AuditEntry
		var okv int
		if err := rows.Scan(&e.ID, &e.Time, &e.Username, &e.IP, &e.Action, &e.Target, &okv); err != nil {
			// A dropped row is an audit entry that disappears from the record
			// somebody is reading precisely to account for what happened.
			// #nosec G706 -- the logged value is a database error; no request-controlled string reaches the log.
			httpx.WarnR(r, "audit list: skipping an unreadable entry: %v", err)
			continue
		}
		e.OK = okv == 1
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "audit log read failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// AuditActions returns the distinct action names present in the table, to
// populate the filter dropdown (instead of a hardcoded list — new actions show
// up on their own as they are added).
func (h *Handlers) AuditActions(w http.ResponseWriter, r *http.Request) {
	// Mirror AuditList's scope so a reseller's dropdown lists only the actions
	// present in its own entries.
	q := `SELECT DISTINCT action FROM audit_log`
	var arg []any
	if scope := auditViewScope(r); scope >= 0 {
		q += ` WHERE reseller_id = ?`
		arg = append(arg, scope)
	}
	q += ` ORDER BY action`
	rows, err := h.DB.QueryContext(r.Context(), q, arg...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "audit actions failed")
		return
	}
	defer func() { _ = rows.Close() }() // read-only query: closing the result set has nothing to flush
	out := make([]string, 0)
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err == nil {
			out = append(out, a)
		}
	}
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "audit log read failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
