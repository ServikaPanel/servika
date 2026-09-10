package auth

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"

	"servika/internal/config"
	"servika/internal/httpx"
)

// claims returns the identity RequireAuth verified for this request.
//
// It reads the request context, never the Authorization header. The panel is
// cookie-only: the session JWT lives in the HttpOnly servika_session cookie and
// no client sends a bearer token, so a handler resolving identity from that
// header answered 401 to every real request. Re-parsing it would also skip the
// token_version check RequireAuth performs, so the acted-upon UserID would come
// from a credential nothing had checked for revocation.
//
// There is no import cycle to work around: ClaimsFromContext lives in this same
// package (context.go), exactly so that auth can read the session middleware put
// there.
func (h *Handlers) claims(r *http.Request) *Claims {
	return ClaimsFromContext(r.Context())
}

// PUT /me — profile information (full name + email + preferences)
func (h *Handlers) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	c := h.claims(r)
	if c == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "no active session")
		return
	}
	var b struct {
		FullName  string `json:"full_name"`
		Email     string `json:"email"`
		PrefTheme string `json:"pref_theme"`
		PrefLang  string `json:"pref_lang"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	b.FullName = strings.TrimSpace(b.FullName)
	b.Email = strings.TrimSpace(b.Email)
	if b.Email != "" && !strings.Contains(b.Email, "@") {
		httpx.WriteError(w, http.StatusBadRequest, "invalid email address")
		return
	}
	theme := "system"
	if b.PrefTheme == "light" || b.PrefTheme == "dark" || b.PrefTheme == "system" {
		theme = b.PrefTheme
	}
	language := config.NormalizeLang(b.PrefLang)
	if _, err := h.DB.Exec(
		`UPDATE users SET full_name=?, email=?, pref_theme=?, pref_lang=?, updated_at=NOW() WHERE id=?`,
		b.FullName, b.Email, theme, language, c.UserID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "profile update failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// UpdateLanguage persists only the caller's language preference. Unlike
// UpdateProfile (ResellerOrAbove), this route is open to every authenticated
// role so a customer (role=user) can also store its own pref_lang. Uses the same
// whitelist as UpdateProfile: anything outside the supported set falls back to "en".
func (h *Handlers) UpdateLanguage(w http.ResponseWriter, r *http.Request) {
	c := h.claims(r)
	if c == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "no active session")
		return
	}
	var b struct {
		PrefLang string `json:"pref_lang"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	language := config.NormalizeLang(b.PrefLang)
	if _, err := h.DB.Exec(
		`UPDATE users SET pref_lang=?, updated_at=NOW() WHERE id=?`,
		language, c.UserID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "language update failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "pref_lang": language})
}

// POST /me/password — change server root password (current password verified → chpasswd)
func (h *Handlers) ChangePassword(w http.ResponseWriter, r *http.Request) {
	c := h.claims(r)
	if c == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "no active session")
		return
	}
	var b struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(b.New) < PasswordMinLength {
		httpx.WriteError(w, http.StatusBadRequest, "new password must be at least 8 characters")
		return
	}

	// root's password lives in the system (/etc/shadow), not the panel DB:
	// verify from shadow, change with chpasswd. Reseller accounts have no system
	// counterpart; they use users.password_hash.
	if IsRootUser(c.Username) {
		if !verifyRootPassword(b.Current) {
			WriteAudit(h.DB, c.UserID, "root", httpx.AuditIP(r), "auth.password", "root", false)
			httpx.WriteError(w, http.StatusUnauthorized, "current password is incorrect")
			return
		}
		if strings.ContainsAny(b.New, "\n\r\x00") {
			httpx.WriteError(w, http.StatusBadRequest, "password contains invalid characters")
			return
		}
		cmd := exec.Command("chpasswd")
		cmd.Stdin = strings.NewReader("root:" + b.New)
		if _, err := cmd.CombinedOutput(); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "password change failed")
			return
		}
		// Bump token_version so every existing session is revoked after the
		// credential changes; the caller must re-authenticate.
		if _, err := h.DB.Exec(`UPDATE users SET token_version=token_version+1, updated_at=NOW() WHERE id=?`, c.UserID); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not revoke existing sessions")
			return
		}
		WriteAudit(h.DB, c.UserID, "root", httpx.AuditIP(r), "auth.password", "root", true)
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}

	var currentHash string
	if err := h.DB.QueryRow(`SELECT password_hash FROM users WHERE id=?`, c.UserID).Scan(&currentHash); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "account could not be read")
		return
	}
	if !PasswordMatches(currentHash, b.Current) {
		WriteAudit(h.DB, c.UserID, c.Username, httpx.AuditIP(r), "auth.password", c.Username, false)
		httpx.WriteError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}
	newHash, err := HashPassword(b.New)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := h.DB.Exec(`UPDATE users SET password_hash=?, token_version=token_version+1, updated_at=NOW() WHERE id=?`, newHash, c.UserID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "password change failed")
		return
	}
	WriteAudit(h.DB, c.UserID, c.Username, httpx.AuditIP(r), "auth.password", c.Username, true)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// POST /me/sessions/revoke — invalidate every admin JWT by bumping token_version.
// The caller's own token is included, so the client must re-authenticate after this.
func (h *Handlers) RevokeSessions(w http.ResponseWriter, r *http.Request) {
	c := h.claims(r)
	if c == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "no active session")
		return
	}
	if _, err := h.DB.Exec(`UPDATE users SET token_version=token_version+1 WHERE id=?`, c.UserID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not revoke sessions")
		return
	}
	WriteAudit(h.DB, c.UserID, "root", httpx.AuditIP(r), "auth.sessions.revoke", "root", true)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// GET /me/2fa/setup — generate a new secret (not yet activated), return otpauth URI
func (h *Handlers) TwoFASetup(w http.ResponseWriter, r *http.Request) {
	if h.claims(r) == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "no active session")
		return
	}
	secret, err := TOTPGenerateSecret()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not generate secret")
		return
	}
	uri := TOTPURI(secret, "root", "Servika")
	resp := map[string]any{
		"secret":      secret,
		"otpauth":     uri, // backwards-compatible (manual entry fallback)
		"otpauth_uri": uri,
	}
	// QR PNG data-URI for scanning with an authenticator app. When generation
	// fails the manual-entry fallback (secret + otpauth) is still present.
	if dataURI, err := TOTPQRDataURI(uri); err == nil {
		resp["qr_data_uri"] = dataURI
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// POST /me/2fa/enable — {secret, code}: enables 2FA if the code validates against the secret
func (h *Handlers) TwoFAEnable(w http.ResponseWriter, r *http.Request) {
	c := h.claims(r)
	if c == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "no active session")
		return
	}
	var b struct {
		Secret string `json:"secret"`
		Code   string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	b.Secret = strings.TrimSpace(b.Secret)
	step, ok := TOTPVerifyStep(b.Secret, b.Code, -1)
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "code verification failed; enter the six-digit code from your authenticator app")
		return
	}
	sealed, err := SealTOTPSecret(b.Secret, c.UserID)
	if err != nil {
		// Storing the seed in the clear instead is not an acceptable fallback:
		// that is the state this replaces.
		httpx.WriteError(w, http.StatusInternalServerError, "2FA settings could not be saved")
		return
	}
	if _, err := h.DB.Exec(`UPDATE users SET totp_secret=?, totp_enabled=1, totp_last_step=?, token_version=token_version+1 WHERE id=?`, sealed, step, c.UserID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "2FA settings could not be saved")
		return
	}
	WriteAudit(h.DB, c.UserID, "root", httpx.AuditIP(r), "auth.2fa.enable", "root", true)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// POST /me/2fa/disable — {code}: disables 2FA with a valid code
func (h *Handlers) TwoFADisable(w http.ResponseWriter, r *http.Request) {
	c := h.claims(r)
	if c == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "no active session")
		return
	}
	var b struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var stored string
	_ = h.DB.QueryRow(`SELECT totp_secret FROM users WHERE id=?`, c.UserID).Scan(&stored)
	seed, err := OpenTOTPSecret(stored, c.UserID)
	if err != nil {
		// A seed that cannot be opened cannot verify a code. Refusing here leaves
		// 2FA on, which is the safe direction: the alternative would let a caller
		// who broke the seal turn the second factor off.
		httpx.WriteError(w, http.StatusBadRequest, "code verification failed")
		return
	}
	if !TOTPVerify(seed, b.Code) {
		httpx.WriteError(w, http.StatusBadRequest, "code verification failed")
		return
	}
	if _, err := h.DB.Exec(`UPDATE users SET totp_secret='', totp_enabled=0, token_version=token_version+1 WHERE id=?`, c.UserID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "2FA could not be disabled")
		return
	}
	WriteAudit(h.DB, c.UserID, "root", httpx.AuditIP(r), "auth.2fa.disable", "root", true)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}
