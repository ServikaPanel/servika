package wordpress

// The generated administrator password never travels in the install response.
// It is sealed into wp_install_passwords instead, and the owner takes it once
// from the reveal endpoint, which deletes the row as it answers.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"servika/internal/httpx"
	"servika/internal/secret"
)

// installPasswordAAD binds the sealed password to the row that holds it. A
// ciphertext copied into another domain's row, or into another install
// directory of the same domain, fails to open instead of revealing a password
// for a site its holder does not own.
func installPasswordAAD(domainID int64, target string) string {
	return "wp-install:" + strconv.FormatInt(domainID, 10) + ":" + target
}

// storeInstallPassword seals the password for one install directory. A repeated
// install into the same directory replaces the earlier row, because the earlier
// password no longer opens the site.
func storeInstallPassword(ctx context.Context, db *sql.DB, domainID int64, target, adminUser, password string) error {
	sealed, err := secret.EncryptWith(password, installPasswordAAD(domainID, target))
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx,
		`INSERT INTO wp_install_passwords (domain_id, target, admin_user, admin_password)
		      VALUES (?,?,?,?)
		 ON DUPLICATE KEY UPDATE admin_user=VALUES(admin_user),
		                         admin_password=VALUES(admin_password),
		                         created_at=CURRENT_TIMESTAMP`,
		domainID, target, adminUser, sealed)
	return err
}

// rememberInstallPassword seals the password and reports whether the owner can
// still take it. A failure is logged and answered, never swallowed: a caller
// told the site is ready would otherwise find no password to reveal.
func (h *Handlers) rememberInstallPassword(r *http.Request, domainID int64, target, adminUser, password string) bool {
	if err := storeInstallPassword(r.Context(), h.DB, domainID, target, adminUser, password); err != nil {
		httpx.LogR(r, "wordpress install password store: %v", err)
		return false
	}
	return true
}

// forgetInstallPassword drops the stored password for one install directory. It
// runs when the install itself goes away, so a later install into the same path
// cannot reveal the previous site's password.
func forgetInstallPassword(ctx context.Context, db *sql.DB, domainID int64, target string) {
	_, _ = db.ExecContext(ctx,
		`DELETE FROM wp_install_passwords WHERE domain_id=? AND target=?`, domainID, target)
}

// storedPasswordTargets returns the install directories of one domain that still
// hold an unread password. The list endpoint uses it to mark the installs whose
// password the owner can still take.
func storedPasswordTargets(ctx context.Context, db *sql.DB, domainID int64) map[string]bool {
	out := map[string]bool{}
	rows, err := db.QueryContext(ctx,
		`SELECT target FROM wp_install_passwords WHERE domain_id=?`, domainID)
	if err != nil {
		return out
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var target string
		if err := rows.Scan(&target); err != nil {
			return out
		}
		out[target] = true
	}
	if rows.Err() != nil {
		return map[string]bool{}
	}
	return out
}

// takeInstallPassword deletes the row and returns what it held, in one
// statement. MariaDB's DELETE ... RETURNING makes the read and the delete
// atomic without a transaction, so two concurrent requests cannot both read the
// same password.
func takeInstallPassword(ctx context.Context, db *sql.DB, domainID int64, target string) (user, password string, err error) {
	var sealed string
	if err := db.QueryRowContext(ctx,
		`DELETE FROM wp_install_passwords WHERE domain_id=? AND target=?
		  RETURNING admin_user, admin_password`, domainID, target).
		Scan(&user, &sealed); err != nil {
		return "", "", err
	}
	password, err = secret.DecryptWith(sealed, installPasswordAAD(domainID, target))
	if err != nil {
		return "", "", err
	}
	return user, password, nil
}

// POST /domains/{id}/wordpress/install-password reveals the generated
// administrator password once and forgets it.
func (h *Handlers) RevealInstallPassword(w http.ResponseWriter, r *http.Request) {
	id, _, _, root, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	var request struct {
		Dir string `json:"dir"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	dir, err := resolveDirectory(root, request.Dir)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request")
		return
	}
	user, password, err := takeInstallPassword(r.Context(), h.DB, id, dir)
	if err != nil {
		// A missing row and an unreadable one answer alike. The password is gone
		// either way, and the caller cannot act on the difference.
		if !errors.Is(err, sql.ErrNoRows) {
			httpx.LogR(r, "wordpress install password reveal: %v", err)
		}
		httpx.WriteError(w, http.StatusNotFound, "no stored password for this installation")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "admin_user": user, "admin_password": password,
	})
}
