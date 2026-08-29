package domains

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"servika/internal/credentials"
	"servika/internal/httpx"

	"github.com/go-chi/chi/v5"
)

type setDBPwReq struct {
	Password string `json:"password"`
	// User is required ONLY when the database has no db_user yet (a database
	// restored from a backup, whose archive carries no MySQL account): the account
	// is created under this name.
	User string `json:"user"`
}

// SetDatabasePassword handles PUT /api/v1/databases/:dbid/password.
// It generates a random password when the request body is empty and rejects demo subscriptions.
func (h *Handlers) SetDatabasePassword(w http.ResponseWriter, r *http.Request) {
	dbid, _ := strconv.ParseInt(chi.URLParam(r, "dbid"), 10, 64)
	var req setDBPwReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Password == "" {
		req.Password = credentials.RandomPassword(24)
	}
	// Reject a user-supplied value that already looks like ciphertext: storing it
	// verbatim and revealing it later would turn this endpoint into a decryption
	// oracle for another account's password.
	if credentials.IsEncryptedValue(req.Password) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid password")
		return
	}
	if len(req.Password) < 6 {
		httpx.WriteError(w, http.StatusBadRequest, "password must be at least 6 characters")
		return
	}

	var dbName, dbUser string
	var isDemo int
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT db.db_name, db.db_user, d.is_demo
		 FROM db_accounts db JOIN domains d ON d.id=db.domain_id
		 WHERE db.id=?`, dbid).Scan(&dbName, &dbUser, &isDemo)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "database record not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	if isDemo == 1 {
		httpx.WriteError(w, http.StatusForbidden, "database passwords cannot be changed for demo subscriptions")
		return
	}

	if strings.TrimSpace(dbUser) == "" {
		// The database has no MySQL user. This happens when a database is deleted
		// from the panel and restored from a backup: the archive holds schema and
		// data, not the account. The panel assumed every database had a user, so the
		// site could not connect and there was no way to create one. Create it now.
		newUser := strings.TrimSpace(req.User)
		if newUser == "" {
			httpx.WriteError(w, http.StatusBadRequest, "this database has no user — send a user name to create one")
			return
		}
		if !credentials.ValidDBIdentifier(newUser) {
			httpx.WriteError(w, http.StatusBadRequest, "invalid user name")
			return
		}
		// The new name must not collide with another database's account, which would
		// hand this database's password to that account's owner.
		var clash int
		if e := h.DB.QueryRowContext(r.Context(),
			`SELECT COUNT(*) FROM db_accounts WHERE db_user=? AND id<>?`, newUser, dbid).Scan(&clash); e != nil || clash > 0 {
			httpx.WriteError(w, http.StatusConflict, "this user name is already used by another database")
			return
		}
		if err := credentials.MySQLAddUser(dbName, newUser, req.Password); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "user could not be created")
			return
		}
		encPass, err := credentials.EncryptDBPass(newUser, req.Password)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "user could not be created")
			return
		}
		if _, err := h.DB.ExecContext(r.Context(),
			`UPDATE db_accounts SET db_user=?, db_pass_plain=?, db_host='localhost' WHERE id=?`,
			newUser, encPass, dbid); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "database record could not be updated")
			return
		}
		dbUser = newUser
	} else if err := credentials.MySQLChangePassword(h.DB, dbUser, req.Password); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "password change failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"dbid":    dbid,
		"db_name": dbName,
		"db_user": dbUser,
		"db_pass": req.Password,
	})
}
