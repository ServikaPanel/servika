// Package pma provides one-time phpMyAdmin SSO token creation and redemption.
package pma

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"servika/internal/config"
	"servika/internal/credentials"
	"servika/internal/httpx"
	"servika/internal/middleware"

	"github.com/go-chi/chi/v5"
)

// Handlers provides HTTP handlers for phpMyAdmin SSO.
type Handlers struct {
	DB *sql.DB
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// internalAuthToken returns the static token used by signon.php to call the panel.
// It denies access when the token file is unavailable.
func internalAuthToken() string {
	b, err := os.ReadFile(config.PMATokenPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// RequestToken creates a short-lived token for opening phpMyAdmin through pma-signon.php.
// URL: POST /api/v1/databases/{dbId}/pma-token
func (h *Handlers) RequestToken(w http.ResponseWriter, r *http.Request) {
	dbID, _ := strconv.ParseInt(chi.URLParam(r, "dbId"), 10, 64)

	// Read database details and join the domain for the demo check.
	//
	// The PASSWORD is deliberately not read here. The token stores a reference to
	// this account and Redeem opens the sealed column at redemption time, so the
	// credential never exists in a second place at rest. Copying the decrypted
	// value into the token row defeated the at-rest encryption of that column for
	// every database whose owner ever opened phpMyAdmin, and put a reusable
	// cleartext tenant password into every panel database dump.
	var dbUser, dbName string
	var domainID int64
	var demo int
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT db.db_user, db.db_name, db.domain_id FROM db_accounts db JOIN domains d ON d.id=db.domain_id
		 WHERE db.id=?`, dbID).Scan(&dbUser, &dbName, &domainID)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "database not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database operation failed")
		return
	}
	if !middleware.DomainOwnedBy(r, domainID) {
		httpx.WriteError(w, http.StatusNotFound, "database not found")
		return
	}
	// This route is keyed by dbId, so CustomerScope (which reads "id") cannot gate it.
	// Apply the same suspended-domain check here so a suspended customer cannot mint a
	// phpMyAdmin signon token that bypasses the suspension boundary.
	if !middleware.EnforceCustomerNotSuspended(w, r, domainID) {
		return
	}
	if demo == 1 {
		httpx.WriteError(w, http.StatusForbidden, "phpMyAdmin is unavailable for demo subscriptions")
		return
	}

	token, err := randomHex(24)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to create a secure signon token")
		return
	}
	expires := time.Now().Add(2 * time.Minute) // Two-minute validity window, for the response only.

	// Write expires_at with the MySQL clock. A Go-side time.Now() (UTC in the driver) mixed
	// with a server-local NOW() makes a fresh token look already expired on hosts whose MySQL
	// session timezone is not UTC, so the cleanup below deletes it instantly and redeem 404s.
	_, err = h.DB.ExecContext(r.Context(),
		`INSERT INTO pma_tokens(token, domain_id, db_account_id, db_user, db_name, expires_at)
		 VALUES(?,?,?,?,?, DATE_ADD(NOW(), INTERVAL 120 SECOND))`,
		token, domainID, dbID, dbUser, dbName)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database operation failed")
		return
	}

	// Delete expired and used tokens on each request. This is a convenience, not
	// the cleanup: it only runs when somebody mints the NEXT token, so on a panel
	// where nobody does the rows survive. StartTokenSweep is what bounds them.
	_, _ = h.DB.ExecContext(r.Context(), sweepStatement)

	// The token is delivered to pma-signon.php in a POST body, never in a URL, so it
	// cannot leak through browser history, proxy access logs, or Referer headers.
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"token":            token,
		"expires_at":       expires.Format(time.RFC3339),
		"validity_seconds": 120,
	})
}

// Redeem validates internal authentication, returns credentials as JSON, and consumes the token once.
// URL: POST /api/v1/internal/pma-redeem  (X-Internal-Auth header)
func (h *Handlers) Redeem(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("X-Internal-Auth")
	expected := internalAuthToken()
	if expected == "" || auth == "" || subtle.ConstantTimeCompare([]byte(auth), []byte(expected)) != 1 {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		httpx.WriteError(w, http.StatusBadRequest, "token is required")
		return
	}

	var dbUser, dbName, storedPassword string
	var used, expired int
	// Evaluate expiry with the MySQL clock so it matches how expires_at was written and how
	// the consume UPDATE below compares it. A Go-side comparison can reject a valid token.
	//
	// The password comes from db_accounts through the token's reference, not from
	// the token row: the token carries no credential at all. The join is INNER,
	// so a token whose account was deleted in the two-minute window answers "not
	// found" rather than serving a stale credential.
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT t.db_user, t.db_name, a.db_pass_plain, t.used, (t.expires_at < NOW())
		 FROM pma_tokens t JOIN db_accounts a ON a.id=t.db_account_id
		 WHERE t.token=?`, req.Token).
		Scan(&dbUser, &dbName, &storedPassword, &used, &expired)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "token not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database operation failed")
		return
	}
	if used == 1 {
		httpx.WriteError(w, http.StatusGone, "token has already been used")
		return
	}
	if expired == 1 {
		httpx.WriteError(w, http.StatusGone, "token has expired")
		return
	}

	result, err := h.DB.ExecContext(r.Context(),
		`UPDATE pma_tokens SET used=1 WHERE token=? AND used=0 AND expires_at >= NOW()`, req.Token)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database operation failed")
		return
	}
	consumed, err := result.RowsAffected()
	if err != nil || consumed != 1 {
		httpx.WriteError(w, http.StatusGone, "token is no longer valid")
		return
	}

	// db_pass_plain is sealed at rest, bound to db_user. Decrypting happens HERE,
	// after the token is consumed, so a failed decrypt cannot be used to probe
	// the same token twice. A legacy plaintext row passes through unchanged.
	dbPassword, derr := credentials.DecryptDBPass(dbUser, storedPassword)
	if derr != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database operation failed")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"username": dbUser,
		"password": dbPassword,
		"db":       dbName,
		"host":     "localhost",
	})
}
