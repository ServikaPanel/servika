package git

// The webhook URL token is stored sealed and matched by hash.
//
// The token is the path segment of the delivery URL, so it is not a signing key:
// 0136 moved the HMAC key into its own column for that reason. It is still worth
// protecting at rest, because holding it means holding the URL that drives
// `git fetch` plus `git reset --hard` against a tenant's document root, and a
// database dump used to hand over every repository's URL in the clear.
//
// The seal is non-deterministic, so it cannot appear in a WHERE clause. The
// SHA-256 digest can, and it gives nothing away: a 40-character random token is
// not recoverable from its digest.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"strconv"

	"servika/internal/secret"
)

// WebhookSecretHash is the lookup value for a delivery token.
func WebhookSecretHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// webhookSecretAAD binds a sealed token to the domain that owns the repository,
// so a ciphertext moved to another row does not open.
func webhookSecretAAD(domainID int64) string {
	return "git-webhook:" + strconv.FormatInt(domainID, 10)
}

// SealWebhookSecret returns the value to store in git_repos.webhook_secret. A
// failure to seal is returned rather than stored in the clear, because a row
// that silently keeps the plaintext is the state this replaces.
func SealWebhookSecret(token string, domainID int64) (string, error) {
	return secret.EncryptWith(token, webhookSecretAAD(domainID))
}

// OpenWebhookSecret reverses SealWebhookSecret. A value written before the seal
// existed carries no prefix and comes back unchanged, so an old row keeps
// working until the backfill reaches it.
func OpenWebhookSecret(stored string, domainID int64) (string, error) {
	return secret.DecryptWith(stored, webhookSecretAAD(domainID))
}

// StoredWebhookToken reads one repository's token in the clear. It is the one
// place that opens the seal for a caller that needs the token itself, which is
// internal/github registering the hook at GitHub. An unreadable or missing row
// answers empty, and the caller then generates a fresh token.
func StoredWebhookToken(ctx context.Context, db *sql.DB, domainID int64) string {
	var stored string
	if err := db.QueryRowContext(ctx,
		`SELECT COALESCE(webhook_secret,'') FROM git_repos WHERE domain_id=?`, domainID).
		Scan(&stored); err != nil || stored == "" {
		return ""
	}
	token, err := OpenWebhookSecret(stored, domainID)
	if err != nil {
		return ""
	}
	return token
}
