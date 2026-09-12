// Package sessionrevoke ends ONE session on the server.
//
// This is a different question from users.token_version. token_version is per
// ACCOUNT: bumping it refuses every token the account holds, which is what
// POST /me/sessions/revoke means and what a password change must do. A logout
// surrenders one session, and taking every other device down with it is not
// what the button says. So a logout records the token's own jti claim here and
// leaves token_version alone.
//
// A row is dead once the token it names has expired, because the token is
// refused on its exp anyway. Sweep deletes those, so the table holds at most
// the sessions signed out inside one token lifetime.
package sessionrevoke

import (
	"context"
	"database/sql"
	"time"

	"servika/internal/logx"
)

// Revoke records that this session identifier must no longer be accepted.
//
// INSERT IGNORE, so a client that posts the logout twice (the browser retries,
// or two tabs both fire it) is not an error. expiresAt is the token's own exp
// and only tells the sweep when the row stops mattering.
func Revoke(ctx context.Context, db *sql.DB, jti string, expiresAt time.Time) error {
	if db == nil || jti == "" {
		return nil
	}
	_, err := db.ExecContext(ctx,
		`INSERT IGNORE INTO revoked_sessions (jti, expires_at) VALUES (?, ?)`,
		jti, expiresAt.UTC())
	return err
}

// Listed answers 1 when this session identifier has been signed out, 0 when it
// has not.
//
// COUNT rather than SELECT 1, so an absent row is a VALUE and not
// sql.ErrNoRows. The caller (middleware.RequireAuth) feeds this through the
// same retry-and-fall-back reader the token_version check uses, and that reader
// treats ErrNoRows as an answer it must not cache or retry, which is the wrong
// reading here: "no row" is the common case, not a missing identity.
func Listed(ctx context.Context, db *sql.DB, jti string) (int64, error) {
	var listed int64
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM revoked_sessions WHERE jti=?`, jti).Scan(&listed)
	return listed, err
}

// sweepStatement removes every row whose token has expired on its own.
const sweepStatement = `DELETE FROM revoked_sessions WHERE expires_at < UTC_TIMESTAMP()`

// sweepInterval is an hour: the shortest thing a row outlives is one token
// lifetime, and the table is small enough that a tighter pass buys nothing.
const sweepInterval = time.Hour

// StartSweep removes expired rows on a timer, and once at startup.
//
// The startup pass matters on its own: a panel stopped for a day comes back
// with rows nothing else would ever delete.
func StartSweep(ctx context.Context, db *sql.DB) {
	go func() {
		sweep(ctx, db)
		ticker := time.NewTicker(sweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sweep(ctx, db)
			}
		}
	}()
}

func sweep(ctx context.Context, db *sql.DB) {
	if _, err := db.ExecContext(ctx, sweepStatement); err != nil {
		// #nosec G706 -- a MariaDB driver error for a statement with no arguments; no tenant string reaches it.
		logx.Errorf("sessionrevoke: the expired rows could not be swept: %v", err)
	}
}
