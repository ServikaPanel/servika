package pma

import (
	"context"
	"database/sql"
	"time"

	"servika/internal/logx"
)

// sweepStatement removes every token that can no longer be redeemed.
//
// A used or expired token is dead weight, and it names the tenant's database
// user and schema. The row used to be removed only as a side effect of the NEXT
// RequestToken call, so on a panel where nobody minted another one the last row
// survived indefinitely and rode into every database dump.
const sweepStatement = `DELETE FROM pma_tokens WHERE expires_at < NOW() OR used=1`

// sweepInterval is short because the tokens are: two minutes of validity means
// a row is dead almost as soon as it is written, and there is never more than a
// handful of them.
const sweepInterval = 5 * time.Minute

// StartTokenSweep removes dead signon tokens on a timer, and once at startup.
//
// The startup pass matters on its own: a panel that was stopped while tokens
// were live comes back with rows nothing else would ever delete.
func StartTokenSweep(ctx context.Context, db *sql.DB) {
	go func() {
		sweepTokens(ctx, db)
		ticker := time.NewTicker(sweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sweepTokens(ctx, db)
			}
		}
	}()
}

func sweepTokens(ctx context.Context, db *sql.DB) {
	if _, err := db.ExecContext(ctx, sweepStatement); err != nil {
		// #nosec G706 -- a MariaDB driver error for a statement with no arguments; no tenant string reaches it.
		logx.Errorf("pma: the signon tokens could not be swept: %v", err)
	}
}
