package datamigrate

import (
	"context"
	"database/sql"

	"servika/internal/auth"
	"servika/internal/logx"
	"servika/internal/secret"
)

// EncryptTOTPSecrets seals any TOTP seed still held as legacy cleartext.
//
// It is separate from EncryptStoredCredentials because that helper seals with no
// associated data, and this seal binds the user id: without that binding a
// ciphertext could be copied from one users row into another, and whoever holds
// the source account's authenticator would satisfy the target account's second
// factor.
//
// secret.DecryptWith returns a value without the encryption prefix unchanged,
// which is what lets the seal be introduced without locking anybody out. The cost
// is that a row written before that point stays readable in the database until
// something rewrites it, and nothing does: a seed is written once, when 2FA is
// enabled. So this converts them.
//
// Idempotent: an already-sealed or empty value is skipped, so this runs on every
// boot and does nothing once converged.
func EncryptTOTPSecrets(ctx context.Context, db *sql.DB) {
	work, ok := cleartextTOTPSeeds(ctx, db)
	if !ok {
		return
	}
	migrated := 0
	for _, p := range work {
		if sealTOTPSeed(ctx, db, p) {
			migrated++
		}
	}
	if migrated > 0 {
		logx.Infof("TOTP secret backfill: sealed %d cleartext seed(s) in users", migrated)
	}
}

// pendingSeed is one user row still holding a cleartext seed.
type pendingSeed struct {
	id    int64
	value string
}

// cleartextTOTPSeeds lists the rows this pass has work to do on, and reports
// whether the table could be read at all.
func cleartextTOTPSeeds(ctx context.Context, db *sql.DB) ([]pendingSeed, bool) {
	rows, err := db.QueryContext(ctx, `SELECT id, totp_secret FROM users WHERE totp_secret <> ''`)
	if err != nil {
		logx.Errorf("TOTP secret backfill: could not read the list: %v", err)
		return nil, false
	}
	var work []pendingSeed
	for rows.Next() {
		var p pendingSeed
		if err := rows.Scan(&p.id, &p.value); err != nil {
			logx.Warnf("TOTP secret backfill: skipping an unreadable row: %v", err)
			continue
		}
		if !secret.IsEncrypted(p.value) {
			work = append(work, p)
		}
	}
	if err := rows.Err(); err != nil {
		// A short list leaves some seeds in the clear, and the count logged by the
		// caller would otherwise read as a complete pass.
		logx.Errorf("TOTP secret backfill: could not read the whole list: %v", err)
	}
	if err := rows.Close(); err != nil {
		logx.Errorf("TOTP secret backfill: could not close the cursor: %v", err)
	}
	return work, true
}

// sealTOTPSeed seals one row and reports whether it was written.
func sealTOTPSeed(ctx context.Context, db *sql.DB, p pendingSeed) bool {
	sealed, err := auth.SealTOTPSecret(p.value, p.id)
	if err != nil {
		logx.Errorf("TOTP secret backfill: could not seal user %d: %v", p.id, err)
		return false
	}
	// Matching the old value as well as the id means a record saved between
	// the read and this write keeps its newer value instead of being
	// overwritten with a re-sealed stale one. That matters here more than
	// elsewhere: overwriting a seed the user has just re-enrolled would lock
	// them out of their own second factor.
	if _, err := db.ExecContext(ctx,
		`UPDATE users SET totp_secret=? WHERE id=? AND totp_secret=?`,
		sealed, p.id, p.value); err != nil {
		logx.Errorf("TOTP secret backfill: could not write user %d: %v", p.id, err)
		return false
	}
	return true
}
