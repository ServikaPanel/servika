package datamigrate

import (
	"context"
	"database/sql"

	"servika/internal/logx"
	"servika/internal/secret"
)

// EncryptRedisPasswords seals any Redis ACL password still held as legacy
// cleartext in domain_redis.
//
// It is separate from EncryptStoredCredentials because that pass seals a column
// with secret.Encrypt, which binds nothing. A Redis password is sealed with the
// row's OWN system_user as the additional authenticated data, so a ciphertext
// lifted from one tenant's row does not open in another's. That binding needs
// the row's second column, which the generic table/column walk does not read.
//
// Idempotent: a value that already carries the encryption prefix, and an empty
// one, are both skipped, so this runs on every boot and does nothing once
// converged. A row whose sealing fails is LEFT AS IT IS rather than half
// written, because a value the panel can no longer decrypt is worse than one
// still in the clear: the tenant's cache would stop authenticating with nothing
// able to recover the password.
func EncryptRedisPasswords(ctx context.Context, db *sql.DB) {
	work, ok := cleartextRedisPasswords(ctx, db)
	if !ok {
		return
	}
	migrated := 0
	for _, p := range work {
		if sealRedisPassword(ctx, db, p) {
			migrated++
		}
	}
	if migrated > 0 {
		logx.Infof("redis password backfill: encrypted %d cleartext password(s) in domain_redis", migrated)
	}
}

// pendingRedis is one row still holding a cleartext password.
type pendingRedis struct {
	domainID   int64
	systemUser string
	password   string
}

// cleartextRedisPasswords lists the rows this pass has work to do on, and
// reports whether the table could be read at all.
func cleartextRedisPasswords(ctx context.Context, db *sql.DB) ([]pendingRedis, bool) {
	rows, err := db.QueryContext(ctx,
		`SELECT domain_id, system_user, redis_pass FROM domain_redis WHERE redis_pass <> ''`)
	if err != nil {
		// An install that predates the table answers here and needs no migration.
		logx.Errorf("redis password backfill: could not read domain_redis: %v", err)
		return nil, false
	}
	var work []pendingRedis
	for rows.Next() {
		var p pendingRedis
		if err := rows.Scan(&p.domainID, &p.systemUser, &p.password); err != nil {
			logx.Warnf("redis password backfill: skipping an unreadable row: %v", err)
			continue
		}
		if !secret.IsEncrypted(p.password) {
			work = append(work, p)
		}
	}
	if err := rows.Err(); err != nil {
		// A short list leaves some passwords in the clear, and the count logged
		// by the caller would otherwise read as a complete pass.
		logx.Errorf("redis password backfill: could not read the whole list: %v", err)
	}
	if err := rows.Close(); err != nil {
		logx.Errorf("redis password backfill: could not close the cursor: %v", err)
	}
	return work, true
}

// sealRedisPassword seals one row and reports whether it was written.
func sealRedisPassword(ctx context.Context, db *sql.DB, p pendingRedis) bool {
	sealed, err := secret.EncryptWith(p.password, p.systemUser)
	if err != nil {
		logx.Errorf("redis password backfill: could not seal domain %d: %v", p.domainID, err)
		return false
	}
	// Matching the old value as well as the id means a record saved between
	// the read and this write keeps its newer value instead of being
	// overwritten with a re-encrypted stale one.
	if _, err := db.ExecContext(ctx,
		`UPDATE domain_redis SET redis_pass=? WHERE domain_id=? AND redis_pass=?`,
		sealed, p.domainID, p.password); err != nil {
		logx.Errorf("redis password backfill: could not write domain %d: %v", p.domainID, err)
		return false
	}
	return true
}
