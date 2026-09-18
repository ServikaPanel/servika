package datamigrate

import (
	"context"
	"database/sql"

	"servika/internal/git"
	"servika/internal/logx"
	"servika/internal/secret"
)

// SealGitWebhookSecrets fills git_repos.webhook_secret_hash and seals the token
// the row still holds in the clear.
//
// The token is the path segment of the delivery URL. Holding it means holding
// the URL that drives `git fetch` plus `git reset --hard` against a tenant's
// document root, so a database dump used to hand over every repository's URL.
// 0144 added the column; this pass fills it, because only the running panel has
// the sealing key.
//
// Idempotent: a row whose token is already sealed AND whose hash is already
// written is skipped, so this runs on every boot and does nothing once
// converged. A row that fails is LEFT AS IT IS rather than half written, because
// a token the panel can no longer open is worse than one still in the clear: the
// webhook registered at the remote would keep delivering to a URL nothing
// matches, with nothing on screen to explain it.
func SealGitWebhookSecrets(ctx context.Context, db *sql.DB) {
	work, ok := unsealedWebhookSecrets(ctx, db)
	if !ok {
		return
	}
	migrated := 0
	for _, row := range work {
		if sealWebhookSecret(ctx, db, row) {
			migrated++
		}
	}
	if migrated > 0 {
		logx.Infof("git webhook backfill: sealed %d webhook token(s) in git_repos", migrated)
	}
}

// pendingWebhook is one repository row this pass has work to do on.
type pendingWebhook struct {
	id       int64
	domainID int64
	stored   string
	hash     string
}

// unsealedWebhookSecrets lists the rows to convert, and reports whether the
// table could be read at all.
func unsealedWebhookSecrets(ctx context.Context, db *sql.DB) ([]pendingWebhook, bool) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, domain_id, COALESCE(webhook_secret,''), COALESCE(webhook_secret_hash,'')
		   FROM git_repos WHERE webhook_secret <> ''`)
	if err != nil {
		// An install that predates the table answers here and needs no migration.
		logx.Errorf("git webhook backfill: could not read git_repos: %v", err)
		return nil, false
	}
	var work []pendingWebhook
	for rows.Next() {
		var row pendingWebhook
		if err := rows.Scan(&row.id, &row.domainID, &row.stored, &row.hash); err != nil {
			logx.Warnf("git webhook backfill: skipping an unreadable row: %v", err)
			continue
		}
		if !secret.IsEncrypted(row.stored) || row.hash == "" {
			work = append(work, row)
		}
	}
	if err := rows.Err(); err != nil {
		// A short list leaves some tokens in the clear, and the count logged by
		// the caller would otherwise read as a complete pass.
		logx.Errorf("git webhook backfill: could not read the whole list: %v", err)
	}
	if err := rows.Close(); err != nil {
		logx.Errorf("git webhook backfill: could not close the cursor: %v", err)
	}
	return work, true
}

// sealWebhookSecret converts one row and reports whether it was written. A row
// already sealed but missing its hash cannot be converted here: the hash is
// taken from the token, and opening the seal is what recovers it.
func sealWebhookSecret(ctx context.Context, db *sql.DB, row pendingWebhook) bool {
	token, err := git.OpenWebhookSecret(row.stored, row.domainID)
	if err != nil {
		logx.Errorf("git webhook backfill: could not open the token of repository %d: %v", row.id, err)
		return false
	}
	sealed, err := git.SealWebhookSecret(token, row.domainID)
	if err != nil {
		logx.Errorf("git webhook backfill: could not seal repository %d: %v", row.id, err)
		return false
	}
	// Matching the old value as well as the id means a record saved between the
	// read and this write keeps its newer value instead of being overwritten
	// with a re-sealed stale one.
	if _, err := db.ExecContext(ctx,
		`UPDATE git_repos SET webhook_secret=?, webhook_secret_hash=? WHERE id=? AND webhook_secret=?`,
		sealed, git.WebhookSecretHash(token), row.id, row.stored); err != nil {
		logx.Errorf("git webhook backfill: could not write repository %d: %v", row.id, err)
		return false
	}
	return true
}
