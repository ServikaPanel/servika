package datamigrate

import (
	"context"
	"database/sql"
	"fmt"

	"servika/internal/logx"
	"servika/internal/secret"
)

// credentialColumn names one stored secret to migrate. Every column listed here
// is written through secret.Encrypt and read back through secret.Decrypt.
type credentialColumn struct {
	table  string
	column string
}

// encryptedCredentials are the columns that gained at-rest encryption after rows
// already existed in them.
//
// The db_accounts and ftp_accounts columns are NOT here: internal/credentials
// backfills those itself, because it has to produce a password hash in the same
// pass while the cleartext is still readable.
var encryptedCredentials = []credentialColumn{
	{table: "github_connections", column: "pat"},
	{table: "backup_destinations", column: "password"},
}

// EncryptStoredCredentials encrypts any credential still held as legacy
// cleartext.
//
// secret.Decrypt returns a value without the encryption prefix unchanged, which
// is what let encryption be introduced without breaking existing installs. The
// cost is that a row written before that point stays readable in the database
// forever, because nothing rewrites it until its owner happens to save the
// record again. A GitHub PAT and a remote backup password are exactly the values
// SERVIKA_SECRET_KEY exists to keep out of a database dump, so leaving them in
// the clear defeats the encryption for every install that predates it.
//
// Idempotent: an already-encrypted or empty value is skipped, so this runs on
// every boot and does nothing once converged.
func EncryptStoredCredentials(ctx context.Context, db *sql.DB) {
	for _, target := range encryptedCredentials {
		migrated, err := encryptColumn(ctx, db, target)
		if err != nil {
			logx.Errorf("credential encryption backfill: %s.%s: %v", target.table, target.column, err)
			continue
		}
		if migrated > 0 {
			logx.Infof("credential encryption backfill: encrypted %d cleartext value(s) in %s.%s",
				migrated, target.table, target.column)
		}
	}
}

// encryptColumn rewrites one column and reports how many rows it changed.
func encryptColumn(ctx context.Context, db *sql.DB, target credentialColumn) (int, error) {
	// The table and column are package constants, never request input, so they
	// cannot be parameterized and cannot carry injected SQL either.
	rows, err := db.QueryContext(ctx,
		fmt.Sprintf(`SELECT id, %s FROM %s`, target.column, target.table)) // #nosec G201 -- identifiers come from encryptedCredentials, not from a request.
	if err != nil {
		return 0, err
	}
	type pending struct {
		id    int64
		value string
	}
	var work []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.value); err != nil {
			_ = rows.Close() // read-only cursor; the Close error is not actionable here
			return 0, err
		}
		if needsEncryption(p.value) {
			work = append(work, p)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close() // read-only cursor; the Close error is not actionable here
		return 0, err
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}

	migrated := 0
	for _, p := range work {
		sealed, err := secret.Encrypt(p.value)
		if err != nil {
			return migrated, err
		}
		// Matching the old value as well as the id means a record saved between
		// the read and this write keeps its newer value instead of being
		// overwritten with a re-encrypted stale one.
		if _, err := db.ExecContext(ctx,
			fmt.Sprintf(`UPDATE %s SET %s=? WHERE id=? AND %s=?`, target.table, target.column, target.column), // #nosec G201 -- identifiers come from encryptedCredentials, not from a request.
			sealed, p.id, p.value); err != nil {
			return migrated, err
		}
		migrated++
	}
	return migrated, nil
}

// needsEncryption reports whether a stored value is legacy cleartext.
//
// An empty column is skipped rather than sealed: encrypting "" produces a
// non-empty ciphertext, which would turn "no credential stored" into something
// that looks like a stored credential to every "is it set?" check.
func needsEncryption(value string) bool {
	return value != "" && !secret.IsEncrypted(value)
}
