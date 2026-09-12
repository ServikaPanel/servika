// Package datamigrate holds one-shot data migrations that run once per version
// upgrade at server startup.
//
// Unlike SQL migrations, these produce DATA (not schema) and need Go-side
// computation (bcrypt hashing, grouping, and so on). Every migration here is
// idempotent: it runs on each boot and exits silently when there is no work.
package datamigrate

import (
	"context"
	"database/sql"

	"servika/internal/logx"
	"servika/internal/tenantaccount"
)

// BackfillCustomerAccounts moves existing domains onto the multi-user account
// model.
//
// The panel began as single-admin: customers signed into /cp with their FTP
// identity only, so neither a customers record nor a panel login account
// existed. This migration produces the missing links for every existing tenant:
//
//	domains.system_user  (tenant)
//	   -> customers       (billing/contact record)
//	        -> users      (role='user', the panel login account)
//
// Grouped by TENANT, not by domain: one tenant may own several domains
// (addon/parked) and in the cPanel model they belong to a SINGLE account.
// Producing one account per domain would create multiple panel accounts for the
// same system user.
//
// The generated users rows are left with an EMPTY password_hash. An empty hash
// never matches any password (see auth.PasswordMatches), so these accounts
// cannot log in until an admin or reseller assigns a password from the Customer
// Accounts screen. This was chosen over generating a random password no one is
// told: it leaves no "has a password but nobody knows it" accounts, and the
// Customer Accounts list flags every passwordless row so none is overlooked.
func BackfillCustomerAccounts(ctx context.Context, db *sql.DB) {
	// Tenants that still have domains not linked to a customer record.
	rows, err := db.QueryContext(ctx, `
		SELECT system_user, MIN(domain_name), COUNT(*)
		FROM domains
		WHERE customer_id IS NULL AND system_user <> ''
		GROUP BY system_user`)
	if err != nil {
		logx.Errorf("customer account backfill: could not read tenant list: %v", err)
		return
	}
	type tenant struct {
		systemUser string
		domainName string
		domains    int
	}
	var list []tenant
	for rows.Next() {
		var t tenant
		if err := rows.Scan(&t.systemUser, &t.domainName, &t.domains); err == nil {
			list = append(list, t)
		}
	}
	if err := rows.Err(); err != nil {
		// A tenant missing from this list keeps no customer account, and the
		// backfill runs once at startup, so the gap is not retried.
		logx.Errorf("customer account backfill: could not read the tenant list: %v", err)
	}
	_ = rows.Close() // read-only query: closing the result set has nothing to flush
	if len(list) == 0 {
		return
	}

	var created, skipped int
	for _, t := range list {
		if err := migrateTenant(ctx, db, t.systemUser, t.domainName); err != nil {
			logx.Warnf("customer account backfill: %s skipped: %v", t.systemUser, err)
			skipped++
			continue
		}
		created++
	}
	logx.Infof("customer account backfill: %d tenants migrated, %d skipped (FTP login stays valid until a password is set)",
		created, skipped)
}

// migrateTenant links one tenant's existing domains to an account.
//
// Building the account itself belongs to internal/tenantaccount, which is also
// what domain creation calls, so an old tenant and a new one end up with the
// same chain rather than two definitions of it that can drift apart.
func migrateTenant(ctx context.Context, db *sql.DB, systemUser, domainName string) error {
	// A nil owner is what these rows already carry: this backfill repairs tenants
	// that predate the account model, and nothing in that history names a reseller
	// to attribute them to. Guessing one would hand old domains to an account that
	// never had them.
	account, err := tenantaccount.Ensure(ctx, db, systemUser, domainName, nil)
	if err != nil {
		return err
	}
	if account.CustomerID == 0 {
		return nil // no tenant to attach anything to
	}
	_, err = db.ExecContext(ctx, `
		UPDATE domains SET customer_id=?
		WHERE system_user=? AND customer_id IS NULL`, account.CustomerID, systemUser)
	return err
}
