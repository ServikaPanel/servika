// Package tenantaccount builds the ownership chain a tenant needs to exist in
// the panel's account model.
//
// Authorization is resolved from the database on every request, never from a
// list embedded in a token:
//
//	domains.customer_id -> customers.id -> customers.owner_user_id  (reseller)
//	                                    -> customers.user_id        (customer)
//
// Without the middle links an account can sign in and see nothing, because
// middleware.ScopeSQL narrows every list through that chain.
//
// This is deliberately separate from internal/datamigrate. That package holds
// one-shot backfills for state that predates a feature and is only meant to run
// at startup; calling it from a live request path would blur what it is for.
// The backfill delegates here instead, so one definition of "the chain" serves
// both the old rows and every new one.
package tenantaccount

import (
	"context"
	"database/sql"
	"errors"
)

// Result is what Ensure did.
//
// Reused matters to the caller because Ensure is idempotent and an existing
// customer keeps the owner it already had. A caller that ASKED for a particular
// owner therefore has to know it did not get one, rather than reporting a
// placement that never happened.
type Result struct {
	CustomerID int64
	// Reused is true when the customer already existed and was returned as it
	// stands, owner included.
	Reused bool
}

// Ensure returns the customers row for a tenant, creating the panel account and
// the customer record when they do not exist yet. It is idempotent: every step
// reuses an existing row, so a repeated call is a no-op that returns the same id.
//
// ownerUserID names the reseller the new customer belongs to, or is nil for a
// customer directly under an administrator. It is applied only when the row is
// CREATED. An existing customer is returned untouched: changing who owns an
// account already in use is a transfer, which is its own operation with its own
// authorization, not a side effect of adding a domain. The caller learns this
// from Result.Reused. A NEW domain no longer reaches the reuse branch, because
// provisioner.allocateSystemUser gives every domain a system user of its own;
// a panel upgraded from before that can still carry two domains sharing one.
//
// A RESELLER never reaches this path: it cannot create a domain without naming
// one of its own customers, so the auto-creation branch only runs on an
// administrator's authority, and the owner it passes is one it chose.
//
// The generated users row carries an EMPTY password_hash. An empty hash matches
// no password at all (auth.PasswordMatches), so the account cannot sign in until
// somebody assigns one. That is chosen over generating a password nobody is
// told: it leaves no account that has a password no one knows, and the Customer
// Accounts screen flags every passwordless row so none is missed.
func Ensure(ctx context.Context, db *sql.DB, systemUser, displayName string, ownerUserID *int64) (Result, error) {
	if systemUser == "" {
		// Nothing identifies the tenant, so there is nothing to attach an account
		// to. Returning early keeps a malformed domain row from producing an
		// account named after nobody.
		return Result{}, nil
	}
	if displayName == "" {
		displayName = systemUser
	}

	transaction, err := db.BeginTx(ctx, nil)
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = transaction.Rollback() }() // no-op once the commit succeeds

	userID, err := ensureUser(ctx, transaction, systemUser, displayName)
	if err != nil {
		return Result{}, err
	}
	customerID, reused, err := ensureCustomer(ctx, transaction, userID, displayName, ownerUserID)
	if err != nil {
		return Result{}, err
	}
	if err := transaction.Commit(); err != nil {
		return Result{}, err
	}
	return Result{CustomerID: customerID, Reused: reused}, nil
}

func ensureUser(ctx context.Context, transaction *sql.Tx, systemUser, displayName string) (int64, error) {
	var userID int64
	err := transaction.QueryRowContext(ctx,
		`SELECT id FROM users WHERE username=?`, systemUser).Scan(&userID)
	if err == nil {
		return userID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	result, err := transaction.ExecContext(ctx, `
		INSERT INTO users(username, email, password_hash, role, full_name, status)
		VALUES(?, '', '', 'user', ?, 'active')`, systemUser, displayName)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func ensureCustomer(ctx context.Context, transaction *sql.Tx, userID int64, displayName string, ownerUserID *int64) (int64, bool, error) {
	var customerID int64
	err := transaction.QueryRowContext(ctx,
		`SELECT id FROM customers WHERE user_id=?`, userID).Scan(&customerID)
	if err == nil {
		// Returned as it stands, owner included. See Ensure's comment.
		return customerID, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, false, err
	}
	// ownerUserID is bound as a value, so nil writes SQL NULL, which is what a
	// customer directly under an administrator carries.
	result, err := transaction.ExecContext(ctx, `
		INSERT INTO customers(name, email, status, notes, user_id, owner_user_id)
		VALUES(?, '', 'active', 'created with the tenant', ?, ?)`, displayName, userID, ownerUserID)
	if err != nil {
		return 0, false, err
	}
	newID, err := result.LastInsertId()
	return newID, false, err
}
