package domains

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net/http"
	"strconv"

	"servika/internal/apps"
	"servika/internal/httpx"
	"servika/internal/provisioner"

	"github.com/go-chi/chi/v5"
)

// Suspend marks a domain as suspended and re-renders its vhost.
func (h *Handlers) Suspend(w http.ResponseWriter, r *http.Request) {
	h.setSuspended(w, r, true)
}

// Resume restores a suspended domain and re-renders its vhost.
func (h *Handlers) Resume(w http.ResponseWriter, r *http.Request) {
	h.setSuspended(w, r, false)
}

// ErrDemoSuspend is returned by ApplyDomainSuspend for a demo subscription,
// which can never be suspended. The reseller-wide cascade treats it as a skip.
var ErrDemoSuspend = errors.New("demo subscriptions cannot be suspended")

func (h *Handlers) setSuspended(w http.ResponseWriter, r *http.Request, suspended bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid domain ID")
		return
	}
	domainName, err := ApplyDomainSuspend(r.Context(), h.DB, id, suspended)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if errors.Is(err, ErrDemoSuspend) {
		httpx.WriteError(w, http.StatusForbidden, "demo subscriptions cannot be suspended")
		return
	}
	if err != nil {
		log.Printf("apply domain suspension state: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not update domain")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "id": id, "domain_name": domainName, "suspended": suspended,
	})
}

// ApplyDomainSuspend suspends or resumes one domain: it updates the domains row,
// re-renders the vhost (rolling the DB row back on failure), cascades the state
// to FTP accounts, mail domains and mailboxes, and stops/starts the tenant
// runtime. It is HTTP-independent so both the handler and the reseller-wide
// cascade can call it. Returns the domain name, ErrDemoSuspend for a demo
// subscription, or sql.ErrNoRows when the domain is gone.
func ApplyDomainSuspend(ctx context.Context, db *sql.DB, id int64, suspended bool) (string, error) {
	var domainName, systemUser, previousStatus string
	var isDemo, previousSuspended int
	if err := db.QueryRowContext(ctx,
		`SELECT domain_name, system_user, is_demo, status, COALESCE(suspended,0) FROM domains WHERE id=?`, id).
		Scan(&domainName, &systemUser, &isDemo, &previousStatus, &previousSuspended); err != nil {
		return "", err
	}
	if isDemo == 1 {
		return domainName, ErrDemoSuspend
	}

	value := 0
	status := "active"
	if suspended {
		value = 1
		status = "passive"
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE domains SET suspended=?, status=? WHERE id=?`, value, status, id); err != nil {
		return domainName, err
	}
	if err := provisioner.RerenderVhost(db, id); err != nil {
		if _, rollbackErr := db.ExecContext(ctx,
			`UPDATE domains SET suspended=?, status=? WHERE id=?`, previousSuspended, previousStatus, id); rollbackErr != nil {
			log.Printf("rollback domain suspension state: %v", rollbackErr)
		} else if restoreErr := provisioner.RerenderVhost(db, id); restoreErr != nil {
			log.Printf("restore domain vhost after suspension rollback: %v", restoreErr)
		}
		return domainName, err
	}

	ftpStatus := "active"
	// Suspending bumps token_version so any active customer JWT is revoked at once;
	// resuming only restores status and leaves the version untouched.
	ftpQuery := `UPDATE ftp_accounts SET status=? WHERE domain_id=?`
	if suspended {
		ftpStatus = "suspended"
		ftpQuery = `UPDATE ftp_accounts SET status=?, token_version=token_version+1 WHERE domain_id=?`
	}
	if _, err := db.ExecContext(ctx, ftpQuery, ftpStatus, id); err != nil {
		log.Printf("update FTP account suspension state for domain %d: %v", id, err)
	}
	mailStatus := "active"
	if suspended {
		mailStatus = "suspended"
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE mail_domains SET status=? WHERE domain_id=?`, mailStatus, id); err != nil {
		log.Printf("update mail domain suspension state for domain %d: %v", id, err)
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE mailboxes SET status=? WHERE domain_id=?`, mailStatus, id); err != nil {
		log.Printf("update mailbox suspension state for domain %d: %v", id, err)
	}
	if systemUser != "" {
		provisioner.SuspendUserRuntime(systemUser, suspended)
		// Separate from the pkill above: an application unit carries
		// Restart=always, so a killed process is back within seconds and the
		// suspended account keeps serving until systemd is told to stop it.
		if err := apps.SuspendForUser(ctx, db, systemUser, suspended); err != nil {
			log.Printf("apply application suspension state for domain %d: %v", id, err)
		}
	}
	return domainName, nil
}

// SuspendResellerDomains applies the suspend/resume state to every domain owned
// by a reseller's customers (domains.customer_id -> customers.owner_user_id).
// A demo subscription is skipped; other per-domain failures are counted and
// logged but do not stop the sweep. Servika already cascades the reseller's
// customer panel logins in users.SetStatus and blocks new domain creation while
// the customer login is suspended (EnforceCustomerNotSuspended), so no separate
// lock is needed to stop a domain being created mid-sweep and escaping suspension.
func SuspendResellerDomains(ctx context.Context, db *sql.DB, resellerID int64, suspended bool) (affected, failed int, err error) {
	rows, err := db.QueryContext(ctx,
		`SELECT d.id FROM domains d JOIN customers c ON c.id = d.customer_id WHERE c.owner_user_id = ?`, resellerID)
	if err != nil {
		return 0, 0, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			// A dropped id is a domain that is not suspended or not resumed while
			// the count returned to the caller says it was.
			log.Printf("suspend: skipping an unreadable domain id: %v", err)
			continue
		}
		ids = append(ids, id)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	for _, id := range ids {
		if _, e := ApplyDomainSuspend(ctx, db, id, suspended); e != nil {
			if errors.Is(e, ErrDemoSuspend) {
				continue
			}
			failed++
			log.Printf("reseller %d suspend cascade: domain %d: %v", resellerID, id, e)
			continue
		}
		affected++
	}
	return affected, failed, nil
}
