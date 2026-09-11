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
		httpx.LogR(r, "apply domain suspension state: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not update domain")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "id": id, "domain_name": domainName, "suspended": suspended,
	})
}

// ownedByDomainOrItsAddons selects the rows of a domain and of every addon that
// answers to it. Both placeholders take the same domain id.
//
// An addon domain is a full domains row carrying its PARENT's system_user, so it
// is the same Linux account, the same home directory and the same database
// namespace. Suspending the parent alone leaves that row active, and every
// CustomerScope handler resolves the tenant from whichever row the URL names, so
// the suspended customer keeps the whole surface through the addon's id.
const ownedByDomainOrItsAddons = `(domain_id=? OR domain_id IN (SELECT id FROM domains WHERE parent_domain_id=?))`

// suspensionRow is one domains row a suspension applies to, with the state to put
// back when the vhost render fails.
type suspensionRow struct {
	id        int64
	suspended int
	status    string
	// byReseller is the row's suspended_by_reseller marker. A rollback has to put
	// it back too: leaving it cleared would hand a suspension the reseller cascade
	// owns to nobody, and the next reseller resume would not lift it.
	byReseller int
}

// suspensionTargets returns the domain and every addon row that answers to it.
//
// Each row's own previous state is kept, never the parent's: an addon can be
// suspended on its own (the endpoint takes any domain id), and a rollback that
// levelled it to the parent's state would silently discard that decision.
func suspensionTargets(ctx context.Context, db *sql.DB, id int64) ([]suspensionRow, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, COALESCE(suspended,0), status, COALESCE(suspended_by_reseller,0)
		 FROM domains WHERE id=? OR parent_domain_id=? ORDER BY id`, id, id)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var targets []suspensionRow
	for rows.Next() {
		var row suspensionRow
		if err := rows.Scan(&row.id, &row.suspended, &row.status, &row.byReseller); err != nil {
			// A dropped row is a domain left active while the caller is told the
			// whole tenant was suspended, which is the defect this exists to close.
			return nil, err
		}
		targets = append(targets, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, sql.ErrNoRows
	}
	return targets, nil
}

// rerenderTargets re-renders every affected vhost. An addon has its own config
// file and applyVhostForDomain reads the suspended flag from the row it is given,
// so a parent-only render leaves the addon site serving.
func rerenderTargets(db *sql.DB, targets []suspensionRow) error {
	for _, target := range targets {
		if err := provisioner.RerenderVhost(db, target.id); err != nil {
			return err
		}
	}
	return nil
}

// restoreSuspensionState puts every row back as it was found and re-renders it.
func restoreSuspensionState(ctx context.Context, db *sql.DB, targets []suspensionRow) {
	for _, target := range targets {
		if _, err := db.ExecContext(ctx,
			`UPDATE domains SET suspended=?, status=?, suspended_by_reseller=? WHERE id=?`,
			target.suspended, target.status, target.byReseller, target.id); err != nil {
			log.Printf("rollback domain suspension state for domain %d: %v", target.id, err)
			continue
		}
		if err := provisioner.RerenderVhost(db, target.id); err != nil {
			log.Printf("restore domain vhost after suspension rollback for domain %d: %v", target.id, err)
		}
	}
}

// ApplyDomainSuspend suspends or resumes one domain AND every addon row that
// answers to it: it updates the domains rows, re-renders each vhost (rolling
// every row back on failure), cascades the state to FTP accounts, mail domains
// and mailboxes, and stops/starts the tenant runtime. It is HTTP-independent so both the handler and the reseller-wide
// cascade can call it. Returns the domain name, ErrDemoSuspend for a demo
// subscription, or sql.ErrNoRows when the domain is gone.
func ApplyDomainSuspend(ctx context.Context, db *sql.DB, id int64, suspended bool) (string, error) {
	var domainName, systemUser string
	var isDemo int
	if err := db.QueryRowContext(ctx,
		`SELECT domain_name, system_user, is_demo FROM domains WHERE id=?`, id).
		Scan(&domainName, &systemUser, &isDemo); err != nil {
		return "", err
	}
	if isDemo == 1 {
		return domainName, ErrDemoSuspend
	}
	targets, err := suspensionTargets(ctx, db, id)
	if err != nil {
		return domainName, err
	}

	value := 0
	status := "active"
	if suspended {
		value = 1
		status = "passive"
	}
	// suspended_by_reseller is CLEARED here whichever direction this goes. This is
	// the individual path: an operator naming one domain has made an explicit
	// decision about it, and that decision takes ownership of the row's state from
	// the reseller cascade. A later reseller resume then leaves the row alone,
	// which is the point of the marker.
	if _, err := db.ExecContext(ctx,
		`UPDATE domains SET suspended=?, status=?, suspended_by_reseller=0
		 WHERE id=? OR parent_domain_id=?`,
		value, status, id, id); err != nil {
		return domainName, err
	}
	if err := rerenderTargets(db, targets); err != nil {
		restoreSuspensionState(ctx, db, targets)
		return domainName, err
	}

	ftpStatus := "active"
	// Suspending bumps token_version so any active customer JWT is revoked at once;
	// resuming only restores status and leaves the version untouched.
	ftpQuery := `UPDATE ftp_accounts SET status=? WHERE ` + ownedByDomainOrItsAddons
	if suspended {
		ftpStatus = "suspended"
		ftpQuery = `UPDATE ftp_accounts SET status=?, token_version=token_version+1 WHERE ` + ownedByDomainOrItsAddons
	}
	if _, err := db.ExecContext(ctx, ftpQuery, ftpStatus, id, id); err != nil {
		log.Printf("update FTP account suspension state for domain %d: %v", id, err)
	}
	mailStatus := "active"
	if suspended {
		mailStatus = "suspended"
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE mail_domains SET status=? WHERE `+ownedByDomainOrItsAddons, mailStatus, id, id); err != nil {
		log.Printf("update mail domain suspension state for domain %d: %v", id, err)
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE mailboxes SET status=? WHERE `+ownedByDomainOrItsAddons, mailStatus, id, id); err != nil {
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
	targets, err := resellerDomainSnapshot(ctx, db, resellerID)
	if err != nil {
		return 0, 0, err
	}
	for _, target := range targets {
		if !cascadeShouldAct(target, suspended) {
			continue
		}
		if _, e := applySuspend(ctx, db, target.id, suspended); e != nil {
			if errors.Is(e, ErrDemoSuspend) {
				continue
			}
			failed++
			log.Printf("reseller %d suspend cascade: domain %d: %v", resellerID, target.id, e)
			continue
		}
		if suspended {
			// Mark AFTER the suspension succeeded, so a row the cascade failed to
			// close is not later opened by a resume that believes it closed it.
			// ApplyDomainSuspend cleared the marker on its way through; the resume
			// direction needs no counterpart, because it clears it the same way.
			if _, e := db.ExecContext(ctx,
				`UPDATE domains SET suspended_by_reseller=1 WHERE id=?`, target.id); e != nil {
				log.Printf("reseller %d suspend cascade: marking domain %d: %v", resellerID, target.id, e)
			}
		}
		affected++
	}
	return affected, failed, nil
}

// applySuspend is the per-domain step of the cascade, a test seam.
//
// ApplyDomainSuspend renders a vhost and runs `nginx -t`, which a unit test
// cannot let succeed, so the cascade's OWN decisions (which rows it acts on and
// which it marks) would otherwise only ever be observable on the failure path.
var applySuspend = ApplyDomainSuspend

// cascadeShouldAct reports whether the reseller cascade owns this row's state.
//
// Suspending: only a row that is currently OPEN. One already closed is left
// entirely alone, so the sweep does not re-render a vhost, rewrite FTP and mail
// rows and stop a tenant runtime that are already in the target state, and
// `affected` counts rows that really changed.
//
// Resuming: only a row the cascade itself closed. This is the whole fix. A
// domain an administrator suspended individually carries no marker, so it stays
// closed while the reseller comes back.
func cascadeShouldAct(target suspensionRow, suspended bool) bool {
	if suspended {
		return target.suspended == 0
	}
	return target.byReseller == 1
}

// resellerDomainSnapshot reads every domain of a reseller's customers WITH the
// state each row is in before any write.
//
// The snapshot is taken once, up front, and the loop decides from it rather than
// re-reading. An addon domain is a full domains row, so it appears in this list
// on its own AND is swept by its parent's ApplyDomainSuspend; a mid-loop re-read
// would see the write the parent just made and conclude the addon was already
// closed, so the addon would never be marked and a later resume would leave it
// down for good.
func resellerDomainSnapshot(ctx context.Context, db *sql.DB, resellerID int64) ([]suspensionRow, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT d.id, COALESCE(d.suspended,0), COALESCE(d.suspended_by_reseller,0)
		 FROM domains d JOIN customers c ON c.id = d.customer_id
		 WHERE c.owner_user_id = ? ORDER BY d.id`, resellerID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var targets []suspensionRow
	for rows.Next() {
		var target suspensionRow
		if err := rows.Scan(&target.id, &target.suspended, &target.byReseller); err != nil {
			// A dropped row is a domain that is not suspended or not resumed while
			// the count returned to the caller says it was.
			log.Printf("suspend: skipping an unreadable domain row: %v", err)
			continue
		}
		targets = append(targets, target)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return targets, nil
}
