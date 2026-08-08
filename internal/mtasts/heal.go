package mtasts

import (
	"context"
	"database/sql"
	"log"
	"time"
)

// Advancing the publication sequence.
//
// Every step after the customer presses the button waits on something outside
// the panel: a DNS record to propagate, then a certificate to be reissued with
// the new name. Neither has a completion signal, so the sequence is advanced by
// a heal that re-measures the world rather than by a callback.

const (
	// healInterval is how often the sequence is re-measured. DNS propagation and
	// certificate renewal both move on the scale of tens of minutes, so a faster
	// pass would only repeat the same resolver queries.
	healInterval = 15 * time.Minute
	// healStartDelay keeps the first pass out of the boot path.
	healStartDelay = 3 * time.Minute
)

// StartHeal advances every domain's publication sequence on a timer.
func StartHeal(db *sql.DB) {
	go func() {
		time.Sleep(healStartDelay)
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			if err := Heal(ctx, db); err != nil {
				log.Printf("mtasts heal: %v", err)
			}
			cancel()
			time.Sleep(healInterval)
		}
	}()
}

// pendingDomain is one row the heal may move.
type pendingDomain struct {
	id         int64
	domainName string
	mode       Mode
	policyID   string
	// withdrawnFor is how many seconds the domain has been withdrawing, or -1
	// when it is not withdrawing or the timestamp is missing.
	withdrawnFor int64
}

// Heal moves every domain that is waiting on the world to its next step.
func Heal(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx,
		`SELECT d.id, d.domain_name, md.mtasts_mode, md.mtasts_id,
		        COALESCE(TIMESTAMPDIFF(SECOND, md.mtasts_changed_at, NOW()), -1)
		   FROM mail_domains md
		   JOIN domains d ON d.id = md.domain_id
		  WHERE md.status = 'active'
		    AND md.mtasts_mode IN ('pending_dns','pending_cert','withdrawing')
		  ORDER BY d.id`)
	if err != nil {
		return err
	}
	var pending []pendingDomain
	for rows.Next() {
		var row pendingDomain
		var mode string
		if err := rows.Scan(&row.id, &row.domainName, &mode, &row.policyID, &row.withdrawnFor); err != nil {
			_ = rows.Close()
			return err
		}
		row.mode = Mode(mode)
		pending = append(pending, row)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}

	for _, row := range pending {
		// One domain's blocked resolver must not stop the rest, so a failure is
		// logged against that domain and the pass continues.
		if err := advance(ctx, db, row); err != nil {
			log.Printf("mtasts heal for domain %d in %s: %v", row.id, describe(row.mode), err)
		}
	}
	return nil
}

func advance(ctx context.Context, db *sql.DB, row pendingDomain) error {
	switch row.mode {
	case ModePendingDNS:
		if !dnsResolves(row.domainName) {
			return nil // the record has not propagated yet
		}
		// The name is now eligible for the SAN set, so the next certificate the
		// SSL heal issues will carry it. Nothing is ordered from here: issuance
		// belongs to that heal, and racing it would spend a Let's Encrypt weekly
		// allowance on a duplicate order.
		_, err := setMode(ctx, db, row.id, ModePendingCert, false)
		return err

	case ModePendingCert:
		if !certCovers(row.domainName) {
			return nil // the certificate does not name the policy host yet
		}
		// The vhost now serves the policy path, so the id may be advertised.
		// This is the first moment a sender told about the policy could actually
		// fetch it.
		id, err := setMode(ctx, db, row.id, ModeTesting, true)
		if err != nil {
			return err
		}
		return WritePolicyTXT(ctx, db, row.id, id)

	case ModeWithdrawing:
		// A sender caches for max_age, and testing publishes the shorter one, so
		// the longer wait is the only safe assumption: the domain may have been
		// in enforce when the withdrawal started.
		if row.withdrawnFor < 0 || row.withdrawnFor < MaxAgeEnforce {
			return nil
		}
		if err := RemoveRecords(ctx, db, row.id); err != nil {
			return err
		}
		_, err := setMode(ctx, db, row.id, ModeOff, false)
		return err
	}
	return nil
}
