package apps

import (
	"context"
	"database/sql"
	"fmt"

	"servika/internal/logx"
)

// enableUnit and disableUnit name the two systemd calls the suspension path
// makes. They are variables so a test can record WHICH applications the path
// decides to act on, which is the whole of the behaviour, on a machine that has
// no systemd to answer.
var (
	enableUnit  = Enable
	disableUnit = Disable
)

// SuspendForUser stops or restores every application belonging to one tenant.
//
// A suspension that only killed the processes would not hold: the units carry
// Restart=always, so systemd brings a killed application straight back and the
// suspended account keeps serving. Restoring starts only what the database says
// was running, so an application the customer had stopped stays stopped.
//
// The stored `enabled` flag is NOT touched, because it records what the customer
// chose and a suspension is not their choice.
func SuspendForUser(ctx context.Context, db *sql.DB, systemUser string, suspended bool) error {
	if !ValidSystemUser(systemUser) {
		return fmt.Errorf("invalid system user: %q", systemUser)
	}
	list, err := ListForSystemUser(ctx, db, systemUser)
	if err != nil {
		return fmt.Errorf("read the applications of %s: %w", systemUser, err)
	}
	var failures int
	for _, app := range list {
		if suspended {
			if err := disableUnit(app.ID); err != nil {
				logx.Errorf("apps: suspend application %d of %s: %v", app.ID, systemUser, err)
				failures++
			}
			continue
		}
		if !app.Enabled {
			continue // stopped by the customer before the suspension
		}
		if err := enableUnit(app.ID); err != nil {
			logx.Errorf("apps: resume application %d of %s: %v", app.ID, systemUser, err)
			failures++
		}
	}
	if failures > 0 {
		return fmt.Errorf("%d of %d applications did not answer", failures, len(list))
	}
	return nil
}

// TeardownForDomain removes every application a domain owns from the host.
//
// The rows go with the domain through the foreign key, but the units, the
// environment files and the logs do not, and a unit left behind keeps its port
// out of the allocator's reach for good.
func TeardownForDomain(ctx context.Context, db *sql.DB, domainID int64) {
	list, err := ListForDomain(ctx, db, domainID)
	if err != nil {
		logx.Errorf("apps: read the applications of domain %d for teardown: %v", domainID, err)
		return
	}
	for _, app := range list {
		Teardown(app.ID)
	}
}
