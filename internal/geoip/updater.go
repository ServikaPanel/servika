package geoip

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"time"
)

// Keeping the country database current.
//
// MaxMind rebuilds GeoLite2 twice a week. A daily check is enough to be within
// a day of a release without spending the operator's download allowance on
// editions that have not changed.

const (
	updateInterval   = 24 * time.Hour
	updateStartDelay = 5 * time.Minute
)

// StartUpdater refreshes the country database on a timer.
//
// With no credentials it does nothing at all rather than failing once a day:
// the feature is off, and an error log every morning would report a decision
// the operator already made.
func StartUpdater(db *sql.DB) {
	go func() {
		time.Sleep(updateStartDelay)
		for {
			refresh(db)
			time.Sleep(updateInterval)
		}
	}()
}

func refresh(db *sql.DB) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	if _, err := Credentials(ctx, db); err != nil {
		return // the feature is off; nothing to report
	}
	// A database already on disk is refreshed, but a download failure with a
	// usable database present is a warning, not a reason to stop enforcing what
	// is already there.
	if err := Download(ctx, db); err != nil {
		if errors.Is(err, ErrNoCredentials) {
			return
		}
		log.Printf("geoip: refresh the country database: %v", err)
	}
}
