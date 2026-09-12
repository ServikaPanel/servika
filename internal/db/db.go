package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"servika/internal/config"
	"servika/internal/logx"

	"github.com/go-sql-driver/mysql"
)

// pinTimeContract forces the two DSN parameters this panel's code assumes, and
// reports an operator value it overrode.
//
// parseTime: several scan sites read a TIMESTAMP straight into time.Time or
// sql.NullTime, which the driver produces ONLY with parseTime=true. Without it
// internal/chains logs "skipping an unreadable event" for every row and writes
// no attack chain at all, and the optimize history endpoint fails outright.
// The installer writes the parameter, so a stock server is fine; a DSN edited
// by hand in /etc/servika/env, or the shorter one in the README, is not.
//
// loc: a bound time.Time is stored as a wall clock IN THIS LOCATION, and
// internal/slowquery compares its buckets against UTC_TIMESTAMP() precisely
// because the driver's default is UTC. An operator who set loc=Local would
// shift every stored bucket off the clock those queries compare it to.
//
// A DSN the driver cannot parse is returned unchanged rather than refused:
// sql.Open makes the same judgement two lines later and its error names the
// real problem.
func pinTimeContract(dsn string) string {
	parsed, err := mysql.ParseDSN(dsn)
	if err != nil {
		return dsn
	}
	if !parsed.ParseTime {
		parsed.ParseTime = true
	}
	// Reported rather than obeyed, and reported rather than dropped, the same
	// judgement the pool size below makes: an operator who set this deserves to
	// know their value is not in effect.
	if parsed.Loc != nil && parsed.Loc != time.UTC {
		logx.Warnf("database: the DSN asks for loc=%s, using UTC instead, which is what the stored timestamps are compared against", parsed.Loc)
	}
	parsed.Loc = time.UTC
	return parsed.FormatDSN()
}

// Open creates and verifies a configured MariaDB connection pool.
func Open(dsn string) (*sql.DB, error) {
	d, err := sql.Open("mysql", pinTimeContract(dsn))
	if err != nil {
		return nil, fmt.Errorf("sql.Open: %w", err)
	}
	maxOpen, override := config.DBMaxOpenConns()
	if override != "" {
		// Reported rather than obeyed, and reported rather than dropped: an
		// operator who set this deserves to know their value is not in effect.
		logx.Warnf("database pool: %s, using %d instead", override, maxOpen)
	}
	d.SetMaxOpenConns(maxOpen)
	d.SetMaxIdleConns(maxOpen / 2)
	d.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping: %w", err)
	}
	return d, nil
}
