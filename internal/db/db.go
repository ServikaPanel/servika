package db

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"servika/internal/config"

	_ "github.com/go-sql-driver/mysql"
)

// Open creates and verifies a configured MariaDB connection pool.
func Open(dsn string) (*sql.DB, error) {
	d, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("sql.Open: %w", err)
	}
	maxOpen, override := config.DBMaxOpenConns()
	if override != "" {
		// Reported rather than obeyed, and reported rather than dropped: an
		// operator who set this deserves to know their value is not in effect.
		log.Printf("database pool: %s, using %d instead", override, maxOpen)
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
