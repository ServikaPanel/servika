package laravel

import (
	"context"
	"database/sql"
	"fmt"
)

const workerColumns = `id, domain_id, name, connection, queues, processes, tries,
	timeout_sec, sleep_sec, max_jobs, memory_mb, enabled`

func scanWorker(scan func(dest ...any) error) (Worker, error) {
	var worker Worker
	var enabled int
	err := scan(&worker.ID, &worker.DomainID, &worker.Name, &worker.Connection, &worker.Queues,
		&worker.Processes, &worker.Tries, &worker.Timeout, &worker.Sleep, &worker.MaxJobs,
		&worker.MemoryMB, &enabled)
	worker.Enabled = enabled == 1
	return worker, err
}

func collectWorkers(rows *sql.Rows) ([]Worker, error) {
	defer func() { _ = rows.Close() }()
	out := make([]Worker, 0, 4)
	for rows.Next() {
		worker, err := scanWorker(rows.Scan)
		if err != nil {
			// A row that cannot be read is reported rather than dropped: the
			// caller would otherwise render a shorter list and read it as
			// "that worker is gone".
			return nil, fmt.Errorf("read a worker row: %w", err)
		}
		out = append(out, worker)
	}
	return out, rows.Err()
}

// WorkersForDomain returns every worker definition on a domain.
func WorkersForDomain(ctx context.Context, db *sql.DB, domainID int64) ([]Worker, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT `+workerColumns+` FROM cp_laravel_workers WHERE domain_id=? ORDER BY name, id`, domainID)
	if err != nil {
		return nil, err
	}
	return collectWorkers(rows)
}

// GetWorker returns one worker, scoped to its domain.
//
// The domain is part of the WHERE clause rather than checked afterwards, so a
// customer who owns domain A cannot reach a worker on domain B by naming its
// id: the query simply returns nothing.
func GetWorker(ctx context.Context, db *sql.DB, domainID, workerID int64) (Worker, error) {
	row := db.QueryRowContext(ctx,
		`SELECT `+workerColumns+` FROM cp_laravel_workers WHERE id=? AND domain_id=?`,
		workerID, domainID)
	return scanWorker(row.Scan)
}

// AllWorkers returns every worker on the host, for startup healing.
func AllWorkers(ctx context.Context, db *sql.DB) ([]Worker, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+workerColumns+` FROM cp_laravel_workers ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return collectWorkers(rows)
}

// InsertWorker stores a new definition and returns it with its id.
func InsertWorker(ctx context.Context, db *sql.DB, worker Worker) (Worker, error) {
	result, err := db.ExecContext(ctx,
		`INSERT INTO cp_laravel_workers
		   (domain_id, name, connection, queues, processes, tries, timeout_sec,
		    sleep_sec, max_jobs, memory_mb, enabled)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		worker.DomainID, worker.Name, worker.Connection, worker.Queues, worker.Processes,
		worker.Tries, worker.Timeout, worker.Sleep, worker.MaxJobs, worker.MemoryMB,
		boolToInt(worker.Enabled))
	if err != nil {
		return worker, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return worker, err
	}
	worker.ID = id
	return worker, nil
}

// UpdateWorker writes a definition back, scoped to its domain.
func UpdateWorker(ctx context.Context, db *sql.DB, worker Worker) error {
	_, err := db.ExecContext(ctx,
		`UPDATE cp_laravel_workers
		    SET name=?, connection=?, queues=?, processes=?, tries=?, timeout_sec=?,
		        sleep_sec=?, max_jobs=?, memory_mb=?, enabled=?
		  WHERE id=? AND domain_id=?`,
		worker.Name, worker.Connection, worker.Queues, worker.Processes, worker.Tries,
		worker.Timeout, worker.Sleep, worker.MaxJobs, worker.MemoryMB,
		boolToInt(worker.Enabled), worker.ID, worker.DomainID)
	return err
}

// DeleteWorker removes a definition, scoped to its domain.
func DeleteWorker(ctx context.Context, db *sql.DB, domainID, workerID int64) error {
	_, err := db.ExecContext(ctx,
		`DELETE FROM cp_laravel_workers WHERE id=? AND domain_id=?`, workerID, domainID)
	return err
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
