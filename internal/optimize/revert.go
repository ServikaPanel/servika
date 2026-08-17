package optimize

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Change is one row of what this screen has done to the server.
type Change struct {
	ID         int64  `json:"id"`
	Service    string `json:"service"`
	Param      string `json:"param"`
	TargetPath string `json:"target_path"`
	OldValue   string `json:"old_value"`
	NewValue   string `json:"new_value"`
	Reverted   bool   `json:"reverted"`
	RevertedAt string `json:"reverted_at,omitempty"`
	CreatedAt  string `json:"created_at"`
	// BackupPresent says whether the copy this row would restore is still on
	// disk. A row whose backup is gone cannot be reverted, and the screen has to
	// say so rather than offering a button that fails.
	BackupPresent bool `json:"backup_present"`
}

// History returns what this screen changed, newest first.
//
// A reverted row is kept rather than deleted, so an operator can see that a
// change was made and undone rather than never made at all. After an incident
// that distinction is the reason somebody opens this screen.
func History(ctx context.Context, db *sql.DB, limit int) ([]Change, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := db.QueryContext(ctx,
		`SELECT id, service, param, target_path, backup_path, old_value, new_value,
		        reverted, reverted_at, created_at
		   FROM optimize_backups
		  ORDER BY id DESC
		  LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	changes := []Change{}
	for rows.Next() {
		var change Change
		var backupPath string
		var revertedAt sql.NullTime
		var createdAt time.Time
		if err := rows.Scan(&change.ID, &change.Service, &change.Param,
			&change.TargetPath, &backupPath, &change.OldValue, &change.NewValue,
			&change.Reverted, &revertedAt, &createdAt); err != nil {
			return nil, err
		}
		change.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		if revertedAt.Valid {
			change.RevertedAt = revertedAt.Time.UTC().Format(time.RFC3339)
		}
		change.BackupPresent = backupExists(backupPath)
		changes = append(changes, change)
	}
	return changes, rows.Err()
}

// Revert puts one file back and makes the old values live again.
//
// The unit is the FILE, not the parameter, because that is what the backup is.
// Every row that shares this row's backup copy is marked reverted with it: they
// were written in one edit and the restore undoes all of them at once, so
// leaving the others marked as applied would tell the operator something that
// is no longer true.
func Revert(ctx context.Context, db *sql.DB, id int64) error {
	var service, param, targetPath, backupPath string
	var reverted bool
	err := db.QueryRowContext(ctx,
		`SELECT service, param, target_path, backup_path, reverted
		   FROM optimize_backups WHERE id=?`, id).
		Scan(&service, &param, &targetPath, &backupPath, &reverted)
	if errors.Is(err, sql.ErrNoRows) {
		return refuse(ReasonUnknownBackup, "no such change")
	}
	if err != nil {
		return err
	}
	if reverted {
		return refuse(ReasonAlreadyRevert, "this change was already put back")
	}
	if backupPath != "" && !backupExists(backupPath) {
		return refuse(ReasonUnknownBackup, "the copy this would restore is no longer on disk: %s", backupPath)
	}

	if err := restore(targetPath, backupPath); err != nil {
		return fmt.Errorf("restore %s: %w", targetPath, err)
	}
	if err := validate(ctx, service); err != nil {
		return fmt.Errorf("the restored file was refused, which means it was already edited outside the panel: %w", err)
	}
	if err := reactivate(ctx, db, service, targetPath); err != nil {
		return err
	}

	// Every row written from the same copy is undone by this one restore.
	if _, err := db.ExecContext(ctx,
		`UPDATE optimize_backups
		    SET reverted=1, reverted_at=NOW()
		  WHERE reverted=0 AND target_path=? AND backup_path=?`,
		targetPath, backupPath); err != nil {
		return err
	}
	return nil
}

// reactivate makes a restored file live again.
//
// For nginx and php-fpm that is the same reload or restart an apply does. For
// MariaDB and sysctl the file alone changes nothing that is already running, so
// the values are read back OUT of the restored file and set again; without that
// the file would say one thing and the running server another, which is the
// state this whole screen exists to make visible.
func reactivate(ctx context.Context, db *sql.DB, service, targetPath string) error {
	switch service {
	case ServiceNginx:
		if out, err := run(ctx, "systemctl", "reload", "nginx"); err != nil {
			return refuse(ReasonValidateFailed, "nginx would not reload: %s", tail(out))
		}
	case ServicePHPFPM:
		if out, err := run(ctx, "systemctl", "restart", "php-fpm"); err != nil {
			return refuse(ReasonValidateFailed, "php-fpm would not restart: %s", tail(out))
		}
	case ServiceMariaDB, ServiceSysctl:
		restored, err := restoredValues(service, targetPath)
		if err != nil {
			return err
		}
		if _, err := activate(ctx, db, restored); err != nil {
			return err
		}
	}
	return nil
}

// restoredValues reads a restored drop-in back into the proposal shape activate
// takes. A parameter this screen knows about that the restored file no longer
// carries is skipped: it was not set before the apply, and nothing here can put
// a value back that never existed. The screen reports the file as restored,
// which it is, and the running value stays until the next restart, which is
// what the drop-in's absence means.
func restoredValues(service, targetPath string) ([]Proposal, error) {
	text, err := readFileIfPresent(targetPath)
	if err != nil {
		return nil, err
	}
	stored := parseDropIn(text)
	var out []Proposal
	for _, item := range specs {
		if item.service != service {
			continue
		}
		value, present := stored[item.param]
		if !present {
			continue
		}
		out = append(out, Proposal{
			ID: item.service + ":" + item.param, Service: item.service,
			Param: item.param, Proposed: value, File: targetPath, Effect: item.effect,
		})
	}
	return out, nil
}
