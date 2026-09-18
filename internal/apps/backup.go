package apps

// On-demand backups of a tenant's own application.
//
// The domain backup schedule already archives the home directory, but it runs
// on its own clock and restores the whole home. What a tenant needs before
// deploying a new version is a copy of THIS application, taken now, and a way
// to put it back without touching the rest of the account.
//
// The mechanics live in internal/appbackup. What stays here is the part that is
// specific to a tenant application: the tree is inside a home the tenant owns
// and can rewrite at any moment, so the path is resolved through SafeAppDir on
// every call rather than being carried in the row.

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"servika/internal/appbackup"
	"servika/internal/config"
	"servika/internal/logx"
)

// Backup is one archive of a tenant application.
type Backup struct {
	ID        int64     `json:"id"`
	AppID     int64     `json:"app_id"`
	DomainID  int64     `json:"domain_id"`
	Path      string    `json:"archive_path"`
	Size      int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256"`
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// BackupDir is where one application's archives live.
//
// Outside every tenant home on purpose: the tree being archived is writable by
// the account that owns it, and an archive kept inside it could be deleted or
// replaced by the very account it protects.
func BackupDir(appID int64) string {
	return filepath.Join(config.AppBackupDir(), strconv.FormatInt(appID, 10))
}

// backupTarget describes the application to internal/appbackup.
//
// The application root is resolved through SafeAppDir rather than read from the
// row: the field is home-relative, the home belongs to the tenant, and a
// symlink planted there between two calls is the case that check exists for. A
// tree that no longer resolves is refused instead of archived.
//
// tar runs WITHOUT -P, so every member is stored with its leading slash
// stripped and a member naming `..` is refused by tar itself. That is what
// keeps an archive of a tenant tree from writing outside it on the way back.
func backupTarget(app App, systemUser string) (appbackup.Target, error) {
	appDir, err := SafeAppDir(systemUser, app.AppRoot)
	if err != nil {
		return appbackup.Target{}, err
	}
	return appbackup.Target{
		Dir:   BackupDir(app.ID),
		Root:  appDir,
		Extra: []string{UnitPath(app.ID), EnvPath(app.ID)},
		Port:  app.Port,
		Stop:  func(context.Context) error { return Disable(app.ID) },
		Start: func(context.Context) error { return Enable(app.ID) },
	}, nil
}

// CreateBackup archives the application and records the archive.
func CreateBackup(ctx context.Context, db *sql.DB, app App, systemUser, note string, actor any) (Backup, error) {
	target, err := backupTarget(app, systemUser)
	if err != nil {
		return Backup{}, err
	}
	archive, err := appbackup.Create(ctx, target)
	if err != nil {
		return Backup{}, err
	}
	result, err := db.ExecContext(ctx,
		`INSERT INTO app_backups (app_id, domain_id, archive_path, size_bytes, sha256, note, created_by)
		 VALUES (?,?,?,?,?,?,?)`,
		app.ID, app.DomainID, archive.Path, archive.Size, archive.SHA256, note, actor)
	if err != nil {
		// The row is what names the file. Without it the archive is unreachable
		// and the rotation will never clear it, so it goes with the row.
		_ = appbackup.Remove(target.Dir, archive.Path)
		return Backup{}, fmt.Errorf("record the backup: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return Backup{}, fmt.Errorf("record the backup: %w", err)
	}
	rotateBackups(ctx, db, app)
	return Backup{
		ID: id, AppID: app.ID, DomainID: app.DomainID, Path: archive.Path,
		Size: archive.Size, SHA256: archive.SHA256, Note: note, CreatedAt: time.Now().UTC(),
	}, nil
}

// ListBackups answers one application's archives, newest first.
//
// The query narrows on the domain as well as the application, because the
// ownership chain the route checked is the domain's: an application id on its
// own would answer for another customer's row.
func ListBackups(ctx context.Context, db *sql.DB, domainID, appID int64) ([]Backup, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, app_id, domain_id, archive_path, size_bytes, sha256, note, created_at
		   FROM app_backups WHERE app_id=? AND domain_id=? ORDER BY id DESC`, appID, domainID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []Backup{}
	for rows.Next() {
		var item Backup
		if err := rows.Scan(&item.ID, &item.AppID, &item.DomainID, &item.Path,
			&item.Size, &item.SHA256, &item.Note, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// RestoreBackup puts one archive back over the application's tree.
func RestoreBackup(ctx context.Context, db *sql.DB, app App, systemUser string, backupID int64) error {
	backup, err := backupByID(ctx, db, app, backupID)
	if err != nil {
		return err
	}
	target, err := backupTarget(app, systemUser)
	if err != nil {
		return err
	}
	return appbackup.Restore(ctx, target, appbackup.Archive{
		Path: backup.Path, Size: backup.Size, SHA256: backup.SHA256,
	})
}

// DeleteBackup removes one archive and its row.
func DeleteBackup(ctx context.Context, db *sql.DB, app App, backupID int64) error {
	backup, err := backupByID(ctx, db, app, backupID)
	if err != nil {
		return err
	}
	// The file goes first. A row with no file is a listing that offers a restore
	// which cannot run; a file with no row is invisible and never rotated.
	if err := appbackup.Remove(BackupDir(app.ID), backup.Path); err != nil {
		return err
	}
	_, err = db.ExecContext(ctx,
		`DELETE FROM app_backups WHERE id=? AND app_id=? AND domain_id=?`,
		backupID, app.ID, app.DomainID)
	return err
}

// rotateBackups drops everything past the newest KeepDefault archives.
//
// A failure is reported and the pass continues: the archive that was just taken
// is valid either way, and refusing a backup because an old file would not
// delete would be the wrong trade.
func rotateBackups(ctx context.Context, db *sql.DB, app App) {
	all, err := ListBackups(ctx, db, app.DomainID, app.ID)
	if err != nil {
		logx.Errorf("apps: rotate the backups of application %d: %v", app.ID, err)
		return
	}
	for _, old := range all[min(len(all), appbackup.KeepDefault):] {
		if err := DeleteBackup(ctx, db, app, old.ID); err != nil {
			logx.Errorf("apps: drop the old backup %d of application %d: %v", old.ID, app.ID, err)
		}
	}
}

func backupByID(ctx context.Context, db *sql.DB, app App, backupID int64) (Backup, error) {
	var item Backup
	err := db.QueryRowContext(ctx,
		`SELECT id, app_id, domain_id, archive_path, size_bytes, sha256, note, created_at
		   FROM app_backups WHERE id=? AND app_id=? AND domain_id=?`,
		backupID, app.ID, app.DomainID).
		Scan(&item.ID, &item.AppID, &item.DomainID, &item.Path,
			&item.Size, &item.SHA256, &item.Note, &item.CreatedAt)
	if err != nil {
		return Backup{}, fmt.Errorf("that backup does not belong to this application")
	}
	return item, nil
}
