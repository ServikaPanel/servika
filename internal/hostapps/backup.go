package hostapps

// On-demand backups of a server-level application.
//
// The removal path already archives the data directory on the way out. That
// archive only exists because a removal cannot be undone; it is not a backup an
// operator can take before an upgrade, and nothing ever read one back. This is
// the other half: an archive taken on request, verified by its digest, and put
// back over a broken install.
//
// The mechanics live in internal/appbackup, which both application kinds share.
// What stays here is the part that is specific to a server application: which
// paths belong to it, which unit controls it, and which table the rows go in.

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"time"

	"servika/internal/appbackup"
	"servika/internal/config"
)

// Backup is one archive of a server-level application.
type Backup struct {
	ID        int64     `json:"id"`
	AppID     int64     `json:"app_id"`
	Code      string    `json:"code"`
	Path      string    `json:"archive_path"`
	Size      int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256"`
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	// Restorable is false for a row written before this feature existed. Those
	// archives carry no digest, so a restore cannot prove the file is intact.
	Restorable bool `json:"restorable"`
}

// BackupDir is where one application's archives live. One directory per
// application, so a rotation cannot reach another application's files.
func BackupDir(code string) string {
	return filepath.Join(config.HostAppBackupDir(), code)
}

// backupTarget describes the application to internal/appbackup.
//
// The unit file and the EnvironmentFile travel WITH the tree. A restore that
// put back only /opt would leave the unit pointing at arguments the restored
// version does not take, and the env file carries the admin token the
// application was installed with.
func backupTarget(app App) appbackup.Target {
	return appbackup.Target{
		Dir:   BackupDir(app.Code),
		Root:  InstallDir(app.Code),
		Extra: []string{UnitPath(app.Code), EnvPath(app.Code)},
		Port:  app.Port,
		Stop:  func(context.Context) error { return Disable(app.Code) },
		Start: func(context.Context) error { return Enable(app.Code) },
	}
}

// CreateBackup archives the application and records the archive.
func CreateBackup(ctx context.Context, db *sql.DB, app App, note string, actor any) (Backup, error) {
	working.Lock()
	defer working.Unlock()

	archive, err := appbackup.Create(ctx, backupTarget(app))
	if err != nil {
		return Backup{}, err
	}
	result, err := db.ExecContext(ctx,
		`INSERT INTO host_app_backups (app_id, code, archive_path, size_bytes, sha256, note, created_by)
		 VALUES (?,?,?,?,?,?,?)`,
		app.ID, app.Code, archive.Path, archive.Size, archive.SHA256, note, actor)
	if err != nil {
		// The row is what names the file. Without it the archive is unreachable
		// and the rotation will never clear it, so it goes with the row.
		_ = appbackup.Remove(BackupDir(app.Code), archive.Path)
		return Backup{}, fmt.Errorf("record the backup: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return Backup{}, fmt.Errorf("record the backup: %w", err)
	}
	rotateBackups(ctx, db, app)
	return Backup{
		ID: id, AppID: app.ID, Code: app.Code, Path: archive.Path,
		Size: archive.Size, SHA256: archive.SHA256, Note: note,
		CreatedAt: time.Now().UTC(), Restorable: true,
	}, nil
}

// ListBackups answers one application's archives, newest first.
func ListBackups(ctx context.Context, db *sql.DB, appID int64) ([]Backup, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, COALESCE(app_id,0), code, archive_path, size_bytes, sha256, note, created_at
		   FROM host_app_backups WHERE app_id=? ORDER BY id DESC`, appID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []Backup{}
	for rows.Next() {
		var item Backup
		if err := rows.Scan(&item.ID, &item.AppID, &item.Code, &item.Path,
			&item.Size, &item.SHA256, &item.Note, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.Restorable = item.SHA256 != ""
		out = append(out, item)
	}
	return out, rows.Err()
}

// RestoreBackup puts one archive back.
func RestoreBackup(ctx context.Context, db *sql.DB, app App, backupID int64) error {
	working.Lock()
	defer working.Unlock()

	backup, err := backupByID(ctx, db, app.ID, backupID)
	if err != nil {
		return err
	}
	// A row written before this feature existed carries no digest, so there is
	// no way to prove the file is the one that was archived. Unpacking it over a
	// working tree on that basis is exactly the risk the digest exists to close.
	if backup.SHA256 == "" {
		return refuse(ReasonNotFound,
			"that archive predates verified backups and carries no digest, so it cannot be restored")
	}
	return appbackup.Restore(ctx, backupTarget(app), appbackup.Archive{
		Path: backup.Path, Size: backup.Size, SHA256: backup.SHA256,
	})
}

// DeleteBackup removes one archive and its row.
func DeleteBackup(ctx context.Context, db *sql.DB, app App, backupID int64) error {
	backup, err := backupByID(ctx, db, app.ID, backupID)
	if err != nil {
		return err
	}
	// The file goes first. A row with no file is a listing that offers a restore
	// which cannot run; a file with no row is invisible and never rotated.
	if err := appbackup.Remove(filepath.Dir(backup.Path), backup.Path); err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `DELETE FROM host_app_backups WHERE id=? AND app_id=?`,
		backupID, app.ID)
	return err
}

// rotateBackups drops everything past the newest KeepDefault archives.
//
// A failure is reported and the pass continues: the archive that was just taken
// is valid either way, and refusing the backup because an old file would not
// delete would be the wrong trade.
func rotateBackups(ctx context.Context, db *sql.DB, app App) {
	all, err := ListBackups(ctx, db, app.ID)
	if err != nil {
		complain("rotate the backups of %s: %v", app.Code, err)
		return
	}
	for _, old := range all[min(len(all), appbackup.KeepDefault):] {
		if err := DeleteBackup(ctx, db, app, old.ID); err != nil {
			complain("drop the old backup %d of %s: %v", old.ID, app.Code, err)
		}
	}
}

func backupByID(ctx context.Context, db *sql.DB, appID, backupID int64) (Backup, error) {
	var item Backup
	err := db.QueryRowContext(ctx,
		`SELECT id, COALESCE(app_id,0), code, archive_path, size_bytes, sha256, note, created_at
		   FROM host_app_backups WHERE id=? AND app_id=?`, backupID, appID).
		Scan(&item.ID, &item.AppID, &item.Code, &item.Path,
			&item.Size, &item.SHA256, &item.Note, &item.CreatedAt)
	if err != nil {
		return Backup{}, refuse(ReasonNotFound, "that backup does not belong to this application")
	}
	item.Restorable = item.SHA256 != ""
	return item, nil
}
