package hostapps

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// working serialises the operations that change what is on the host.
//
// Two installs at once would race for the same free port between the read and
// the insert, and an install racing a removal would rebuild directories the
// removal is deleting. The port table's UNIQUE key catches the first case, but
// only after a download has already run.
var working sync.Mutex

// installTimeout bounds one install. The download alone can take minutes on a
// slow link, and the operation outlives the request that started it.
const installTimeout = 45 * time.Minute

// Reserve records an application and takes its port, in one transaction.
//
// The port is allocated INSIDE the transaction against the port table's UNIQUE
// key, because a check followed by an insert is not atomic. The system_user
// UNIQUE key is what refuses a second install of the same application: a check
// on the code alone would let two concurrent requests both read it as free, and
// the two would then share one directory, one unit and one account.
func Reserve(ctx context.Context, db *sql.DB, entry Entry, actor any) (App, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return App{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var state string
	err = tx.QueryRowContext(ctx, `SELECT state FROM host_apps WHERE code=?`, entry.Code).Scan(&state)
	switch {
	case err == nil:
		return App{}, refuse(ReasonAlready,
			"%s is already recorded on this server (%s); remove it before installing again",
			entry.Name, state)
	case !errors.Is(err, sql.ErrNoRows):
		return App{}, err
	}

	taken, highest, err := takenPorts(ctx, tx)
	if err != nil {
		return App{}, err
	}
	port, err := NextPort(taken, highest)
	if err != nil {
		return App{}, err
	}

	app := App{
		Code:       entry.Code,
		Name:       entry.Name,
		Version:    entry.Version,
		SystemUser: SystemUser(entry.Code),
		InstallDir: InstallDir(entry.Code),
		DataDir:    DataDir(entry.Code),
		State:      "installing",
		Port:       port,
	}
	result, err := tx.ExecContext(ctx,
		`INSERT INTO host_apps (code, name, version, system_user, install_dir, data_dir, created_by)
		 VALUES (?,?,?,?,?,?,?)`,
		app.Code, app.Name, app.Version, app.SystemUser, app.InstallDir, app.DataDir, actor)
	if err != nil {
		return App{}, err
	}
	app.ID, err = result.LastInsertId()
	if err != nil {
		return App{}, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO host_app_ports (app_id, port) VALUES (?,?)`, app.ID, port); err != nil {
		return App{}, err
	}
	return app, tx.Commit()
}

// Install lays the application down on the host.
//
// It runs on its OWN context rather than the request's: the request that started
// it is answered as soon as the row exists, and a browser tab closed mid-download
// must not cancel a half-written installation.
func Install(db *sql.DB, entry Entry, app App, jobID int64) {
	working.Lock()
	defer working.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), installTimeout)
	defer cancel()

	err := install(ctx, entry, app)
	finishJob(ctx, db, jobID, err)
	if err != nil {
		complain("install %s: %v", entry.Code, err)
		message := err.Error()
		if len(message) > 512 {
			message = message[:512]
		}
		if _, execErr := db.ExecContext(ctx,
			`UPDATE host_apps SET state='failed', last_error=?, finished_at=NOW() WHERE id=?`,
			message, app.ID); execErr != nil {
			complain("record the failure: %v", execErr)
		}
		return
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE host_apps SET state='installed', last_error='', finished_at=NOW() WHERE id=?`,
		app.ID); err != nil {
		complain("record the install: %v", err)
	}
	reapplyFirewall()
}

func install(ctx context.Context, entry Entry, app App) error {
	url, digest, err := Download(entry)
	if err != nil {
		return err
	}
	systemUser, err := EnsureUser(entry.Code)
	if err != nil {
		return err
	}
	if err := PrepareDirectories(entry.Code, systemUser); err != nil {
		return err
	}

	// The download lands under TMPDIR, which cmd/server pins to persistent disk
	// so a large archive is not written into the RAM-backed /tmp AlmaLinux 10
	// ships.
	staging, err := os.MkdirTemp("", "servika-hostapp-")
	if err != nil {
		return fmt.Errorf("create the download directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(staging) }()

	archive := filepath.Join(staging, "download")
	if err := Fetch(ctx, url, digest, archive); err != nil {
		return err
	}
	if err := Unpack(ctx, entry, archive, app.InstallDir); err != nil {
		return err
	}
	binary, err := VerifyBinary(entry.Code, entry.BinaryPath)
	if err != nil {
		return err
	}
	// Ownership is set again AFTER the unpack: the files that just landed are
	// root's, and the service account cannot read its own program otherwise.
	if err := PrepareDirectories(entry.Code, systemUser); err != nil {
		return err
	}

	arguments, err := BuildArgv(entry, app.DataDir, app.Port)
	if err != nil {
		return err
	}
	if err := WriteEnvFile(entry, app.Port, nil); err != nil {
		return err
	}
	if err := EnsureLogFile(entry.Code); err != nil {
		return err
	}
	body := RenderUnit(entry, systemUser, append([]string{binary}, arguments...))
	if err := InstallUnit(entry.Code, body); err != nil {
		return err
	}
	return Enable(entry.Code)
}

// Remove takes the application off the host.
//
// The data directory is archived FIRST. Removal is the one operation here that
// cannot be undone and the contents are the operator's, not the panel's: a Gitea
// removal takes every repository with it. A failed archive stops the removal
// rather than proceeding without a copy.
func Remove(db *sql.DB, app App, jobID int64) {
	working.Lock()
	defer working.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), installTimeout)
	defer cancel()

	err := remove(ctx, db, app)
	finishJob(ctx, db, jobID, err)
	if err != nil {
		complain("remove %s: %v", app.Code, err)
		message := err.Error()
		if len(message) > 512 {
			message = message[:512]
		}
		if _, execErr := db.ExecContext(ctx,
			`UPDATE host_apps SET state='failed', last_error=?, finished_at=NOW() WHERE id=?`,
			message, app.ID); execErr != nil {
			complain("record the failure: %v", execErr)
		}
		return
	}
	reapplyFirewall()
}

func remove(ctx context.Context, db *sql.DB, app App) error {
	archive, size, err := BackupData(ctx, app.Code)
	if err != nil {
		return err
	}
	if archive != "" {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO host_app_backups (app_id, code, archive_path, size_bytes)
			 VALUES (?,?,?,?)`, app.ID, app.Code, archive, size); err != nil {
			// The archive is on disk; losing the row that names it is worth
			// reporting but not worth abandoning the removal for.
			complain("record the backup of %s: %v", app.Code, err)
		}
	}

	TeardownFiles(app.Code)
	if err := RemoveUser(app.SystemUser); err != nil {
		return err
	}
	// The port row goes with the application through ON DELETE CASCADE, so the
	// port returns to the pool with the row and the two cannot disagree.
	if _, err := db.ExecContext(ctx, `DELETE FROM host_apps WHERE id=?`, app.ID); err != nil {
		return err
	}
	return nil
}

// SetFirewall opens or closes an application's port.
func SetFirewall(ctx context.Context, db *sql.DB, appID int64, open bool) error {
	result, err := db.ExecContext(ctx,
		`UPDATE host_app_ports SET firewall_open=? WHERE app_id=?`, open, appID)
	if err != nil {
		return err
	}
	if affected, err := result.RowsAffected(); err == nil && affected == 0 {
		return refuse(ReasonNotFound, "that application has no port to open")
	}
	reapplyFirewall()
	return nil
}

// reapply is how this package asks the firewall to re-render. It is a hook
// rather than a direct call because internal/firewall reads this package's port
// table through its own hook, and calling in both directions would close an
// import cycle.
var reapply func()

// SetReapply wires the firewall reapply. cmd/server calls it once at startup.
func SetReapply(fn func()) { reapply = fn }

func reapplyFirewall() {
	if reapply != nil {
		reapply()
	}
}
