package apps

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"

	"servika/internal/logx"
	"servika/internal/secret"
)

// envAAD binds a stored environment value to the application and the name it
// was written under, so a row moved to another application or renamed decrypts
// to nothing instead of silently becoming a different variable's value.
func envAAD(appID int64, name string) string {
	return "app:" + strconv.FormatInt(appID, 10) + ":" + name
}

const appColumns = `id, domain_id, COALESCE(subdomain_id,0), name, runtime,
	runtime_version, app_root, start_command, mount_path, port, enabled`

func scanApp(scan func(dest ...any) error) (App, error) {
	var app App
	var enabled int
	err := scan(&app.ID, &app.DomainID, &app.SubdomainID, &app.Name, &app.Runtime,
		&app.Version, &app.AppRoot, &app.Start, &app.Mount, &app.Port, &enabled)
	app.Enabled = enabled == 1
	return app, err
}

func collect(rows *sql.Rows) ([]App, error) {
	defer func() { _ = rows.Close() }()
	out := make([]App, 0, 4)
	for rows.Next() {
		app, err := scanApp(rows.Scan)
		if err != nil {
			// A row that cannot be read is reported rather than dropped
			// silently, because the caller would otherwise render a shorter
			// list and read it as "that application is gone".
			return nil, fmt.Errorf("read an application row: %w", err)
		}
		out = append(out, app)
	}
	return out, rows.Err()
}

// ListForDomain returns every application on a domain.
func ListForDomain(ctx context.Context, db *sql.DB, domainID int64) ([]App, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT `+appColumns+` FROM apps WHERE domain_id=? ORDER BY mount_path, id`, domainID)
	if err != nil {
		return nil, err
	}
	return collect(rows)
}

// Get returns one application, scoped to its domain.
//
// The domain is part of the WHERE clause rather than checked afterwards, so a
// customer who owns domain A cannot reach an application on domain B by naming
// its id: the query simply returns nothing.
func Get(ctx context.Context, db *sql.DB, domainID, appID int64) (App, error) {
	row := db.QueryRowContext(ctx,
		`SELECT `+appColumns+` FROM apps WHERE id=? AND domain_id=?`, appID, domainID)
	return scanApp(row.Scan)
}

// ListAll returns every application on the host, for startup healing.
func ListAll(ctx context.Context, db *sql.DB) ([]App, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+appColumns+` FROM apps ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return collect(rows)
}

// ListForSystemUser returns the applications belonging to one tenant login.
func ListForSystemUser(ctx context.Context, db *sql.DB, systemUser string) ([]App, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT `+appColumns+` FROM apps a
		 JOIN domains d ON d.id = a.domain_id
		 WHERE d.system_user=? ORDER BY a.id`, systemUser)
	if err != nil {
		return nil, err
	}
	return collect(rows)
}

// ReadEnv returns the decrypted environment for an application.
//
// A value that cannot be decrypted is reported as an error rather than passed
// through: the column holds ciphertext bound to an AAD, so echoing it would put
// a base64 blob where a password belongs and publish that ciphertext to
// everyone who can see the screen.
func ReadEnv(ctx context.Context, db *sql.DB, appID int64) (map[string]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT name, value FROM app_env WHERE app_id=? ORDER BY name`, appID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	values := map[string]string{}
	for rows.Next() {
		var name, stored string
		if err := rows.Scan(&name, &stored); err != nil {
			return nil, fmt.Errorf("read an environment row: %w", err)
		}
		plain, err := secret.DecryptWith(stored, envAAD(appID, name))
		if err != nil {
			logx.Errorf("apps: environment value %q of application %d cannot be decrypted: %v", name, appID, err)
			return nil, fmt.Errorf("environment value %q cannot be decrypted", name)
		}
		values[name] = plain
	}
	return values, rows.Err()
}

// ReplaceEnv writes the whole environment for an application in one transaction,
// so a half-applied edit cannot leave the unit with a mixture of old and new.
func ReplaceEnv(ctx context.Context, db *sql.DB, appID int64, values map[string]string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM app_env WHERE app_id=?`, appID); err != nil {
		return err
	}
	for name, value := range values {
		sealed, err := secret.EncryptWith(value, envAAD(appID, name))
		if err != nil {
			return fmt.Errorf("encrypt %q: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO app_env(app_id, name, value) VALUES(?,?,?)`, appID, name, sealed); err != nil {
			return err
		}
	}
	return tx.Commit()
}
