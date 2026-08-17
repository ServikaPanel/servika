package hostapps

import (
	"context"
	"database/sql"
	"errors"
	"log"
)

func complain(format string, args ...any) {
	log.Printf("hostapps: "+format, args...)
}

// App is one installed application.
type App struct {
	ID         int64  `json:"id"`
	Code       string `json:"code"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	SystemUser string `json:"system_user"`
	InstallDir string `json:"install_dir"`
	DataDir    string `json:"data_dir"`
	State      string `json:"state"`
	LastError  string `json:"last_error,omitempty"`
	Port       int    `json:"port"`
	Open       bool   `json:"firewall_open"`
	Status     Status `json:"status"`
}

const catalogColumns = `code, name, version, url_amd64, sha256_amd64, url_arm64, sha256_arm64,
	 archive_kind, strip_components, binary_path, start_args, port_env_name,
	 takes_port, default_port, needs_data_dir, enabled`

func scanEntry(row interface{ Scan(...any) error }) (Entry, error) {
	var entry Entry
	err := row.Scan(&entry.Code, &entry.Name, &entry.Version,
		&entry.URLAMD64, &entry.SHA256AMD64, &entry.URLARM64, &entry.SHA256ARM64,
		&entry.ArchiveKind, &entry.StripComponents, &entry.BinaryPath, &entry.StartArgs,
		&entry.PortEnvName, &entry.TakesPort, &entry.DefaultPort,
		&entry.NeedsDataDir, &entry.Enabled)
	return entry, err
}

// CatalogEntry reads one catalog row.
func CatalogEntry(ctx context.Context, db *sql.DB, code string) (Entry, error) {
	if !codePattern.MatchString(code) {
		return Entry{}, refuse(ReasonUnknownApp, "%q is not an application this offers", code)
	}
	entry, err := scanEntry(db.QueryRowContext(ctx,
		`SELECT `+catalogColumns+` FROM host_app_catalog WHERE code=?`, code))
	if errors.Is(err, sql.ErrNoRows) {
		return Entry{}, refuse(ReasonUnknownApp, "%q is not an application this offers", code)
	}
	if err != nil {
		return Entry{}, err
	}
	return entry, nil
}

// Catalog reads every enabled row.
func Catalog(ctx context.Context, db *sql.DB) ([]Entry, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT `+catalogColumns+` FROM host_app_catalog WHERE enabled=1 ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []Entry{}
	for rows.Next() {
		entry, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, rows.Err()
}

// Installed reads every installed application with its port.
//
// The port comes from a LEFT JOIN rather than a second query, so an application
// whose port row is missing still appears. A row in that state is exactly the
// one an operator needs to see: a half-finished install is what left it there.
func Installed(ctx context.Context, db *sql.DB) ([]App, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT a.id, a.code, a.name, a.version, a.system_user, a.install_dir, a.data_dir,
		        a.state, a.last_error, COALESCE(p.port,0), COALESCE(p.firewall_open,0)
		   FROM host_apps a
		   LEFT JOIN host_app_ports p ON p.app_id = a.id
		  ORDER BY a.name`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []App{}
	for rows.Next() {
		var app App
		if err := rows.Scan(&app.ID, &app.Code, &app.Name, &app.Version, &app.SystemUser,
			&app.InstallDir, &app.DataDir, &app.State, &app.LastError,
			&app.Port, &app.Open); err != nil {
			return nil, err
		}
		out = append(out, app)
	}
	return out, rows.Err()
}

// AppByID reads one installed application.
func AppByID(ctx context.Context, db *sql.DB, id int64) (App, error) {
	var app App
	err := db.QueryRowContext(ctx,
		`SELECT a.id, a.code, a.name, a.version, a.system_user, a.install_dir, a.data_dir,
		        a.state, a.last_error, COALESCE(p.port,0), COALESCE(p.firewall_open,0)
		   FROM host_apps a
		   LEFT JOIN host_app_ports p ON p.app_id = a.id
		  WHERE a.id=?`, id).
		Scan(&app.ID, &app.Code, &app.Name, &app.Version, &app.SystemUser,
			&app.InstallDir, &app.DataDir, &app.State, &app.LastError,
			&app.Port, &app.Open)
	if errors.Is(err, sql.ErrNoRows) {
		return App{}, refuse(ReasonNotFound, "that application is not installed")
	}
	return app, err
}

// OpenPorts reads the ports the firewall must accept.
//
// It returns an ERROR rather than an empty list on a read failure. An empty list
// means "open nothing", which for a firewall renderer is a valid answer, so a
// database that could not be read would silently close every application's port
// on the next reapply.
func OpenPorts(ctx context.Context, db *sql.DB) ([]int, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT port FROM host_app_ports WHERE firewall_open=1 ORDER BY port`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []int{}
	for rows.Next() {
		var port int
		if err := rows.Scan(&port); err != nil {
			return nil, err
		}
		if InRange(port) {
			out = append(out, port)
		}
	}
	return out, rows.Err()
}

// AnyInstalled reports whether the range drop needs writing at all.
//
// The drop is emitted only while at least one application exists, so an operator
// running their own service on a port in this range is not silently cut off by a
// panel update. That mirrors the rule internal/dbremote follows for 3306.
func AnyInstalled(ctx context.Context, db *sql.DB) (bool, error) {
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM host_apps`).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

// takenPorts reads every port already assigned, plus the highest of them.
func takenPorts(ctx context.Context, tx *sql.Tx) (map[int]bool, int, error) {
	rows, err := tx.QueryContext(ctx, `SELECT port FROM host_app_ports`)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()

	taken := map[int]bool{}
	highest := 0
	for rows.Next() {
		var port int
		if err := rows.Scan(&port); err != nil {
			return nil, 0, err
		}
		taken[port] = true
		if port > highest {
			highest = port
		}
	}
	return taken, highest, rows.Err()
}

// startJob opens a job row so a long operation can be reported while it runs.
func startJob(ctx context.Context, db *sql.DB, appID *int64, code, action string, actor any) (int64, error) {
	result, err := db.ExecContext(ctx,
		`INSERT INTO host_app_jobs (app_id, code, action, actor_uid) VALUES (?,?,?,?)`,
		appID, code, action, actor)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// finishJob closes a job row with its verdict.
func finishJob(ctx context.Context, db *sql.DB, id int64, err error) {
	state, message := "finished", ""
	if err != nil {
		state, message = "failed", err.Error()
	}
	if len(message) > 512 {
		message = message[:512]
	}
	if _, execErr := db.ExecContext(ctx,
		`UPDATE host_app_jobs SET state=?, last_error=?, finished_at=NOW() WHERE id=?`,
		state, message, id); execErr != nil {
		complain("close job %d: %v", id, execErr)
	}
}

// HealRunningJobs closes at startup every job left running.
//
// The install runs in this process, so a job still marked running after a
// restart is one whose process is gone. Leaving it would show the operator an
// install that never finishes and refuse a second attempt for good.
func HealRunningJobs(db *sql.DB) {
	if _, err := db.Exec(
		`UPDATE host_app_jobs
		    SET state='failed', last_error='the panel restarted before this finished',
		        finished_at=NOW()
		  WHERE state='running'`); err != nil {
		complain("heal running jobs: %v", err)
		return
	}
	if _, err := db.Exec(
		`UPDATE host_apps
		    SET state='failed', last_error='the panel restarted before this finished',
		        finished_at=NOW()
		  WHERE state IN ('installing','removing')`); err != nil {
		complain("heal unfinished applications: %v", err)
	}
}
