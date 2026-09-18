//go:build windows

package platform

// Running the three database clients.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	// mssqlServer names the instance. SQL Express installs as SQLEXPRESS and
	// there is NO default instance, so the instance name is required. TCP
	// discovery needs the SQL Browser service, which the installer sets to
	// automatic and starts.
	mssqlServer = `localhost\SQLEXPRESS`

	// sqlcmdInstalled is where the installer puts go-sqlcmd. The SQL Server
	// engine does NOT ship sqlcmd, so the installer fetches the single-binary
	// ODBC-free build to this path. It is preferred over PATH, where an operator
	// may have put their own.
	sqlcmdInstalled = `C:\Program Files\Servika\sqlcmd.exe`

	// listTimeout and adminTimeout bound a read and a change.
	listTimeout  = 20
	adminTimeout = 60
)

// sqlcmd returns the client to use.
func sqlcmd() string {
	if _, err := os.Stat(sqlcmdInstalled); err == nil {
		return sqlcmdInstalled
	}
	return "sqlcmd"
}

// dbRun executes a database client with a timeout and returns its stdout.
//
// The callers also pass the client's own connection timeouts (-l,
// --connect-timeout, -w, PGCONNECT_TIMEOUT); this context is the last belt, for
// a client that hangs after connecting. Arguments go to exec.Command
// separately: nothing is joined into a shell string.
func dbRun(timeoutSec int, env []string, name string, arg ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, arg...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	if err == nil {
		return out.String(), nil
	}
	if ctx.Err() == context.DeadlineExceeded {
		return out.String(), fmt.Errorf("%s: timed out after %d seconds", name, timeoutSec)
	}
	detail := strings.TrimSpace(errOut.String())
	if detail == "" {
		detail = strings.TrimSpace(out.String())
	}
	return out.String(), fmt.Errorf("%s: %v - %s", name, err, detail)
}

// mssqlQuery runs one statement against the instance with Windows auth.
//
// -x disables sqlcmd variable substitution, -b makes a SQL error an exit code,
// and -l bounds the login wait.
func mssqlQuery(timeoutSec int, database, statement string, readArgs ...string) (string, error) {
	args := []string{"-S", mssqlServer, "-E", "-x", "-b", "-l", "5"}
	if database != "" {
		args = append(args, "-d", database)
	}
	args = append(args, readArgs...)
	args = append(args, "-Q", statement)
	return dbRun(timeoutSec, nil, sqlcmd(), args...)
}

// readArgs are the flags that make sqlcmd print parsable rows: no header, right
// trim, and a pipe separator that keeps a name with spaces whole.
var readArgs = []string{"-h-1", "-W", "-s|"}

// commandExists reports whether a client is on PATH.
func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// dirExists and fileExists report what is on disk at a known install location.
func dirExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

// DatabaseEngines reports which of the three engines is installed. An engine
// counts as installed when its client is on PATH or its known directory exists.
func DatabaseEngines() []EngineStatus {
	return []EngineStatus{
		{Kind: "mssql", Name: "Microsoft SQL Server",
			Installed: commandExists("sqlcmd") || dirExists(`C:\Program Files\Microsoft SQL Server`) || fileExists(sqlcmdInstalled)},
		{Kind: "mysql", Name: "MySQL",
			Installed: commandExists("mysql") || dirExists(`C:\Program Files\MySQL`)},
		{Kind: "pgsql", Name: "PostgreSQL",
			Installed: commandExists("psql") || dirExists(`C:\Program Files\PostgreSQL`)},
	}
}

// ListDatabases returns an engine's user databases with their sizes.
func ListDatabases(engine string) ([]DatabaseView, error) {
	switch engine {
	case "mssql":
		return listMSSQL()
	case "mysql":
		return listMySQL()
	case "pgsql":
		return listPostgres()
	}
	return nil, fmt.Errorf("unknown engine %q: %w", engine, ErrInvalidRequest)
}

// listMSSQL lists through Windows authentication, which needs no password.
func listMSSQL() ([]DatabaseView, error) {
	const query = "SET NOCOUNT ON; " +
		"SELECT DB_NAME(database_id), CAST(SUM(size)*8/1024 AS INT) " +
		"FROM sys.master_files " +
		"WHERE DB_NAME(database_id) NOT IN ('master','tempdb','model','msdb') " +
		"GROUP BY DB_NAME(database_id) ORDER BY DB_NAME(database_id)"
	out, err := mssqlQuery(listTimeout, "", query, readArgs...)
	if err != nil {
		return nil, fmt.Errorf("could not list the mssql databases: %w", err)
	}
	return parseRows(out, "|"), nil
}

// listMySQL tries a password-less root connection, which some installations
// allow locally, and reports plainly when it does not work. mysql without -p
// never PROMPTS, so this cannot hang on a password question.
func listMySQL() ([]DatabaseView, error) {
	const query = "SELECT s.schema_name, " +
		"IFNULL(CAST(SUM(t.data_length + t.index_length)/1024/1024 AS UNSIGNED), 0) " +
		"FROM information_schema.schemata s " +
		"LEFT JOIN information_schema.tables t ON t.table_schema = s.schema_name " +
		"WHERE s.schema_name NOT IN ('information_schema','mysql','performance_schema','sys') " +
		"GROUP BY s.schema_name ORDER BY s.schema_name"
	out, err := dbRun(listTimeout, nil, "mysql", "-u", "root", "-N", "-B", "--connect-timeout=5", "-e", query)
	if err != nil {
		return nil, fmt.Errorf("the agent does not hold the MySQL administrator password and a password-less connection also failed, so this engine needs manual configuration (%v): %w", err, ErrPasswordRequired)
	}
	return parseRows(out, "\t"), nil
}

// listPostgres does the same for PostgreSQL. -w makes psql fail instead of
// prompting for a password.
func listPostgres() ([]DatabaseView, error) {
	const query = "SELECT datname, pg_database_size(datname)/1024/1024 " +
		"FROM pg_database WHERE NOT datistemplate ORDER BY datname"
	out, err := dbRun(listTimeout, []string{"PGCONNECT_TIMEOUT=5"}, "psql", "-w", "-U", "postgres", "-tAc", query)
	if err != nil {
		return nil, fmt.Errorf("the agent does not hold the PostgreSQL password, so this engine cannot be managed yet (%v): %w", err, ErrPasswordRequired)
	}
	return parseRows(out, "|"), nil
}

// CreateDatabase creates a database with its own login and user.
//
// Only mssql is implemented; the other two need a password the agent does not
// keep, and they say so rather than reporting a success that did not happen.
func CreateDatabase(engine, name, user, password string) error {
	if !validEngine(engine) {
		return fmt.Errorf("unknown engine %q: %w", engine, ErrInvalidRequest)
	}
	if engine != "mssql" {
		return fmt.Errorf("creating a database on %s needs a password the agent does not hold: %w", engine, ErrPasswordRequired)
	}
	if err := validateDBName("database name", name); err != nil {
		return err
	}
	if err := validateDBName("user name", user); err != nil {
		return err
	}
	if err := validateDBPassword(password); err != nil {
		return err
	}
	first, second := createStatements(name, user, password)
	if _, err := mssqlQuery(adminTimeout, "", first); err != nil {
		return fmt.Errorf("could not create the mssql database or login: %w", err)
	}
	if _, err := mssqlQuery(adminTimeout, name, second); err != nil {
		return fmt.Errorf("could not create the mssql user or grant its role, though the database was created: %w", err)
	}
	return nil
}

// DropDatabase drops a database and cleans up the login it leaves behind.
func DropDatabase(engine, name string) error {
	if !validEngine(engine) {
		return fmt.Errorf("unknown engine %q: %w", engine, ErrInvalidRequest)
	}
	if err := validateDBName("database name", name); err != nil {
		return err
	}
	// The system-database guard comes FIRST, so a request for one is refused
	// with a clear answer even on an engine that could not act anyway.
	if isSystemDatabase(engine, name) {
		return fmt.Errorf("%q cannot be dropped: %w", name, ErrProtected)
	}
	if engine != "mssql" {
		return fmt.Errorf("dropping a database on %s needs a password the agent does not hold: %w", engine, ErrPasswordRequired)
	}
	candidates := mappedLogins(name)
	if _, err := mssqlQuery(adminTimeout, "", dropStatement(name)); err != nil {
		// The drop stopped part way, so the database may be stuck in
		// single-user mode and unreachable. Put it back; harmless if it is gone.
		_, _ = mssqlQuery(30, "", reopenStatement(name))
		return fmt.Errorf("could not drop the mssql database: %w", err)
	}
	for _, login := range candidates {
		// Best-effort: the database is already gone and the statement refuses to
		// drop a login another database still maps.
		_, _ = mssqlQuery(30, "", orphanLoginStatement(login))
	}
	return nil
}

// mappedLogins names the server logins a database's users map to, by SID.
//
// A failed query answers NO names, so the orphan cleanup is skipped rather than
// dropping the wrong login.
func mappedLogins(database string) []string {
	out, err := mssqlQuery(listTimeout, database,
		"SET NOCOUNT ON; SELECT sp.name FROM sys.database_principals dp "+
			"JOIN sys.server_principals sp ON sp.sid = dp.sid "+
			"WHERE sp.type IN ('S','U') AND sp.name NOT IN ('sa','dbo');", readArgs...)
	if err != nil {
		return nil
	}
	return loginNames(out)
}
