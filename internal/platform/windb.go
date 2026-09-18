package platform

// Local database management for the Windows agent, across three engines.
//
// WHAT EACH ENGINE CAN ACTUALLY DO, stated plainly because the answer differs:
//
//	mssql  Works through Windows authentication (-E) with no password at all.
//	       Listing, creating and dropping are fully implemented.
//	mysql  The administrator password is generated at install time and is NOT
//	pgsql  kept by the agent. Management therefore cannot be performed; listing
//	       is ATTEMPTED without a password and reports a clear failure when that
//	       does not work. There is no pretend success here: telling an operator
//	       something was done when nothing was is worse than doing it wrong.
//
// THE SQL IS BUILT AS TEXT AND CANNOT BE PARAMETERISED. sqlcmd offers no
// parameter binding, and a database or login NAME cannot be a parameter in
// T-SQL in any case. The defense is therefore layered and every layer is here:
// a strict allowlist on every identifier, escaping for both the bracket and the
// literal form, and a character gate on the password for sqlcmd's own
// client-side parse. This file carries no build tag so all of it is measured on
// every build.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// dbNamePattern is the allowlist every database and login name must pass.
// Because the SQL is assembled by concatenation, this is the primary defense
// rather than a convenience.
var dbNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

// engines are the three this agent knows.
var engines = map[string]bool{"mssql": true, "mysql": true, "pgsql": true}

// systemDatabases are the databases that are never dropped, per engine.
var systemDatabases = map[string]map[string]bool{
	"mssql": {"master": true, "tempdb": true, "model": true, "msdb": true},
	"mysql": {"information_schema": true, "mysql": true, "performance_schema": true, "sys": true},
	"pgsql": {"postgres": true, "template0": true, "template1": true},
}

// ErrPasswordRequired means the engine needs an administrator password the
// agent does not keep, so the operation cannot be performed.
var ErrPasswordRequired = fmt.Errorf("this database engine needs a password the agent does not hold")

// ErrProtected means the target is a system database and is never touched.
var ErrProtected = fmt.Errorf("that is a system database")

// EngineStatus is one row of the engine listing.
type EngineStatus struct {
	Kind      string // mssql | mysql | pgsql
	Name      string
	Installed bool
}

// DatabaseView is one database with its size.
type DatabaseView struct {
	Name   string
	SizeMB int64
}

// escapeBrackets makes a name safe inside a T-SQL [bracketed] identifier.
func escapeBrackets(s string) string { return strings.ReplaceAll(s, "]", "]]") }

// escapeLiteral makes a value safe inside a T-SQL 'quoted' literal.
func escapeLiteral(s string) string { return strings.ReplaceAll(s, "'", "''") }

// validEngine reports whether the agent knows this engine.
func validEngine(engine string) bool { return engines[engine] }

// isSystemDatabase reports whether a name is one the engine owns.
func isSystemDatabase(engine, name string) bool {
	return systemDatabases[engine][strings.ToLower(name)]
}

// validateDBName refuses an identifier that will not go into SQL text safely.
func validateDBName(what, name string) error {
	if !dbNamePattern.MatchString(name) {
		return fmt.Errorf("invalid %s %q: it must start with a letter or underscore and hold 1 to 64 letters, digits or underscores: %w", what, name, ErrInvalidRequest)
	}
	return nil
}

// validatePassword refuses a password sqlcmd would not carry safely.
//
// The password ends up inside an N'...' literal, and doubling the quote only
// protects the SERVER's parse. sqlcmd processes the text of -Q LINE BY LINE
// FIRST: a line that is just "GO" is a batch separator, a line starting with
// ":" is a sqlcmd command, and "$(...)" is a variable substitution. sqlcmd does
// not know it is inside a string literal. So a newline is forbidden, because it
// opens the GO and ":" doors, and "$(" is forbidden outright. Every sqlcmd call
// also passes -x to disable substitution.
func validateDBPassword(password string) error {
	if password == "" {
		return fmt.Errorf("the password cannot be empty: %w", ErrInvalidRequest)
	}
	if strings.ContainsAny(password, "\r\n") || strings.Contains(password, "$(") {
		return fmt.Errorf("the password holds a character sqlcmd would read as a command (a newline or $( ): %w", ErrInvalidRequest)
	}
	return nil
}

// parseRows reads "name<separator>size" lines.
//
// The size is always a number and always LAST, so the line is split at the LAST
// separator. A name containing the separator therefore survives whole. A line
// whose tail is not a number is a warning or a banner and is skipped.
func parseRows(out, separator string) []DatabaseView {
	list := make([]DatabaseView, 0, 8)
	for line := range strings.SplitSeq(out, "\n") {
		if row, ok := parseRow(strings.TrimSpace(strings.TrimRight(line, "\r")), separator); ok {
			list = append(list, row)
		}
	}
	return list
}

// parseRow reads one "name<separator>size" line.
func parseRow(line, separator string) (DatabaseView, bool) {
	if line == "" {
		return DatabaseView{}, false
	}
	at := strings.LastIndex(line, separator)
	if at < 0 {
		return DatabaseView{}, false
	}
	name := strings.TrimSpace(line[:at])
	if name == "" {
		return DatabaseView{}, false
	}
	size, err := strconv.ParseInt(strings.TrimSpace(line[at+len(separator):]), 10, 64)
	if err != nil {
		return DatabaseView{}, false
	}
	return DatabaseView{Name: name, SizeMB: size}, true
}

// createStatements builds the two batches that create a database, its login and
// its user.
//
// THEY MUST BE TWO SEPARATE CALLS. CREATE DATABASE and USE cannot share a
// batch: SQL Server cannot connect to the new database until the creating batch
// closes, and answers "Msg 911: database does not exist". The first batch runs
// in master and makes the database and the login; the second runs with -d
// against the new database and adds the user and its role.
//
// EVERY STATEMENT IS IDEMPOTENT. If the agent dies between the two calls and
// the request is retried, the second attempt must not fail on CREATE DATABASE
// with "already exists": a half-built state has to be recoverable. An EXISTING
// login has its password RE-APPLIED rather than left alone, because leaving it
// would keep an old password while the panel shows a new one and the site could
// never connect.
func createStatements(name, user, password string) (first, second string) {
	dbBracket := escapeBrackets(name)
	userBracket := escapeBrackets(user)
	dbLiteral := escapeLiteral(name)
	userLiteral := escapeLiteral(user)
	passLiteral := escapeLiteral(password)

	first = fmt.Sprintf("SET NOCOUNT ON; "+
		"IF DB_ID(N'%s') IS NULL CREATE DATABASE [%s]; "+
		"IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'%s') "+
		"CREATE LOGIN [%s] WITH PASSWORD = N'%s'; "+
		"ELSE ALTER LOGIN [%s] WITH PASSWORD = N'%s';",
		dbLiteral, dbBracket, userLiteral, userBracket, passLiteral, userBracket, passLiteral)

	second = fmt.Sprintf("SET NOCOUNT ON; "+
		"IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'%s') "+
		"CREATE USER [%s] FOR LOGIN [%s]; "+
		"IF NOT EXISTS (SELECT 1 FROM sys.database_role_members drm "+
		"JOIN sys.database_principals r ON r.principal_id = drm.role_principal_id AND r.name = 'db_owner' "+
		"JOIN sys.database_principals m ON m.principal_id = drm.member_principal_id AND m.name = N'%s') "+
		"ALTER ROLE db_owner ADD MEMBER [%s];",
		userLiteral, userBracket, userBracket, userLiteral, userBracket)
	return first, second
}

// dropStatement builds the drop. SINGLE_USER WITH ROLLBACK IMMEDIATE is there
// so open connections cannot hold the drop off indefinitely.
func dropStatement(name string) string {
	b := escapeBrackets(name)
	return fmt.Sprintf("ALTER DATABASE [%s] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [%s];", b, b)
}

// reopenStatement puts a database back into multi-user mode.
//
// If the drop fails part way, because another connection took the single seat,
// the database is left HANGING in single-user mode and the customer cannot
// reach it at all. This undoes that.
func reopenStatement(name string) string {
	return fmt.Sprintf("IF DB_ID(N'%s') IS NOT NULL ALTER DATABASE [%s] SET MULTI_USER;",
		escapeLiteral(name), escapeBrackets(name))
}

// orphanLoginStatement drops a login ONLY when no user database maps to it any
// more.
//
// Creating a database makes a database, a server-level LOGIN and a
// database-level USER. Dropping the database takes the database and the user,
// and leaves the LOGIN on the server. Orphaned logins accumulate, and recreating
// the same username can pick one up with its old password.
//
// The cursor walks every online user database. If ANY of them still maps the
// login, or if the scan itself errors, the login is KEPT. Failing safe matters
// more than tidiness: another site may be using it.
func orphanLoginStatement(login string) string {
	literal := escapeLiteral(login)
	return fmt.Sprintf("SET NOCOUNT ON; "+
		"IF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'%s' AND type IN ('S','U')) "+
		"BEGIN "+
		"  DECLARE @sid VARBINARY(85) = (SELECT sid FROM sys.server_principals WHERE name = N'%s'); "+
		"  DECLARE @used INT = 0, @db SYSNAME, @sql NVARCHAR(MAX); "+
		"  DECLARE c CURSOR LOCAL FAST_FORWARD FOR SELECT name FROM sys.databases WHERE state = 0 AND database_id > 4; "+
		"  OPEN c; FETCH NEXT FROM c INTO @db; "+
		"  WHILE @@FETCH_STATUS = 0 AND @used = 0 "+
		"  BEGIN "+
		"    SET @sql = N'SELECT @c = COUNT(*) FROM ' + QUOTENAME(@db) + N'.sys.database_principals WHERE sid = @s'; "+
		"    BEGIN TRY EXEC sp_executesql @sql, N'@s VARBINARY(85), @c INT OUTPUT', @s = @sid, @c = @used OUTPUT; END TRY "+
		"    BEGIN CATCH SET @used = 1; END CATCH; "+
		"    FETCH NEXT FROM c INTO @db; "+
		"  END "+
		"  CLOSE c; DEALLOCATE c; "+
		"  IF @used = 0 DROP LOGIN [%s]; "+
		"END",
		literal, literal, escapeBrackets(login))
}

// loginNames reads the login names a listing produced, keeping only the ones
// shaped like names this agent creates.
func loginNames(out string) []string {
	var names []string
	for line := range strings.SplitSeq(out, "\n") {
		name := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if name != "" && dbNamePattern.MatchString(name) {
			names = append(names, name)
		}
	}
	return names
}
