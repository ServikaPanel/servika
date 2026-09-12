package credentials

import (
	"database/sql"
	"fmt"
	"regexp"
)

// mysqlRemoteHostPattern is the last gate before a value reaches the HOST
// component of a MariaDB account.
//
// The host component is a PATTERN: `%` matches any string and `_` any single
// character there, so a value carrying either would silently widen the grant to
// the whole internet on an account the panel still described as restricted.
// internal/dbremote produces these values by parsing an address and rendering it
// again, so nothing that fails this can normally arrive; the pattern is here
// because the statement is built by string interpolation and a boundary that
// depends on a caller having done the right thing is not a boundary.
//
// Only what an address or a base/netmask pair can spell: digits, dots, colons
// and one slash.
var mysqlRemoteHostPattern = regexp.MustCompile(`^[0-9a-fA-F.:]{1,45}(/[0-9.]{1,15})?$`)

// ValidRemoteHost reports whether a value may be used as the host component of a
// MariaDB account.
func ValidRemoteHost(host string) bool {
	return mysqlRemoteHostPattern.MatchString(host)
}

// MySQLGrantRemote creates or updates the account a remote client authenticates
// as, and grants it the databases the user already owns locally.
//
// A remote client does NOT use the 'user'@'localhost' account: MariaDB matches
// on the host component, so 'user'@'203.0.113.7' is a separate account with its
// own password and its own grants. Everything the local account can reach, this
// one must reach too, or the customer connects successfully and then sees an
// empty schema list.
func MySQLGrantRemote(dbUser, mysqlHost, dbPass string, dbNames []string) error {
	if !mysqlIdentifierPattern.MatchString(dbUser) {
		return fmt.Errorf("%w: database user", ErrInvalidMySQLCredentials)
	}
	if !ValidRemoteHost(mysqlHost) {
		return fmt.Errorf("%w: remote host", ErrInvalidMySQLCredentials)
	}
	if !mysqlPasswordPattern.MatchString(dbPass) {
		return fmt.Errorf("%w: database password", ErrInvalidMySQLCredentials)
	}
	// REQUIRE SSL is what stops the account speaking the plain MySQL protocol
	// across the public internet. Without it every query, every result set and
	// everything written through them crossed the network in the clear, with
	// nothing at the transport layer to detect a modification. internal/dbremote
	// refuses to open the port at all unless the server has a key pair, so an
	// account created here always has a link it can use.
	//
	// The clause rides on ALTER as well as CREATE. CREATE USER IF NOT EXISTS does
	// not touch an account that already exists, so removing a host and adding it
	// back is what converts an account made before this existed.
	statements := []string{
		fmt.Sprintf("CREATE USER IF NOT EXISTS '%s'@'%s' IDENTIFIED BY '%s' REQUIRE SSL;", dbUser, mysqlHost, escapeSQLString(dbPass)),
		// ALTER as well as CREATE, so re-adding a host the customer removed and
		// re-added does not leave the account on a password nobody has.
		fmt.Sprintf("ALTER USER '%s'@'%s' IDENTIFIED BY '%s' REQUIRE SSL;", dbUser, mysqlHost, escapeSQLString(dbPass)),
	}
	for _, dbName := range dbNames {
		if !mysqlIdentifierPattern.MatchString(dbName) {
			return fmt.Errorf("%w: database name", ErrInvalidMySQLCredentials)
		}
		statements = append(statements,
			fmt.Sprintf("GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'%s';", dbName, dbUser, mysqlHost))
	}
	statements = append(statements, "FLUSH PRIVILEGES;")
	return runRootSQL(statements...)
}

// MySQLRevokeRemote removes a remote account. It is idempotent so a caller can
// defer it without knowing whether creation got that far.
func MySQLRevokeRemote(dbUser, mysqlHost string) error {
	if !mysqlIdentifierPattern.MatchString(dbUser) {
		return fmt.Errorf("%w: database user", ErrInvalidMySQLCredentials)
	}
	if !ValidRemoteHost(mysqlHost) {
		return fmt.Errorf("%w: remote host", ErrInvalidMySQLCredentials)
	}
	return runRootSQL(
		fmt.Sprintf("DROP USER IF EXISTS '%s'@'%s';", dbUser, mysqlHost),
		"FLUSH PRIVILEGES;",
	)
}

// RemoteHostsFor lists the host components a database user currently answers on,
// besides localhost.
//
// Every path that touches a local account has to walk this list too: a password
// change, a newly attached database and a teardown all apply to one account each,
// and MariaDB has no notion that they belong together. A caller that forgets one
// leaves the remote client on the old password, without the new database, or
// alive after the domain is gone.
func RemoteHostsFor(db *sql.DB, dbUser string) ([]string, error) {
	if db == nil {
		return nil, nil
	}
	rows, err := db.Query(`SELECT mysql_host FROM db_remote_hosts WHERE db_user=?`, dbUser)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var hosts []string
	for rows.Next() {
		var host string
		if err := rows.Scan(&host); err != nil {
			return nil, err
		}
		hosts = append(hosts, host)
	}
	return hosts, rows.Err()
}

// remoteHostStatements applies a per-host statement builder to every remote host
// a user answers on.
//
// It returns an error rather than skipping on a read failure: a password change
// that silently missed the remote accounts leaves a working credential the
// customer believes they have rotated, which is worse than a failed change.
func remoteHostStatements(db *sql.DB, dbUser string, build func(host string) []string) ([]string, error) {
	hosts, err := RemoteHostsFor(db, dbUser)
	if err != nil {
		return nil, err
	}
	var statements []string
	for _, host := range hosts {
		if !ValidRemoteHost(host) {
			return nil, fmt.Errorf("%w: stored remote host %q", ErrInvalidMySQLCredentials, host)
		}
		statements = append(statements, build(host)...)
	}
	return statements, nil
}
