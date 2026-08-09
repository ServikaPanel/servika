package credentials

import (
	"database/sql"
	"fmt"
	"strings"
)

// MySQLChangePassword changes a MariaDB user's password and updates the account metadata.
func MySQLChangePassword(panelDB *sql.DB, dbUser, newPassword string) error {
	if !strings.HasPrefix(dbUser, "c_") {
		return fmt.Errorf("security: database user must have the c_ prefix")
	}
	if !mysqlIdentifierPattern.MatchString(dbUser) {
		return fmt.Errorf("%w: database user", ErrInvalidMySQLCredentials)
	}
	if !ValidPassword(newPassword) {
		return fmt.Errorf("%w: database password", ErrInvalidMySQLCredentials)
	}
	if !mysqlPasswordPattern.MatchString(newPassword) {
		return fmt.Errorf("%w: database password", ErrInvalidMySQLCredentials)
	}
	// Every host the user answers on, not only localhost. MariaDB keeps one
	// account per host component with its own password, so changing localhost
	// alone leaves each remote client working on the credential the customer
	// just believed they rotated.
	statements := []string{
		fmt.Sprintf("ALTER USER '%s'@'localhost' IDENTIFIED BY '%s';", dbUser, escapeSQLString(newPassword)),
	}
	remote, err := remoteHostStatements(panelDB, dbUser, func(host string) []string {
		return []string{fmt.Sprintf("ALTER USER '%s'@'%s' IDENTIFIED BY '%s';", dbUser, host, escapeSQLString(newPassword))}
	})
	if err != nil {
		return fmt.Errorf("remote hosts: %w", err)
	}
	statements = append(statements, remote...)
	statements = append(statements, "FLUSH PRIVILEGES;")
	if err := runRootSQL(statements...); err != nil {
		return fmt.Errorf("alter user: %w", err)
	}
	// Store the new password encrypted at rest (bound to the database user).
	encPass, err := encryptDBPass(dbUser, newPassword)
	if err != nil {
		return fmt.Errorf("encrypt db password: %w", err)
	}
	if _, err := panelDB.Exec(
		`UPDATE db_accounts SET db_pass_plain=? WHERE db_user=?`,
		encPass, dbUser); err != nil {
		return fmt.Errorf("metadata: %w", err)
	}
	return nil
}
