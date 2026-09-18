package credentials

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// The scoped account is what keeps an untrusted SQL dump inside one schema (see
// internal/sqlimport). A grant that widened to *.* would put the dump back on a
// full-privilege connection, which is the whole exposure.
func TestMySQLCreateScopedUserGrantsOneSchemaOnly(t *testing.T) {
	argvPath, stdinPath := stubRootSQL(t, 0)

	if err := MySQLCreateScopedUser("svk_imp_abc123", "SentryPassKey234", "c_example_main"); err != nil {
		t.Fatalf("MySQLCreateScopedUser() = %v, want nil", err)
	}

	statements := readStub(t, stdinPath)
	// The name is escaped, because MariaDB reads the schema position of a GRANT
	// as a pattern: an unescaped `_` would widen the account to every schema the
	// pattern matches, which is exactly what this account must not reach.
	if !strings.Contains(statements, "GRANT ALL PRIVILEGES ON `c\\_example\\_main`.* TO 'svk_imp_abc123'@'localhost';") {
		t.Errorf("the grant is not scoped to the target schema:\n%s", statements)
	}
	if strings.Contains(statements, "ON *.*") {
		t.Errorf("the grant reaches every schema:\n%s", statements)
	}
	if strings.Contains(statements, "WITH GRANT OPTION") {
		t.Errorf("the account can widen its own rights:\n%s", statements)
	}
	// Same rule as every other privileged statement: argv is world-readable
	// through /proc/<pid>/cmdline and a tenant reaches it with cron.
	if argv := readStub(t, argvPath); strings.Contains(argv, "SentryPassKey234") {
		t.Errorf("the account password reached argv: %q", argv)
	}
	if !strings.Contains(statements, "SentryPassKey234") {
		t.Error("the password never reached the client at all")
	}
}

// The account is created for one import and must not outlive it, so the drop
// has to succeed even when creation did not get that far.
func TestMySQLDropUserIsIdempotent(t *testing.T) {
	_, stdinPath := stubRootSQL(t, 0)

	if err := MySQLDropUser("svk_imp_abc123"); err != nil {
		t.Fatalf("MySQLDropUser() = %v, want nil", err)
	}
	if statements := readStub(t, stdinPath); !strings.Contains(statements, "DROP USER IF EXISTS 'svk_imp_abc123'@'localhost';") {
		t.Errorf("the drop is not idempotent:\n%s", statements)
	}
}

// An identifier that escapes its quoting would let a caller write the grant
// itself, so both functions must refuse before any statement is generated.
func TestScopedUserFunctionsRefuseUnsafeIdentifiers(t *testing.T) {
	cases := []struct {
		name           string
		user, pass, db string
	}{
		{"quoted user", "a'@'localhost'; GRANT ALL ON *.* TO 'x", "SentryPassKey234", "c_example_main"},
		{"backticked database", "svk_imp_abc123", "SentryPassKey234", "c_example_main`.* TO 'x'@'localhost'; -- "},
		{"password with a line break", "svk_imp_abc123", "pass\nFLUSH PRIVILEGES;", "c_example_main"},
		{"empty database", "svk_imp_abc123", "SentryPassKey234", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, stdinPath := stubRootSQL(t, 0)
			if err := MySQLCreateScopedUser(c.user, c.pass, c.db); !errors.Is(err, ErrInvalidMySQLCredentials) {
				t.Fatalf("MySQLCreateScopedUser() = %v, want ErrInvalidMySQLCredentials", err)
			}
			if _, err := readFileIfExists(stdinPath); err == nil {
				t.Error("the client ran before the identifiers were validated")
			}
		})
	}

	_, stdinPath := stubRootSQL(t, 0)
	if err := MySQLDropUser("a'@'localhost'; DROP USER 'root'@'localhost"); !errors.Is(err, ErrInvalidMySQLCredentials) {
		t.Fatalf("MySQLDropUser() = %v, want ErrInvalidMySQLCredentials", err)
	}
	if _, err := readFileIfExists(stdinPath); err == nil {
		t.Error("the client ran before the user name was validated")
	}
}

// readFileIfExists reports whether the stub client ran at all. A validation
// guard that fires only after exec is not a guard.
func readFileIfExists(path string) ([]byte, error) {
	return os.ReadFile(path) // #nosec G304 -- test-owned path under t.TempDir().
}
