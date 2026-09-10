package credentials

import (
	"os"
	"strings"
	"testing"
)

// statementsFrom splits what the privileged client received on stdin back into
// statements. runRootSQL keeps them out of argv, so stdin is where they are.
func statementsFrom(script string) []string {
	var out []string
	for line := range strings.SplitSeq(script, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// findStatement returns the first recorded statement starting with the prefix.
func findStatement(statements []string, prefix string) (string, bool) {
	for _, statement := range statements {
		if strings.HasPrefix(statement, prefix) {
			return statement, true
		}
	}
	return "", false
}

// Turning remote access on rebinds MariaDB to every interface, and the account
// created for each allowed address spoke the plain MySQL protocol: every query,
// every result set and everything written through them crossed the public
// internet in the clear, with nothing at the transport layer to detect a
// modification.
func TestARemoteAccountIsCreatedRequiringTLS(t *testing.T) {
	_, stdinPath := stubRootSQL(t, 0)

	if err := MySQLGrantRemote("c_t_db", "203.0.113.7", "pw23456789", []string{"c_t_shop"}); err != nil {
		t.Fatalf("MySQLGrantRemote: %v", err)
	}
	recorded := statementsFrom(readStub(t, stdinPath))

	// Both account statements, because CREATE USER IF NOT EXISTS does not touch an
	// account that already exists: the ALTER is what converts one made before this
	// clause existed, when a customer removes the host and adds it back.
	for _, prefix := range []string{"CREATE USER", "ALTER USER"} {
		statement, ok := findStatement(recorded, prefix)
		if !ok {
			t.Fatalf("no %s statement was issued: %v", prefix, recorded)
		}
		if !strings.Contains(statement, "REQUIRE SSL") {
			t.Errorf("%s does not require TLS: %s", prefix, statement)
		}
	}
}

// The clause belongs on the account, not on the privilege. GRANT does not change
// an account's REQUIRE condition, and stating it there would be a claim the
// statement does not make.
func TestTheGrantAndTheDropDoNotCarryTheClause(t *testing.T) {
	_, stdinPath := stubRootSQL(t, 0)

	if err := MySQLGrantRemote("c_t_db", "203.0.113.7", "pw23456789", []string{"c_t_shop"}); err != nil {
		t.Fatalf("MySQLGrantRemote: %v", err)
	}
	recorded := statementsFrom(readStub(t, stdinPath))
	if statement, ok := findStatement(recorded, "GRANT ALL PRIVILEGES"); ok && strings.Contains(statement, "REQUIRE") {
		t.Errorf("the grant carries a REQUIRE clause: %s", statement)
	}

	if err := MySQLRevokeRemote("c_t_db", "203.0.113.7"); err != nil {
		t.Fatalf("MySQLRevokeRemote: %v", err)
	}
	recorded = statementsFrom(readStub(t, stdinPath))
	if statement, ok := findStatement(recorded, "DROP USER"); ok && strings.Contains(statement, "REQUIRE") {
		t.Errorf("the drop carries a REQUIRE clause: %s", statement)
	}
}

// The clause must not have loosened the checks that stand between a request and
// an interpolated statement.
func TestTheRemoteGrantStillRefusesAnUnusableHostOrIdentifier(t *testing.T) {
	_, stdinPath := stubRootSQL(t, 0)

	for name, call := range map[string]func() error{
		"wildcard host":   func() error { return MySQLGrantRemote("c_t_db", "%", "pw23456789", nil) },
		"bad user":        func() error { return MySQLGrantRemote("c_t db", "203.0.113.7", "pw23456789", nil) },
		"bad database":    func() error { return MySQLGrantRemote("c_t_db", "203.0.113.7", "pw23456789", []string{"a`b"}) },
		"wildcard revoke": func() error { return MySQLRevokeRemote("c_t_db", "%") },
	} {
		if err := call(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// The stub writes this file only when it is actually run, so its absence is
	// the proof that nothing reached MariaDB.
	if _, err := os.Stat(stdinPath); err == nil {
		t.Error("a refused request reached MariaDB")
	}
}
