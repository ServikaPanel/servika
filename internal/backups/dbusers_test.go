package backups

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These tests need a real MariaDB reachable through root socket auth. Without it
// they skip, so the package still prints ok on a host with no database.
const (
	testDB   = "svk_t_dbusers"
	testUser = "svk_t_user"
	testPass = "S3cr3t-Passw0rd!x"
)

func requireMySQL(t *testing.T) {
	t.Helper()
	if err := exec.Command("mysql", "-e", "SELECT 1").Run(); err != nil {
		t.Skip("no mysql access, skipping")
	}
}

func cleanupTestDB() {
	bg := context.Background()
	_ = mysqlExec(bg, "DROP DATABASE IF EXISTS `"+testDB+"`;")
	_ = mysqlExec(bg, "DROP USER IF EXISTS '"+testUser+"'@'localhost';")
}

func setupTestDB(t *testing.T) {
	t.Helper()
	cleanupTestDB()
	if err := mysqlExec(context.Background(),
		"CREATE DATABASE `"+testDB+"`;"+
			"CREATE USER '"+testUser+"'@'localhost' IDENTIFIED BY '"+testPass+"';"+
			"GRANT ALL PRIVILEGES ON `"+testDB+"`.* TO '"+testUser+"'@'localhost';"); err != nil {
		t.Fatalf("setup: %v", err)
	}
}

// TestWriteAndApplyDBUsers: an account that entered the archive must come BACK
// after it is dropped, and its password must still work.
func TestWriteAndApplyDBUsers(t *testing.T) {
	requireMySQL(t)
	setupTestDB(t)
	defer cleanupTestDB()
	bg := context.Background()

	// Positive control: does the measurement method work at all? If this fails the
	// "the password came back" assertion below proves nothing.
	if err := exec.Command("mysql", "-u", testUser, "-p"+testPass, "-e", "SELECT 1", testDB).Run(); err != nil {
		t.Fatalf("positive control: the fresh user cannot connect: %v", err)
	}

	dir := t.TempDir()
	if n := writeDBUsers(bg, dir, []string{testDB}); n != 1 {
		t.Fatalf("accounts written = %d, want 1", n)
	}
	raw, err := os.ReadFile(filepath.Join(dir, dbUsersFileName))
	if err != nil {
		t.Fatalf("file unreadable: %v", err)
	}
	content := string(raw)
	if !strings.Contains(content, "CREATE USER IF NOT EXISTS") || !strings.Contains(content, testUser) {
		t.Fatalf("no CREATE USER:\n%s", content)
	}
	if !strings.Contains(content, "ON `"+testDB+"`.*") {
		t.Fatalf("no DB grant:\n%s", content)
	}
	// The file carries a password hash: its permissions must be 0600.
	fi, _ := os.Stat(filepath.Join(dir, dbUsersFileName))
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
	}

	// Drop the user, then bring it back from the archive.
	if err := mysqlExec(bg, "DROP USER '"+testUser+"'@'localhost';"); err != nil {
		t.Fatalf("drop user: %v", err)
	}
	if userExists(t) {
		t.Fatal("negative control: the user was not dropped, the rest is meaningless")
	}
	n, err := applyDBUsers(bg, dir, map[string]bool{testDB: true})
	if err != nil || n == 0 {
		t.Fatalf("apply: n=%d err=%v", n, err)
	}
	if !userExists(t) {
		t.Fatal("the user did not come back")
	}
	// The password must come back too (the hash travelled): connect and prove it.
	// Over the socket: a @localhost account does not match a TCP 127.0.0.1 client.
	if err := exec.Command("mysql", "-u", testUser, "-p"+testPass, "-e", "SELECT 1", testDB).Run(); err != nil {
		t.Fatalf("the restored user could not connect with its password: %v", err)
	}
}

// TestGlobalGrantRefused: NEGATIVE control. A grant from an archive must never
// widen privilege, neither on write into the file nor on read out of it.
func TestGlobalGrantRefused(t *testing.T) {
	requireMySQL(t)
	setupTestDB(t)
	defer cleanupTestDB()
	bg := context.Background()

	// (a) Write side: the user has a REAL global grant; it must not enter the file.
	if err := mysqlExec(bg, "GRANT SELECT ON *.* TO '"+testUser+"'@'localhost';"); err != nil {
		t.Fatalf("global grant: %v", err)
	}
	dir := t.TempDir()
	writeDBUsers(bg, dir, []string{testDB})
	raw, _ := os.ReadFile(filepath.Join(dir, dbUsersFileName))
	for l := range strings.SplitSeq(string(raw), "\n") {
		if strings.HasPrefix(l, "GRANT") && strings.Contains(l, "ON *.*") && !strings.Contains(l, "USAGE ON *.*") {
			t.Fatalf("global privilege leaked into the archive: %s", l)
		}
	}

	// (b) Read side: inject a global grant into the file by hand; it must not apply.
	path := filepath.Join(dir, dbUsersFileName)
	bad := "GRANT ALL PRIVILEGES ON *.* TO '" + testUser + "'@'localhost' WITH GRANT OPTION;\n" +
		"GRANT ALL PRIVILEGES ON `mysql`.* TO '" + testUser + "'@'localhost';\n" +
		// Chained: the first statement is allowed, the second is global. `mysql -e`
		// would run both; a leftover semicolon in the line must trigger the refusal.
		"GRANT ALL PRIVILEGES ON `" + testDB + "`.* TO '" + testUser + "'@'localhost'; " +
		"GRANT ALL PRIVILEGES ON *.* TO '" + testUser + "'@'localhost';\n"
	_ = os.WriteFile(path, append(raw, []byte(bad)...), 0600)

	_ = mysqlExec(bg, "REVOKE SELECT ON *.* FROM '"+testUser+"'@'localhost';")
	if _, err := applyDBUsers(bg, dir, map[string]bool{testDB: true}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	out, _ := exec.Command("mysql", "-N", "-B", "-e",
		"SHOW GRANTS FOR '"+testUser+"'@'localhost'").Output()
	for l := range strings.SplitSeq(string(out), "\n") {
		if strings.Contains(l, "ON *.*") && !strings.Contains(l, "USAGE ON *.*") {
			t.Fatalf("injected global privilege WAS applied: %s", l)
		}
		if strings.Contains(l, "`mysql`.*") {
			t.Fatalf("a grant on a database outside the allowlist WAS applied: %s", l)
		}
	}
}

func userExists(t *testing.T) bool {
	t.Helper()
	out, err := exec.Command("mysql", "-N", "-B", "-e",
		"SELECT COUNT(*) FROM mysql.user WHERE User='"+testUser+"'").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) != "0"
}
