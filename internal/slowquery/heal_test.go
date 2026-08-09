package slowquery

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// captureRootSQL replaces the privileged runner and returns what it was handed.
func captureRootSQL(t *testing.T) *[]string {
	t.Helper()
	var seen []string
	previous := rootSQL
	rootSQL = func(statements ...string) error {
		seen = append(seen, statements...)
		return nil
	}
	t.Cleanup(func() { rootSQL = previous })
	return &seen
}

// THE threshold rule. The value is rendered into MariaDB's own configuration
// file and into a SET GLOBAL statement, and a file MariaDB refuses stops it from
// starting on the next restart.
func TestAThresholdOutsideTheRangeIsRefused(t *testing.T) {
	for _, bad := range []float64{0, -1, 0.05, 60.1, 1e9} {
		if ValidThreshold(bad) {
			t.Errorf("ValidThreshold(%v) = true, want false", bad)
		}
	}
	for _, good := range []float64{0.1, 1, 2, 59.999, 60} {
		if !ValidThreshold(good) {
			t.Errorf("ValidThreshold(%v) = false, want true", good)
		}
	}
}

// A refused threshold never reaches MariaDB: Apply falls back to the default
// rather than rendering the value it was handed.
func TestARefusedThresholdNeverReachesMariaDB(t *testing.T) {
	seen := captureRootSQL(t)
	withTempPaths(t)

	if err := Apply(context.Background(), true, 1e9); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	joined := strings.Join(*seen, "\n")
	if strings.Contains(joined, "1e+09") || strings.Contains(joined, "1000000000") {
		t.Errorf("the refused value reached MariaDB:\n%s", joined)
	}
	if !strings.Contains(joined, "SET GLOBAL long_query_time = 2.000;") {
		t.Errorf("the default was not applied:\n%s", joined)
	}
}

// The threshold is FORMATTED, never interpolated as text, so a value carrying
// SQL cannot reach the statement. Go's type system makes the field a float, and
// this pins the rendering that keeps it one.
func TestTheThresholdIsRenderedAsANumber(t *testing.T) {
	seen := captureRootSQL(t)
	withTempPaths(t)

	if err := Apply(context.Background(), true, 1.5); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	joined := strings.Join(*seen, "\n")
	if !strings.Contains(joined, "SET GLOBAL long_query_time = 1.500;") {
		t.Errorf("the threshold was not rendered with a fixed precision:\n%s", joined)
	}

	source := readSource(t, "heal.go")
	if !strings.Contains(source, `"SET GLOBAL long_query_time = %.3f;"`) {
		t.Error("the statement is not built with a numeric verb")
	}
	if strings.Contains(source, "long_query_time = %s") || strings.Contains(source, "long_query_time = \"+") {
		t.Error("the threshold reaches the statement as text")
	}
}

// Privileged SQL travels on stdin, never on argv: /proc/<pid>/cmdline is
// world-readable and a tenant reaches it through cron.
func TestPrivilegedSQLTravelsOnStdin(t *testing.T) {
	source := readSource(t, "heal.go")
	if !strings.Contains(source, "credentials.RunRootSQL") {
		t.Error("the heal does not use the shared privileged runner")
	}
	if strings.Contains(source, `"mysql", "-e"`) || strings.Contains(source, `"-e",`) {
		t.Error("a statement is placed on argv")
	}

	// The runner itself: the command it builds must carry no statement.
	cmd := exec.Command("mysql")
	if len(cmd.Args) != 1 {
		t.Fatalf("unexpected baseline argv: %v", cmd.Args)
	}
}

// MariaDB is never restarted. A startup heal that restarted it would drop every
// site's database connections.
func TestMariaDBIsNeverRestarted(t *testing.T) {
	source := readSource(t, "heal.go")
	// Matched as QUOTED arguments, not as prose: the comments explain why the
	// heal avoids a restart, and a bare word search would flag those instead of
	// a real call.
	for _, forbidden := range []string{`"systemctl"`, `"restart"`, `"shutdown"`, `"reload"`} {
		if strings.Contains(source, forbidden) {
			t.Errorf("the heal passes %s to a command, which can interrupt every site", forbidden)
		}
	}
	if !strings.Contains(source, "SET GLOBAL") {
		t.Error("the heal has no way to make the setting current without a restart")
	}
}

// The switch is applied LAST, so the file, the threshold and the verbosity are
// already in force for the first entry MariaDB writes.
func TestTheSwitchIsAppliedLast(t *testing.T) {
	seen := captureRootSQL(t)
	withTempPaths(t)

	if err := Apply(context.Background(), true, 2); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	last := (*seen)[len(*seen)-1]
	if !strings.HasPrefix(last, "SET GLOBAL slow_query_log =") {
		t.Errorf("the last statement is %q, want the switch", last)
	}
}

// The drop-in carries the setting across a restart and is idempotent, so a
// startup heal does not rewrite a file that already says the right thing.
func TestTheDropInIsIdempotent(t *testing.T) {
	dir := withTempPaths(t)
	captureRootSQL(t)

	if err := Apply(context.Background(), true, 2); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	first, err := os.Stat(dropInPath)
	if err != nil {
		t.Fatalf("the drop-in was not written: %v", err)
	}
	body, err := os.ReadFile(dropInPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"slow_query_log            = 1",
		"long_query_time           = 2.000",
		"log_slow_verbosity        = query_plan",
		filepath.Join(dir, "servika-slow.log"),
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("the drop-in is missing %q:\n%s", want, body)
		}
	}

	if err := Apply(context.Background(), true, 2); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	second, err := os.Stat(dropInPath)
	if err != nil {
		t.Fatal(err)
	}
	if !first.ModTime().Equal(second.ModTime()) {
		t.Error("the drop-in was rewritten even though nothing changed")
	}
}

// Rotation moves the file and asks the server to reopen it. copytruncate races
// with mysqld's write and must never appear.
func TestRotationDoesNotTruncateUnderTheServer(t *testing.T) {
	withTempPaths(t)
	captureRootSQL(t)

	if err := Apply(context.Background(), true, 2); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	body, err := os.ReadFile(logrotatePath)
	if err != nil {
		t.Fatalf("the logrotate drop-in was not written: %v", err)
	}
	text := string(body)
	if strings.Contains(text, "copytruncate") {
		t.Error("copytruncate races with mysqld's write")
	}
	for _, want := range []string{"flush-slow-logs", "create 0600 mysql mysql", "rotate 7"} {
		if !strings.Contains(text, want) {
			t.Errorf("the logrotate drop-in is missing %q:\n%s", want, text)
		}
	}
}

// The log directory is closed to everyone but its owner. The file carries every
// tenant's SQL, so a loose mode lets one tenant read a neighbour's queries.
func TestTheLogDirectoryIsClosedToOtherTenants(t *testing.T) {
	dir := withTempPaths(t)
	captureRootSQL(t)
	// A deliberately loose starting state, which is what a package default or a
	// manual chmod leaves behind.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "servika-slow.log")
	if err := os.WriteFile(logPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := Apply(context.Background(), true, 2); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("directory mode is %o, want 700", info.Mode().Perm())
	}
	fi, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("file mode is %o, which is readable by another account", fi.Mode().Perm())
	}

	// Idempotent: a second pass changes nothing.
	if err := Apply(context.Background(), true, 2); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if again, _ := os.Stat(dir); again.Mode().Perm() != 0o700 {
		t.Errorf("directory mode drifted to %o on the second pass", again.Mode().Perm())
	}
}

// A path crossing into SQL is quoted, even though the only caller passes a
// configured absolute path.
func TestThePathIsQuotedIntoTheStatement(t *testing.T) {
	if got := quoteSQLString(`/var/log/o'brien/slow.log`); got != `'/var/log/o\'brien/slow.log'` {
		t.Errorf("quoteSQLString = %s", got)
	}
	if got := quoteSQLString(`/a\b`); got != `'/a\\b'` {
		t.Errorf("quoteSQLString = %s", got)
	}
}

// withTempPaths points every file the heal writes at a temporary directory and
// returns the log directory.
func withTempPaths(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SERVIKA_MARIADB_SLOW_LOG", filepath.Join(dir, "servika-slow.log"))

	previousDropIn, previousRotate := dropInPath, logrotatePath
	setPaths(filepath.Join(dir, "servika-slowlog.cnf"), filepath.Join(dir, "logrotate.conf"))
	t.Cleanup(func() { setPaths(previousDropIn, previousRotate) })

	// The heal must not need root to be exercised, so the command that changes
	// the owner is stubbed out.
	previousCommand := healCommand
	healCommand = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}
	t.Cleanup(func() { healCommand = previousCommand })
	return dir
}
