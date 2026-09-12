package serverip

import (
	"context"
	"database/sql/driver"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// WritePersistence writes a root shell script and a systemd unit, then reloads
// systemd, so it had no test. The two paths and the command are seams (see
// seams.go); these tests point them at a temporary directory and a recorder.

const persistQuery = "SELECT ip, interface, prefix_length, label FROM server_ips ORDER BY id"

// ranCommand is one command WritePersistence ran.
type ranCommand struct {
	name string
	args []string
}

// persistInto points the two file seams at a temporary directory and records
// every command instead of running it.
func persistInto(t *testing.T, failure error) (script, unit *string, ran *[]ranCommand) {
	t.Helper()
	dir := t.TempDir()
	scriptFile := filepath.Join(dir, "servika-server-ips")
	unitFile := filepath.Join(dir, "servika-server-ips.service")
	setForTest(t, &scriptPath, scriptFile)
	setForTest(t, &unitPath, unitFile)

	var commands []ranCommand
	setForTest(t, &runCommand, func(_ context.Context, name string, args ...string) (string, error) {
		commands = append(commands, ranCommand{name: name, args: args})
		if failure != nil {
			return "Failed to enable unit", failure
		}
		return "", nil
	})
	return &scriptFile, &unitFile, &commands
}

// rowsOf scripts the table WritePersistence reads.
func rowsOf(rows ...[]driver.Value) *sqlScript {
	script := newScript()
	script.rows[persistQuery] = rows
	return script
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path) // #nosec G304 -- a path this test just created.
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(body)
}

func TestTheBootScriptCarriesOneSortedLinePerRow(t *testing.T) {
	scriptFile, unitFile, ran := persistInto(t, nil)
	db := scriptDB(t, rowsOf(
		[]driver.Value{"203.0.113.30", "eth0", int64(32), "panel-0002"},
		[]driver.Value{"203.0.113.20", "eth0", int64(32), "panel-0001"},
	))

	if err := WritePersistence(context.Background(), db); err != nil {
		t.Fatalf("WritePersistence: %v", err)
	}

	body := readFile(t, *scriptFile)
	if !strings.HasPrefix(body, scriptHeader) {
		t.Errorf("the script does not open with the generated header:\n%s", body)
	}
	// Every line tolerates "File exists", which is the normal state of a re-run,
	// and the set is sorted so an unchanged table writes an unchanged file.
	want := scriptHeader +
		"ip addr add 203.0.113.20/32 dev eth0 label panel-0001 2>/dev/null || true\n" +
		"ip addr add 203.0.113.30/32 dev eth0 label panel-0002 2>/dev/null || true\n"
	if body != want {
		t.Errorf("script =\n%s\nwant\n%s", body, want)
	}

	unit := readFile(t, *unitFile)
	if !strings.Contains(unit, "ExecStart="+*scriptFile) {
		t.Errorf("the unit does not run the script it was written beside:\n%s", unit)
	}
	assertRan(t, *ran, []ranCommand{
		{name: "systemctl", args: []string{"daemon-reload"}},
		{name: "systemctl", args: []string{"enable", unitName}},
	})
}

func assertRan(t *testing.T, got, want []ranCommand) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("commands = %v, want %v", got, want)
	}
	for i := range want {
		if got[i].name != want[i].name || strings.Join(got[i].args, " ") != strings.Join(want[i].args, " ") {
			t.Fatalf("commands = %v, want %v", got, want)
		}
	}
}

// An empty table still writes both files: the unit must exist and add nothing,
// rather than keep the addresses of a table that no longer holds them.
func TestAnEmptyTableStillWritesTheScript(t *testing.T) {
	scriptFile, _, _ := persistInto(t, nil)
	db := scriptDB(t, rowsOf())

	if err := WritePersistence(context.Background(), db); err != nil {
		t.Fatalf("WritePersistence: %v", err)
	}
	if body := readFile(t, *scriptFile); body != scriptHeader+"\n" {
		t.Errorf("script = %q, want the header alone", body)
	}
}

// Every value is checked again on the way OUT, because this text becomes a root
// shell script and a row outlives the code that wrote it.
func TestARowThatCouldNotHaveBeenWrittenStopsTheScript(t *testing.T) {
	cases := []struct {
		name string
		row  []driver.Value
		want string
	}{
		{
			name: "an address that is not IPv4",
			row:  []driver.Value{"2001:db8::1", "eth0", int64(32), "panel-0001"},
			want: `row for "2001:db8::1"`,
		},
		{
			name: "a prefix outside IPv4",
			row:  []driver.Value{"203.0.113.20", "eth0", int64(64), "panel-0001"},
			want: `row for "203.0.113.20"`,
		},
		{
			name: "an interface name that is a flag",
			row:  []driver.Value{"203.0.113.20", "-r", int64(32), "panel-0001"},
			want: `names the interface "-r"`,
		},
		{
			name: "a label this package did not generate",
			row:  []driver.Value{"203.0.113.20", "eth0", int64(32), "eth0"},
			want: `carries the label "eth0"`,
		},
		{
			name: "a label carrying another shell word",
			row:  []driver.Value{"203.0.113.20", "eth0", int64(32), "panel- x"},
			want: `carries the label "panel- x"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scriptFile, _, ran := persistInto(t, nil)
			db := scriptDB(t, rowsOf(tc.row))

			err := WritePersistence(context.Background(), db)
			if err == nil {
				t.Fatal("the row was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error is %q, want it to hold %q", err, tc.want)
			}
			// Nothing is written and nothing is reloaded: the old script stays
			// as it was rather than being replaced by a shorter one.
			if _, err := os.Stat(*scriptFile); !os.IsNotExist(err) {
				t.Error("a script was written for a row that was refused")
			}
			if len(*ran) != 0 {
				t.Errorf("systemd was reloaded anyway: %v", *ran)
			}
		})
	}
}

// A systemctl that fails names which step failed, because "enable" failing
// after "daemon-reload" succeeded is a different repair.
func TestAFailingSystemctlNamesTheStep(t *testing.T) {
	_, _, ran := persistInto(t, errors.New("exit status 1"))
	db := scriptDB(t, rowsOf([]driver.Value{"203.0.113.20", "eth0", int64(32), "panel-0001"}))

	err := WritePersistence(context.Background(), db)
	if err == nil {
		t.Fatal("the failure was swallowed")
	}
	if !strings.Contains(err.Error(), "daemon-reload") {
		t.Errorf("error is %q, want it to name daemon-reload", err)
	}
	if len(*ran) != 1 {
		t.Errorf("commands = %v, want the run to stop at the first failure", *ran)
	}
}

// "enable" failing after "daemon-reload" succeeded names its own step, so the
// operator repairs the right one.
func TestAFailingEnableNamesTheUnit(t *testing.T) {
	_, _, ran := persistInto(t, nil)
	setForTest(t, &runCommand, func(_ context.Context, _ string, args ...string) (string, error) {
		*ran = append(*ran, ranCommand{name: "systemctl", args: args})
		if len(args) > 0 && args[0] == "enable" {
			return "Failed to enable unit", errors.New("exit status 1")
		}
		return "", nil
	})
	db := scriptDB(t, rowsOf([]driver.Value{"203.0.113.20", "eth0", int64(32), "panel-0001"}))

	err := WritePersistence(context.Background(), db)
	if err == nil {
		t.Fatal("the failure was swallowed")
	}
	if !strings.Contains(err.Error(), "enable "+unitName) {
		t.Errorf("error is %q, want it to name the unit it could not enable", err)
	}
}

// A script path that cannot be written stops before the unit and before
// systemd, so a half-written pair is never left behind.
func TestAnUnwritableScriptPathStopsTheWrite(t *testing.T) {
	_, unitFile, ran := persistInto(t, nil)
	setForTest(t, &scriptPath, filepath.Join(t.TempDir(), "missing", "servika-server-ips"))
	db := scriptDB(t, rowsOf([]driver.Value{"203.0.113.20", "eth0", int64(32), "panel-0001"}))

	if err := WritePersistence(context.Background(), db); err == nil {
		t.Fatal("an unwritable path was accepted")
	}
	if _, err := os.Stat(*unitFile); !os.IsNotExist(err) {
		t.Error("the unit was written after the script could not be")
	}
	if len(*ran) != 0 {
		t.Errorf("systemd was reloaded anyway: %v", *ran)
	}
}

// A unit path that cannot be written is returned rather than logged, and the
// script beside it is already on disk: the caller answers with the warning that
// says the reboot is not covered.
func TestAnUnwritableUnitPathIsReported(t *testing.T) {
	scriptFile, _, ran := persistInto(t, nil)
	setForTest(t, &unitPath, t.TempDir()) // a directory, which WriteFile refuses
	db := scriptDB(t, rowsOf([]driver.Value{"203.0.113.20", "eth0", int64(32), "panel-0001"}))

	if err := WritePersistence(context.Background(), db); err == nil {
		t.Fatal("an unwritable unit path was accepted")
	}
	if _, err := os.Stat(*scriptFile); err != nil {
		t.Errorf("the script was not written before the unit: %v", err)
	}
	if len(*ran) != 0 {
		t.Errorf("systemd was reloaded anyway: %v", *ran)
	}
}

// Every read failure is returned as it is: the caller logs it and the address
// stays live, which is the whole point of the boot script being the last step.
func TestEveryReadFailureIsReturned(t *testing.T) {
	cases := []struct {
		name  string
		build func(*sqlScript)
		want  string
	}{
		{
			name:  "the query itself",
			build: func(s *sqlScript) { s.fail[persistQuery] = errors.New("connection refused") },
			want:  "connection refused",
		},
		{
			name: "a row that does not read back",
			build: func(s *sqlScript) {
				s.rows[persistQuery] = [][]driver.Value{
					{"203.0.113.20", "eth0", "not a number", "panel-0001"},
				}
			},
			want: "Scan error on column index 2",
		},
		{
			name:  "a result set that ends badly",
			build: func(s *sqlScript) { s.endWith[persistQuery] = errors.New("connection reset") },
			want:  "connection reset",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scriptFile, _, _ := persistInto(t, nil)
			script := newScript()
			tc.build(script)

			err := WritePersistence(context.Background(), scriptDB(t, script))
			if err == nil {
				t.Fatal("the failure was swallowed")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error is %q, want it to hold %q", err, tc.want)
			}
			if _, err := os.Stat(*scriptFile); !os.IsNotExist(err) {
				t.Error("a script was written from a table that could not be read")
			}
		})
	}
}
