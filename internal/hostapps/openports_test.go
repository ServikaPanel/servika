package hostapps

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

// The firewall asks these two questions on every rebuild, so they are the one
// place the selection rule lives. A scripted connector answers them without a
// database.
type portScript struct {
	installed int64
	ports     []int64
	queryErr  error
}

func (s *portScript) Connect(context.Context) (driver.Conn, error) { return s, nil }
func (s *portScript) Driver() driver.Driver                        { return s }
func (s *portScript) Open(string) (driver.Conn, error)             { return s, nil }
func (s *portScript) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (s *portScript) Close() error                                 { return nil }
func (s *portScript) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (s *portScript) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if s.queryErr != nil {
		return nil, s.queryErr
	}
	if strings.Contains(query, "COUNT(*) FROM host_apps") {
		return &portRows{values: [][]driver.Value{{s.installed}}}, nil
	}
	rows := make([][]driver.Value, 0, len(s.ports))
	for _, port := range s.ports {
		rows = append(rows, []driver.Value{port})
	}
	return &portRows{values: rows}, nil
}

type portRows struct {
	values [][]driver.Value
	at     int
}

func (r *portRows) Columns() []string { return []string{"port"} }
func (r *portRows) Close() error      { return nil }
func (r *portRows) Next(dest []driver.Value) error {
	if r.at >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.at])
	r.at++
	return nil
}

func portDB(t *testing.T, script *portScript) *sql.DB {
	t.Helper()
	db := sql.OpenDB(script)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// A port outside the allocator's range must not be returned. The firewall's
// accept would sit above a drop that does not cover it, so it would open a port
// belonging to something else entirely.
func TestOpenPortsDropsAPortOutsideTheRange(t *testing.T) {
	script := &portScript{ports: []int64{int64(PortMin - 1), int64(PortMin), int64(PortMax), int64(PortMax + 1), 22}}

	ports, err := OpenPorts(t.Context(), portDB(t, script))
	if err != nil {
		t.Fatalf("OpenPorts: %v", err)
	}
	want := []int{PortMin, PortMax}
	if !reflect.DeepEqual(ports, want) {
		t.Errorf("OpenPorts() = %v, want %v", ports, want)
	}
}

// An empty list is a valid answer for a firewall renderer ("open nothing"), so a
// read failure has to be an error or a database that could not be read would
// close every application's port on the next reapply.
func TestOpenPortsReportsAReadFailure(t *testing.T) {
	script := &portScript{queryErr: errors.New("the read is refused in this test")}

	if _, err := OpenPorts(t.Context(), portDB(t, script)); err == nil {
		t.Error("a failed read answered an empty list")
	}
}

// The range drop comes with the listeners: on a server with none, emitting it
// would cut off an operator running their own service on one of those ports.
func TestAnyInstalledFollowsTheRowCount(t *testing.T) {
	for _, tc := range []struct {
		count int64
		want  bool
	}{{0, false}, {1, true}, {7, true}} {
		got, err := AnyInstalled(t.Context(), portDB(t, &portScript{installed: tc.count}))
		if err != nil {
			t.Fatalf("AnyInstalled: %v", err)
		}
		if got != tc.want {
			t.Errorf("AnyInstalled() with %d rows = %t, want %t", tc.count, got, tc.want)
		}
	}
}
