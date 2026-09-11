package dns

import (
	"context"
	"database/sql/driver"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// commandRecorder answers the commands a zone write runs. Every call is
// recorded as one line, and a line the test's fail function names fails with
// the output it returns.
type commandRecorder struct {
	mu    sync.Mutex
	lines []string
	fail  func(line string) (string, bool)
}

func withZoneCommands(t *testing.T, fail func(line string) (string, bool)) *commandRecorder {
	t.Helper()
	recorder := &commandRecorder{fail: fail}
	setForTest(t, &zoneCommand, recorder.command)
	return recorder
}

func (c *commandRecorder) command(name string, args ...string) *exec.Cmd {
	line := strings.Join(append([]string{name}, args...), " ")
	c.mu.Lock()
	c.lines = append(c.lines, line)
	c.mu.Unlock()
	if output, failing := c.fail(line); failing {
		return exec.Command("sh", "-c", `printf '%s' "$1"; exit 1`, "sh", output)
	}
	return exec.Command("true")
}

func (c *commandRecorder) all() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.lines...)
}

// nothingFails is the fail function for a host where every command succeeds.
func nothingFails(string) (string, bool) { return "", false }

// failLines fails the commands named exactly, each with its output.
func failLines(outputs map[string]string) func(string) (string, bool) {
	return func(line string) (string, bool) {
		output, failing := outputs[line]
		return output, failing
	}
}

// failPrefix fails every command whose line starts with prefix.
func failPrefix(prefix, output string) func(string) (string, bool) {
	return func(line string) (string, bool) {
		return output, strings.HasPrefix(line, prefix)
	}
}

// zoneHost points the zone directory and the include file at temporary paths.
func zoneHost(t *testing.T) (zoneDir, include string) {
	t.Helper()
	zoneDir = t.TempDir()
	include = filepath.Join(t.TempDir(), "servika-zones.conf")
	setForTest(t, &zoneDirectory, zoneDir)
	setForTest(t, &namedConfIncludePath, include)
	return zoneDir, include
}

const zoneRecordsQuery = "WHERE domain_id=? AND enabled=1 ORDER BY type, name"

// zoneScript answers a zone write for domain 7, example.com, with one A record
// and a configured nameserver pair.
func zoneScript() *sqlScript {
	s := newScript()
	s.rows["SELECT domain_name FROM domains WHERE id=?"] = [][]driver.Value{{"example.com"}}
	s.rows[zoneRecordsQuery] = [][]driver.Value{
		{int64(1), int64(7), "@", "A", "192.0.2.10", int64(3600), int64(0), int64(1), "2026-09-12 10:00"},
	}
	s.rows["JOIN reseller_nameservers rn"] = nil
	s.rows["SELECT ns1_hostname, ns2_hostname FROM panel_settings"] = [][]driver.Value{{"ns1.host.example", "ns2.host.example"}}
	s.rows["FROM dns_soa WHERE domain_id=?"] = nil
	s.rows["SELECT d.domain_name, COALESCE(d.dnssec_active,0) FROM domains d"] = [][]driver.Value{{"example.com", int64(0)}}
	return s
}

// assertErrText fails the test unless err reads want; an empty want means nil.
func assertErrText(t *testing.T, err error, want string) {
	t.Helper()
	got := ""
	if err != nil {
		got = err.Error()
	}
	if got != want {
		t.Fatalf("err = %q, want %q", got, want)
	}
}

func TestWriteZoneStopsBeforeItServesABadZone(t *testing.T) {
	cases := []struct {
		name    string
		script  func(s *sqlScript)
		host    func(t *testing.T, zoneDir string)
		fail    func(string) (string, bool)
		wantErr string
		calls   int
	}{
		{name: "a domain that cannot be read",
			script:  func(s *sqlScript) { s.fail["SELECT domain_name FROM domains WHERE id=?"] = errScripted },
			wantErr: errScripted.Error()},
		{name: "a name that is not a file leaf",
			script: func(s *sqlScript) {
				s.rows["SELECT domain_name FROM domains WHERE id=?"] = [][]driver.Value{{"../evil"}}
			},
			wantErr: `invalid domain name for a zone file: "../evil"`},
		{name: "records that cannot be queried",
			script: func(s *sqlScript) { s.fail[zoneRecordsQuery] = errScripted }, wantErr: errScripted.Error()},
		{name: "a record row that cannot be read",
			script: func(s *sqlScript) {
				s.rows[zoneRecordsQuery] = [][]driver.Value{{"x", int64(7), "@", "A", "192.0.2.10", int64(3600), int64(0), int64(1), ""}}
			},
			wantErr: "sql: Scan error on column index 0*"},
		{name: "a result set that ends in an error",
			script: func(s *sqlScript) { s.endWith[zoneRecordsQuery] = errScripted }, wantErr: errScripted.Error()},
		{name: "a zone directory that cannot be made",
			host: func(t *testing.T, zoneDir string) {
				blocker := filepath.Join(zoneDir, "file")
				if err := os.WriteFile(blocker, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				setForTest(t, &zoneDirectory, filepath.Join(blocker, "named"))
			},
			wantErr: "mkdir *"},
		{name: "a zone named-checkzone refuses", fail: failPrefix("named-checkzone", "bad zone"),
			wantErr: "named-checkzone: bad zone: exit status 1", calls: 1},
		{name: "a zone file that cannot be replaced",
			host: func(t *testing.T, zoneDir string) {
				if err := os.MkdirAll(filepath.Join(zoneDir, "example.com.zone", "occupied"), 0o750); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "rename *", calls: 1},
		{name: "an include list that cannot be read",
			script: func(s *sqlScript) {
				s.fail["SELECT d.domain_name, COALESCE(d.dnssec_active,0) FROM domains d"] = errScripted
			},
			wantErr: errScripted.Error(), calls: 3},
		{name: "an include named-checkconf refuses", fail: failPrefix("named-checkconf ", "bad include"),
			wantErr: "validate generated zone include: bad include: exit status 1", calls: 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			zoneDir, _ := zoneHost(t)
			recorder := runWriteZone(t, tc.script, tc.host, tc.fail, zoneDir)
			assertZoneFailure(t, recorder.err, tc.wantErr)
			if got := len(recorder.commands.all()); got != tc.calls {
				t.Errorf("%d commands ran, want %d: %q", got, tc.calls, recorder.commands.all())
			}
			assertNoTempZone(t, zoneDir)
		})
	}
}

// zoneRun is one WriteZone call and what it ran.
type zoneRun struct {
	err      error
	commands *commandRecorder
}

func runWriteZone(t *testing.T, change func(*sqlScript), host func(*testing.T, string), fail func(string) (string, bool), zoneDir string) zoneRun {
	t.Helper()
	script := zoneScript()
	if change != nil {
		change(script)
	}
	if host != nil {
		host(t, zoneDir)
	}
	if fail == nil {
		fail = nothingFails
	}
	commands := withZoneCommands(t, fail)
	err := WriteZone(context.Background(), scriptDB(t, script), 7)
	return zoneRun{err: err, commands: commands}
}

// assertZoneFailure checks the error. A want that ends in "*" pins only the
// start of the text, for an error whose rest names a temporary path or a
// conversion the driver words.
func assertZoneFailure(t *testing.T, err error, want string) {
	t.Helper()
	prefix, pinsStart := strings.CutSuffix(want, "*")
	switch {
	case err == nil:
		t.Fatalf("err = nil, want %q", want)
	case pinsStart:
		if !strings.HasPrefix(err.Error(), prefix) {
			t.Fatalf("err = %q, want it to start with %q", err, prefix)
		}
	default:
		assertErrText(t, err, want)
	}
}

// assertNoTempZone fails the test when a refused write left its temporary file.
func assertNoTempZone(t *testing.T, zoneDir string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(zoneDir, "example.com.zone.tmp")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the temporary zone file was left behind: %v", err)
	}
}

// A domain with no enabled record writes no zone and runs nothing.
func TestWriteZoneWritesNothingForAnEmptyZone(t *testing.T) {
	zoneDir, _ := zoneHost(t)
	run := runWriteZone(t, func(s *sqlScript) { s.rows[zoneRecordsQuery] = nil }, nil, nil, zoneDir)
	assertErrText(t, run.err, "")
	if calls := run.commands.all(); len(calls) != 0 {
		t.Errorf("an empty zone ran %q", calls)
	}
	if entries, _ := os.ReadDir(zoneDir); len(entries) != 0 {
		t.Errorf("an empty zone wrote %d files", len(entries))
	}
}

// A temporary file the panel cannot write stops the run before it validates or
// replaces anything.
func TestWriteZoneStopsWhenTheTemporaryFileCannotBeWritten(t *testing.T) {
	zoneDir, _ := zoneHost(t)
	if err := os.MkdirAll(filepath.Join(zoneDir, "example.com.zone.tmp"), 0o750); err != nil {
		t.Fatal(err)
	}
	run := runWriteZone(t, nil, nil, nil, zoneDir)
	assertZoneFailure(t, run.err, "open *")
	if calls := run.commands.all(); len(calls) != 0 {
		t.Errorf("commands ran: %q", calls)
	}
}

// A valid zone replaces the previous one, keeps it as .bak, regenerates the
// include list and reloads named.
func TestWriteZoneReplacesTheZoneAndReloads(t *testing.T) {
	zoneDir, include := zoneHost(t)
	zonePath := filepath.Join(zoneDir, "example.com.zone")
	previous := "@ IN SOA x. y. (\n    2000010100  ; serial\n)\n"
	if err := os.WriteFile(zonePath, []byte(previous), 0o640); err != nil {
		t.Fatal(err)
	}
	run := runWriteZone(t, nil, nil, nil, zoneDir)
	assertErrText(t, run.err, "")

	want := []string{
		"named-checkzone example.com " + zonePath + ".tmp",
		"chown named:named " + zonePath,
		"restorecon " + zonePath,
		"named-checkconf " + include + ".tmp",
		"restorecon " + include,
		"rndc reload",
	}
	if got := run.commands.all(); !reflect.DeepEqual(got, want) {
		t.Errorf("commands =\n%q\nwant\n%q", got, want)
	}
	assertFileHolds(t, zonePath+".bak", previous)
	assertZoneFile(t, zonePath)
	assertFileHolds(t, include, "// Automatically generated by Servika\n"+zoneIncludeStatement("example.com", false))
}

func assertFileHolds(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("%s =\n%s\nwant\n%s", path, got, want)
	}
}

// assertZoneFile checks the written zone carries today's serial, the configured
// primary nameserver and the record.
func assertZoneFile(t *testing.T, path string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	today := time.Now().UTC().Format("20060102") + "00"
	for _, fragment := range []string{today + "  ; serial", "SOA ns1.host.example. admin.example.com.", "@\t3600\tIN\tA\t192.0.2.10"} {
		if !strings.Contains(string(body), fragment) {
			t.Errorf("the zone lacks %q:\n%s", fragment, body)
		}
	}
}

// A reload falls back from rndc to systemctl, and restarts named only when its
// configuration checks out.
func TestReloadNamedFallsBackInOrder(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fail  map[string]string
		lines []string
	}{
		{name: "rndc answers", lines: []string{"rndc reload"}},
		{name: "systemctl reloads", fail: map[string]string{"rndc reload": ""},
			lines: []string{"rndc reload", "systemctl reload named"}},
		{name: "a configuration that does not check out",
			fail:  map[string]string{"rndc reload": "", "systemctl reload named": "", "named-checkconf": ""},
			lines: []string{"rndc reload", "systemctl reload named", "named-checkconf"}},
		{name: "a restart", fail: map[string]string{"rndc reload": "", "systemctl reload named": ""},
			lines: []string{"rndc reload", "systemctl reload named", "named-checkconf", "systemctl restart named"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			commands := withZoneCommands(t, failLines(tc.fail))
			reloadNamed()
			if got := commands.all(); !reflect.DeepEqual(got, tc.lines) {
				t.Errorf("commands = %q, want %q", got, tc.lines)
			}
		})
	}
}

const (
	glueLookup = "SELECT value FROM dns_records WHERE domain_id=? AND name=? AND type='A' LIMIT 1"
	glueInsert = "VALUES(?,?, 'A', ?, 3600, 0, 1)"
	glueUpdate = "UPDATE dns_records SET value=? WHERE domain_id=? AND name=? AND type='A'"
	glueStale  = "AND name IN ('ns1','ns2')"
	glueDelete = "DELETE FROM dns_records WHERE domain_id=? AND type='A' AND name=?"
)

type glueCase struct {
	name      string
	ns1, ipv4 string
	script    func(s *sqlScript)
	changed   bool
	wantErr   error
	writes    []sqlScriptExec
}

func TestSyncGlueRecordsKeepsInZoneNameserversAddressed(t *testing.T) {
	const inZone, outOfZone = "ns1.example.com", "ns1.host.example"
	staleRows := func(s *sqlScript) { s.rows[glueStale] = [][]driver.Value{{"ns1"}, {"ns2"}} }
	cases := []glueCase{
		{name: "an in-zone nameserver with no address", ns1: inZone, wantErr: ErrGlueAddressMissing},
		{name: "a missing glue record", ns1: inZone, ipv4: "192.0.2.10", changed: true,
			script: func(s *sqlScript) { s.rows[glueLookup] = nil },
			writes: []sqlScriptExec{{query: glueInsert, args: []driver.Value{int64(7), "ns1", "192.0.2.10"}}}},
		{name: "a glue record at an old address", ns1: inZone, ipv4: "192.0.2.10", changed: true,
			script: func(s *sqlScript) { s.rows[glueLookup] = [][]driver.Value{{"192.0.2.99"}} },
			writes: []sqlScriptExec{{query: glueUpdate, args: []driver.Value{"192.0.2.10", int64(7), "ns1"}}}},
		{name: "a glue record that is current", ns1: inZone, ipv4: "192.0.2.10"},
		{name: "a glue lookup that fails", ns1: inZone, ipv4: "192.0.2.10",
			script: func(s *sqlScript) { s.fail[glueLookup] = errScripted }, wantErr: errScripted},
		{name: "a glue insert that fails", ns1: inZone, ipv4: "192.0.2.10",
			script:  func(s *sqlScript) { s.rows[glueLookup] = nil; s.fail[glueInsert] = errScripted },
			wantErr: errScripted, writes: []sqlScriptExec{{query: glueInsert, args: []driver.Value{int64(7), "ns1", "192.0.2.10"}}}},
		{name: "a glue update that fails", ns1: inZone, ipv4: "192.0.2.10",
			script: func(s *sqlScript) {
				s.rows[glueLookup] = [][]driver.Value{{"192.0.2.99"}}
				s.fail[glueUpdate] = errScripted
			},
			wantErr: errScripted, writes: []sqlScriptExec{{query: glueUpdate, args: []driver.Value{"192.0.2.10", int64(7), "ns1"}}}},
		{name: "vanity records left behind by an out-of-zone pair", ns1: outOfZone, changed: true, script: staleRows,
			writes: []sqlScriptExec{
				{query: glueDelete, args: []driver.Value{int64(7), "ns1"}},
				{query: glueDelete, args: []driver.Value{int64(7), "ns2"}},
			}},
		{name: "a vanity lookup that fails", ns1: outOfZone,
			script: func(s *sqlScript) { s.fail[glueStale] = errScripted }, wantErr: errScripted},
		{name: "a vanity row that cannot be read", ns1: outOfZone,
			script: func(s *sqlScript) { s.rows[glueStale] = [][]driver.Value{{nil}} }, wantErr: errAny},
		{name: "a vanity result set that ends in an error", ns1: outOfZone,
			script: func(s *sqlScript) { s.endWith[glueStale] = errScripted }, wantErr: errScripted},
		{name: "a vanity delete that fails", ns1: outOfZone,
			script:  func(s *sqlScript) { staleRows(s); s.fail[glueDelete] = errScripted },
			wantErr: errScripted, writes: []sqlScriptExec{{query: glueDelete, args: []driver.Value{int64(7), "ns1"}}}},
		{name: "a nameserver that is the zone itself", ns1: "example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := newScript()
			script.rows[glueLookup] = [][]driver.Value{{"192.0.2.10"}}
			script.rows[glueStale] = nil
			if tc.script != nil {
				tc.script(script)
			}
			changed, err := SyncGlueRecords(context.Background(), scriptDB(t, script), 7, "example.com", tc.ipv4, tc.ns1, "ns2.host.example")
			assertChangedAndErr(t, changed, err, tc.changed, tc.wantErr)
			assertWrites(t, script, tc.writes)
		})
	}
}

// errAny stands for an error whose text a test does not pin.
var errAny = errors.New("any error")

func assertChangedAndErr(t *testing.T, changed bool, err error, wantChanged bool, wantErr error) {
	t.Helper()
	if changed != wantChanged {
		t.Errorf("changed = %v, want %v", changed, wantChanged)
	}
	switch {
	case wantErr == errAny:
		if err == nil {
			t.Error("err = nil, want an error")
		}
	case !errors.Is(err, wantErr):
		t.Errorf("err = %v, want %v", err, wantErr)
	}
}

// assertWrites checks every statement the script recorded, in order, by the
// fragment each one holds and its arguments.
func assertWrites(t *testing.T, script *sqlScript, want []sqlScriptExec) {
	t.Helper()
	script.mu.Lock()
	got := append([]sqlScriptExec(nil), script.execs...)
	script.mu.Unlock()
	if len(got) != len(want) {
		t.Fatalf("%d statements ran, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if !strings.Contains(got[i].query, want[i].query) || !reflect.DeepEqual(got[i].args, want[i].args) {
			t.Errorf("statement %d = %q %v, want %q %v", i, got[i].query, got[i].args, want[i].query, want[i].args)
		}
	}
}

const (
	nsLookup  = "SELECT value FROM dns_records WHERE domain_id=? AND type='NS' AND name='@'"
	soaLookup = "SELECT primary_ns FROM dns_soa WHERE domain_id=?"
	ipLookup  = "SELECT ipv4 FROM domains WHERE id=?"
	nsDelete  = "DELETE FROM dns_records WHERE domain_id=? AND type='NS' AND name='@'"
	nsInsert  = "VALUES(?, '@', 'NS', ?, 86400, 0, 1)"
	soaUpdate = "UPDATE dns_soa SET primary_ns=? WHERE domain_id=?"
)

// nameserverScript answers for a domain whose NS records and SOA already name
// the shared pair.
func nameserverScript() *sqlScript {
	s := newScript()
	s.rows[nsLookup] = [][]driver.Value{{"NS1.HOST.EXAMPLE."}, {"ns2.host.example"}}
	s.rows[soaLookup] = [][]driver.Value{{"ns1.host.example."}}
	s.rows[ipLookup] = [][]driver.Value{{"192.0.2.10"}}
	s.rows[glueStale] = nil
	return s
}

func TestSyncNameserverRecordsMovesAZoneOntoThePair(t *testing.T) {
	newPair := []sqlScriptExec{
		{query: nsDelete, args: []driver.Value{int64(7)}},
		{query: nsInsert, args: []driver.Value{int64(7), "ns1.host.example"}},
		{query: nsInsert, args: []driver.Value{int64(7), "ns2.host.example"}},
	}
	oneRecord := func(s *sqlScript) { s.rows[nsLookup] = [][]driver.Value{{"ns1.host.example"}} }
	cases := []glueCase{
		{name: "records that cannot be queried", script: func(s *sqlScript) { s.fail[nsLookup] = errScripted }, wantErr: errScripted},
		{name: "a record that cannot be read", script: func(s *sqlScript) { s.rows[nsLookup] = [][]driver.Value{{nil}} }, wantErr: errAny},
		{name: "a result set that ends in an error", script: func(s *sqlScript) { s.endWith[nsLookup] = errScripted }, wantErr: errScripted},
		{name: "an SOA that cannot be read", script: func(s *sqlScript) { s.fail[soaLookup] = errScripted }, wantErr: errScripted},
		{name: "an address that cannot be read", script: func(s *sqlScript) { s.fail[ipLookup] = errScripted }, wantErr: errScripted},
		{name: "glue that cannot be settled", script: func(s *sqlScript) { s.fail[glueStale] = errScripted }, wantErr: errScripted},
		{name: "a zone that already matches"},
		{name: "a zone with no SOA row", script: func(s *sqlScript) { s.rows[soaLookup] = nil }},
		{name: "a wrong NS set", script: oneRecord, changed: true, writes: newPair},
		{name: "an NS record from somewhere else", changed: true, writes: newPair,
			script: func(s *sqlScript) {
				s.rows[nsLookup] = [][]driver.Value{{"ns1.host.example"}, {"ns9.old.example"}}
			}},
		{name: "an NS delete that fails", script: func(s *sqlScript) { oneRecord(s); s.fail[nsDelete] = errScripted },
			wantErr: errScripted, writes: newPair[:1]},
		{name: "an NS insert that fails", script: func(s *sqlScript) { oneRecord(s); s.fail[nsInsert] = errScripted },
			wantErr: errScripted, writes: newPair[:2]},
		{name: "a stale SOA", script: func(s *sqlScript) { s.rows[soaLookup] = [][]driver.Value{{"ns9.old.example"}} },
			changed: true, writes: []sqlScriptExec{{query: soaUpdate, args: []driver.Value{"ns1.host.example", int64(7)}}}},
		{name: "an SOA update that fails",
			script: func(s *sqlScript) {
				s.rows[soaLookup] = [][]driver.Value{{"ns9.old.example"}}
				s.fail[soaUpdate] = errScripted
			},
			wantErr: errScripted, writes: []sqlScriptExec{{query: soaUpdate, args: []driver.Value{"ns1.host.example", int64(7)}}}},
		{name: "only the glue changed", script: func(s *sqlScript) { s.rows[glueStale] = [][]driver.Value{{"ns1"}} },
			changed: true, writes: []sqlScriptExec{{query: glueDelete, args: []driver.Value{int64(7), "ns1"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := nameserverScript()
			if tc.script != nil {
				tc.script(script)
			}
			changed, err := syncNameserverRecords(context.Background(), scriptDB(t, script), 7, "example.com", "ns1.host.example", "ns2.host.example")
			assertChangedAndErr(t, changed, err, tc.changed, tc.wantErr)
			assertWrites(t, script, tc.writes)
		})
	}
}
