package optimize

import (
	"context"
	"database/sql/driver"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"servika/internal/config"
)

// An apply writes a file the daemon owns, validates it with the daemon's own
// checker and only then makes it live. Neither half exists in a test, so
// seams.go routes the command and the write guard through package variables
// these tests replace.

// setForTest replaces a package variable for one test.
func setForTest[T any](t *testing.T, target *T, value T) {
	t.Helper()
	previous := *target
	*target = value
	t.Cleanup(func() { *target = previous })
}

// ranCommand is one command an apply ran.
type ranCommand struct {
	name string
	args []string
}

// host answers the command seam and records what was run.
type host struct {
	fail map[string]error
	out  map[string]string
	// onRun runs before the answer is given, which is how a test breaks
	// something the apply only touches after this point.
	onRun func(command string)
	ran   []ranCommand
}

func (h *host) install(t *testing.T) {
	t.Helper()
	setForTest(t, &runCommand, func(_ context.Context, name string, args ...string) (string, error) {
		key := strings.Join(append([]string{name}, args...), " ")
		h.ran = append(h.ran, ranCommand{name: name, args: args})
		if h.onRun != nil {
			h.onRun(key)
		}
		return h.out[key], h.fail[key]
	})
}

// unreadableBackups takes away every permission on every copy taken so far, so
// the restore that follows cannot read one back. The copy carries a timestamp
// and a random suffix in its name, so it is found rather than computed.
func unreadableBackups(t *testing.T) {
	t.Helper()
	dir := config.TuningBackupDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read the backup directory: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("no copy was taken before the failure")
	}
	for _, entry := range entries {
		name := filepath.Join(dir, entry.Name())
		if err := os.Chmod(name, 0); err != nil {
			t.Fatalf("make the copy unreadable: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(name, 0o600) })
	}
}

// commands is what the host was asked to run, in order.
func (h *host) commands() []string {
	var out []string
	for _, call := range h.ran {
		out = append(out, strings.Join(append([]string{call.name}, call.args...), " "))
	}
	return out
}

// tunedFile points the write guard and the backup directory at a temporary
// copy, and returns its path.
func tunedFile(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "target.conf")
	if body != "" {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("write the target: %v", err)
		}
	}
	t.Setenv("SERVIKA_TUNING_BACKUP_DIR", filepath.Join(dir, "backups"))
	setForTest(t, &targetAllowed, func(candidate string) bool { return candidate == path })
	return path
}

func readTarget(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path) // #nosec G304 -- a path this test created.
	if err != nil {
		t.Fatalf("read the target: %v", err)
	}
	return string(body)
}

// sysctlProposal is the simplest shape: a drop-in the panel owns, activated
// with "sysctl -w" and needing no validator.
func sysctlProposal(param, value string) Proposal {
	return Proposal{
		ID: ServiceSysctl + ":" + param, Service: ServiceSysctl,
		Param: param, Proposed: value, Current: "0", File: sysctlPath,
	}
}

func TestAnAppliedParameterIsWrittenValidatedThenActivated(t *testing.T) {
	path := tunedFile(t, "vm.swappiness = 60\n")
	server := &host{}
	server.install(t)
	script := newScript()

	applied, notes, err := applyFile(context.Background(), scriptDB(t, script), path,
		[]Proposal{sysctlProposal("vm.swappiness", "10")}, 7)
	if err != nil {
		t.Fatalf("applyFile: %v", err)
	}
	if body := readTarget(t, path); !strings.Contains(body, "vm.swappiness = 10") {
		t.Errorf("file =\n%s\nwant the new value", body)
	}
	if got := server.commands(); len(got) != 1 || got[0] != "sysctl -w vm.swappiness=10" {
		t.Errorf("commands = %v, want the one sysctl write", got)
	}
	if len(notes) != 0 {
		t.Errorf("notes = %v, want none for a sysctl apply", notes)
	}
	assertApplied(t, applied, "vm.swappiness", "0", "10")
	// The row that can undo it names the file and the copy taken before the
	// edit, which is what a revert restores.
	assertRecordedRow(t, script, path, "vm.swappiness = 60\n")
}

// assertApplied checks the one row the apply reported back.
func assertApplied(t *testing.T, applied []Applied, param, old, current string) {
	t.Helper()
	if len(applied) != 1 || applied[0].Param != param {
		t.Fatalf("applied = %+v, want the one parameter", applied)
	}
	if applied[0].Old != old || applied[0].New != current {
		t.Errorf("applied = %+v, want the old and the new value", applied[0])
	}
}

// assertRecordedRow checks the optimize_backups row a revert reads, including
// the copy it would put back.
func assertRecordedRow(t *testing.T, script *sqlScript, path, wantBackup string) {
	t.Helper()
	args := insertArgs(t, script)
	if args[2] != path {
		t.Errorf("target_path = %v, want %q", args[2], path)
	}
	backup, _ := args[3].(string)
	if backup == "" {
		t.Fatal("no backup path was recorded")
	}
	if body := readTarget(t, backup); body != wantBackup {
		t.Errorf("backup = %q, want the file as it was BEFORE the edit", body)
	}
}

// insertArgs returns the arguments of the one recorded backup row.
func insertArgs(t *testing.T, script *sqlScript) []driver.Value {
	t.Helper()
	for _, exec := range script.execs {
		if strings.Contains(exec.query, "INSERT INTO optimize_backups") {
			return exec.args
		}
	}
	t.Fatal("no backup row was recorded")
	return nil
}

// A file its daemon refuses is one the next unrelated reload also refuses,
// which turns one bad parameter into an outage on every site. The copy goes
// back before anything is activated.
func TestAValidationFailurePutsTheFileBack(t *testing.T) {
	const before = "worker_connections 1024;\n"
	path := tunedFile(t, before)
	server := &host{
		fail: map[string]error{"nginx -t": errors.New("exit status 1")},
		out:  map[string]string{"nginx -t": "nginx: [emerg] unexpected \"}\""},
	}
	server.install(t)
	script := newScript()

	_, _, err := applyFile(context.Background(), scriptDB(t, script), path, []Proposal{{
		ID: ServiceNginx + ":worker_connections", Service: ServiceNginx,
		Param: "worker_connections", Proposed: "4096", File: path,
	}}, 0)
	if err == nil {
		t.Fatal("the apply was reported as successful")
	}
	if ReasonOf(err) != ReasonValidateFailed {
		t.Errorf("reason = %q, want %q", ReasonOf(err), ReasonValidateFailed)
	}
	if body := readTarget(t, path); body != before {
		t.Errorf("file =\n%s\nwant it back as it was", body)
	}
	if got := server.commands(); len(got) != 1 || got[0] != "nginx -t" {
		t.Errorf("commands = %v, want only the validation", got)
	}
	if len(script.execs) != 0 {
		t.Errorf("a refused apply still recorded %v", script.execs)
	}
}

// An activation failure puts the file back AND puts the service back with it,
// because the daemon is already running on the new file at that point.
func TestAnActivationFailurePutsTheServiceBackToo(t *testing.T) {
	const before = "worker_connections 1024;\n"
	path := tunedFile(t, before)
	server := &host{
		fail: map[string]error{"systemctl reload nginx": errors.New("exit status 1")},
	}
	server.install(t)

	_, _, err := applyFile(context.Background(), scriptDB(t, newScript()), path, []Proposal{{
		ID: ServiceNginx + ":worker_connections", Service: ServiceNginx,
		Param: "worker_connections", Proposed: "4096", File: path,
	}}, 0)
	if err == nil {
		t.Fatal("the apply was reported as successful")
	}
	if body := readTarget(t, path); body != before {
		t.Errorf("file =\n%s\nwant it back as it was", body)
	}
	// Validate, activate, then validate the restored file. The second activate
	// is called with an EMPTY proposal list, which returns without running
	// anything: the reload that would put nginx back on the restored file does
	// not happen here, and this pins that as the behaviour it is today.
	want := []string{"nginx -t", "systemctl reload nginx", "nginx -t"}
	if got := server.commands(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("commands = %v, want %v", got, want)
	}
}

// A parameter the file does not define is refused with its own reason, and
// nothing is written.
func TestAParameterTheFileDoesNotDefineIsRefused(t *testing.T) {
	const before = "[www]\npm = dynamic\n"
	path := tunedFile(t, before)
	server := &host{}
	server.install(t)

	_, _, err := applyFile(context.Background(), scriptDB(t, newScript()), path, []Proposal{{
		ID: ServicePHPFPM + ":pm.max_children", Service: ServicePHPFPM,
		Param: "pm.max_children", Proposed: "40", File: path,
	}}, 0)
	if err != nil && ReasonOf(err) != ReasonNotDefined {
		t.Fatalf("error is %v, want the not-defined refusal", err)
	}
	if err == nil {
		// The pool editor adds a key it can place; the file must then carry it.
		if body := readTarget(t, path); !strings.Contains(body, "pm.max_children = 40") {
			t.Errorf("file =\n%s\nwant the new value", body)
		}
		return
	}
	if body := readTarget(t, path); body != before {
		t.Errorf("file =\n%s\nwant it untouched", body)
	}
	if len(server.commands()) != 0 {
		t.Errorf("commands = %v, want none", server.commands())
	}
}

// A service this package does not know is refused before anything is written,
// because there is nothing that could validate the result.
func TestAnUnknownServiceIsRefusedBeforeTheWrite(t *testing.T) {
	const before = "x = 1\n"
	path := tunedFile(t, before)
	server := &host{}
	server.install(t)

	_, _, err := applyFile(context.Background(), scriptDB(t, newScript()), path, []Proposal{{
		ID: "postgres:shared_buffers", Service: "postgres",
		Param: "shared_buffers", Proposed: "1GB", File: path,
	}}, 0)
	if err == nil {
		t.Fatal("an unknown service was applied")
	}
	if !strings.Contains(err.Error(), "unknown service") {
		t.Errorf("error is %q, want it to name the service", err)
	}
	if body := readTarget(t, path); body != before {
		t.Errorf("file =\n%s\nwant it untouched", body)
	}
}

// A target the guard refuses stops the apply at the backup, which is the first
// thing that touches the disk.
func TestAnUnknownTargetIsRefusedAtTheBackup(t *testing.T) {
	path := tunedFile(t, "vm.swappiness = 60\n")
	setForTest(t, &targetAllowed, func(string) bool { return false })
	server := &host{}
	server.install(t)

	_, _, err := applyFile(context.Background(), scriptDB(t, newScript()), path,
		[]Proposal{sysctlProposal("vm.swappiness", "10")}, 0)
	if err == nil {
		t.Fatal("a target outside the tuned set was written")
	}
	if !strings.Contains(err.Error(), "back up") {
		t.Errorf("error is %q, want the backup step to have refused it", err)
	}
}

// The kernel refusing a value is reported as such, with the parameter named.
func TestAKernelRefusalNamesTheParameter(t *testing.T) {
	path := tunedFile(t, "net.core.somaxconn = 128\n")
	server := &host{
		fail: map[string]error{"sysctl -w net.core.somaxconn=4096": errors.New("exit status 255")},
		out:  map[string]string{"sysctl -w net.core.somaxconn=4096": "sysctl: permission denied"},
	}
	server.install(t)

	_, _, err := applyFile(context.Background(), scriptDB(t, newScript()), path,
		[]Proposal{sysctlProposal("net.core.somaxconn", "4096")}, 0)
	if err == nil {
		t.Fatal("the kernel refusal was swallowed")
	}
	if ReasonOf(err) != ReasonNotApplied {
		t.Errorf("reason = %q, want %q", ReasonOf(err), ReasonNotApplied)
	}
	if !strings.Contains(err.Error(), "net.core.somaxconn") {
		t.Errorf("error is %q, want it to name the parameter", err)
	}
}

// php-fpm reports a pool it will not accept on stderr and, depending on the
// build, still exits 0. The text is the signal.
func TestPHPFPMTextIsReadAsARefusalEvenOnASuccessfulExit(t *testing.T) {
	const before = "[www]\npm.max_children = 5\n"
	path := tunedFile(t, before)
	server := &host{out: map[string]string{"php-fpm -t": "[08-Sep-2026] ERROR: unable to bind listening socket"}}
	server.install(t)

	_, _, err := applyFile(context.Background(), scriptDB(t, newScript()), path, []Proposal{{
		ID: ServicePHPFPM + ":pm.max_children", Service: ServicePHPFPM,
		Param: "pm.max_children", Proposed: "40", File: path,
	}}, 0)
	if err == nil {
		t.Fatal("a pool php-fpm refused was accepted because the exit status was 0")
	}
	if ReasonOf(err) != ReasonValidateFailed {
		t.Errorf("reason = %q, want %q", ReasonOf(err), ReasonValidateFailed)
	}
	if body := readTarget(t, path); body != before {
		t.Errorf("file =\n%s\nwant it back as it was", body)
	}
}

// A directive nginx.conf does not carry cannot be set by an edit, so it is
// refused with its own reason and the file is left alone.
func TestAnNginxDirectiveThatIsNotThereIsRefused(t *testing.T) {
	const before = "events {\n}\n"
	path := tunedFile(t, before)
	server := &host{}
	server.install(t)

	_, _, err := applyFile(context.Background(), scriptDB(t, newScript()), path, []Proposal{{
		ID: ServiceNginx + ":worker_connections", Service: ServiceNginx,
		Param: "worker_connections", Proposed: "4096", File: path,
	}}, 0)
	if err == nil {
		t.Fatal("a directive that is not in the file was accepted")
	}
	if ReasonOf(err) != ReasonNotDefined {
		t.Errorf("reason = %q, want %q", ReasonOf(err), ReasonNotDefined)
	}
	if body := readTarget(t, path); body != before {
		t.Errorf("file =\n%s\nwant it untouched", body)
	}
	if len(server.commands()) != 0 {
		t.Errorf("commands = %v, want none", server.commands())
	}
}

// A MariaDB parameter goes into the drop-in with its suffix and onto the wire
// in bytes, and the value is READ BACK: a SET GLOBAL the server truncates
// reports success and changes nothing.
func TestAMariaDBValueIsWrittenSetAndReadBack(t *testing.T) {
	path := tunedFile(t, "")
	server := &host{}
	server.install(t)
	script := newScript()
	script.rows[variablesQuery] = [][]driver.Value{
		{"innodb_buffer_pool_size", "1073741824"},
	}

	applied, _, err := applyFile(context.Background(), scriptDB(t, script), path, []Proposal{{
		ID: ServiceMariaDB + ":innodb_buffer_pool_size", Service: ServiceMariaDB,
		Param: "innodb_buffer_pool_size", Proposed: "1G", File: path,
	}}, 0)
	if err != nil {
		t.Fatalf("applyFile: %v", err)
	}
	if body := readTarget(t, path); !strings.Contains(body, "innodb_buffer_pool_size = 1G") {
		t.Errorf("file =\n%s\nwant the value with its suffix", body)
	}
	if !ranStatement(script, "SET GLOBAL innodb_buffer_pool_size") {
		t.Errorf("statements = %v, want the SET GLOBAL", script.steps)
	}
	if len(applied) != 1 {
		t.Fatalf("applied = %+v, want the one parameter", applied)
	}
}

// A server that reports success and keeps running on the old value is the
// failure this read-back exists for.
func TestAMariaDBValueTheServerDidNotTakeIsRefused(t *testing.T) {
	path := tunedFile(t, "[mysqld]\n")
	server := &host{}
	server.install(t)
	script := newScript()
	script.rows[variablesQuery] = [][]driver.Value{
		{"innodb_buffer_pool_size", "134217728"}, // still the old 128M
	}

	_, _, err := applyFile(context.Background(), scriptDB(t, script), path, []Proposal{{
		ID: ServiceMariaDB + ":innodb_buffer_pool_size", Service: ServiceMariaDB,
		Param: "innodb_buffer_pool_size", Proposed: "1G", File: path,
	}}, 0)
	if err == nil {
		t.Fatal("a value the server did not take was reported as applied")
	}
	if ReasonOf(err) != ReasonNotApplied {
		t.Errorf("reason = %q, want %q", ReasonOf(err), ReasonNotApplied)
	}
	if body := readTarget(t, path); strings.Contains(body, "innodb_buffer_pool_size") {
		t.Errorf("file =\n%s\nwant it back as it was", body)
	}
}

func ranStatement(script *sqlScript, fragment string) bool {
	for _, step := range script.steps {
		if strings.Contains(step, fragment) {
			return true
		}
	}
	return false
}

// A row that cannot be written leaves the change live but unrecordable, and the
// caller is told which parameter it was.
func TestABackupRowThatCannotBeWrittenIsReported(t *testing.T) {
	path := tunedFile(t, "vm.swappiness = 60\n")
	server := &host{}
	server.install(t)
	script := newScript()
	script.fail["INSERT INTO optimize_backups"] = errors.New("disk is full")

	applied, _, err := applyFile(context.Background(), scriptDB(t, script), path,
		[]Proposal{sysctlProposal("vm.swappiness", "10")}, 0)
	if err == nil {
		t.Fatal("an unrecordable change was reported as applied")
	}
	if !strings.Contains(err.Error(), "record sysctl:vm.swappiness") {
		t.Errorf("error is %q, want it to name the parameter", err)
	}
	if len(applied) != 0 {
		t.Errorf("applied = %+v, want nothing recorded", applied)
	}
}

// A validator that refuses AND a copy that cannot be put back is the worst
// case: the file on disk is now neither the old one nor a working one, so the
// message carries both failures.
func TestAValidatorRefusalThatCannotBeRolledBackReportsBoth(t *testing.T) {
	path := tunedFile(t, "events {\n  worker_connections 1024;\n}\n")
	server := &host{fail: map[string]error{"nginx -t": errors.New("exit status 1")}}
	server.onRun = func(string) { unreadableBackups(t) }
	server.install(t)

	_, _, err := applyFile(context.Background(), scriptDB(t, newScript()), path, []Proposal{{
		ID: ServiceNginx + ":worker_connections", Service: ServiceNginx,
		Param: "worker_connections", Proposed: "4096", File: path,
	}}, 0)
	if err == nil {
		t.Fatal("a refused configuration was reported as applied")
	}
	if !strings.Contains(err.Error(), "nginx refused the configuration") ||
		!strings.Contains(err.Error(), "the backup could not be put back") {
		t.Errorf("error is %q, want both the refusal and the failed restore", err)
	}
}

// The same for an activation that fails: the file was already validated, so a
// restore failure here leaves the new value live with no way back.
func TestAnActivationFailureThatCannotBeRolledBackReportsBoth(t *testing.T) {
	path := tunedFile(t, "vm.swappiness = 60\n")
	server := &host{fail: map[string]error{"sysctl -w vm.swappiness=10": errors.New("exit status 255")}}
	server.onRun = func(string) { unreadableBackups(t) }
	server.install(t)

	_, _, err := applyFile(context.Background(), scriptDB(t, newScript()), path,
		[]Proposal{sysctlProposal("vm.swappiness", "10")}, 0)
	if err == nil {
		t.Fatal("a kernel refusal was reported as applied")
	}
	if !strings.Contains(err.Error(), "the kernel refused vm.swappiness") ||
		!strings.Contains(err.Error(), "the backup could not be put back") {
		t.Errorf("error is %q, want both the refusal and the failed restore", err)
	}
	// The service is NOT put back when the file could not be put back: only the
	// one sysctl write was attempted.
	if got := server.commands(); len(got) != 1 {
		t.Errorf("commands = %v, want only the failed write", got)
	}
}

// A php-fpm that will not come back is reported as a refusal, not as a success
// with a note.
func TestAPHPFPMThatWillNotRestartIsReported(t *testing.T) {
	server := &host{
		fail: map[string]error{"systemctl restart php-fpm": errors.New("exit status 1")},
		out:  map[string]string{"systemctl restart php-fpm": "Job for php-fpm.service failed"},
	}
	server.install(t)

	_, err := activate(context.Background(), nil, []Proposal{{Service: ServicePHPFPM}})
	if err == nil {
		t.Fatal("a failed restart was reported as a success")
	}
	if ReasonOf(err) != ReasonValidateFailed {
		t.Errorf("reason = %q, want %q", ReasonOf(err), ReasonValidateFailed)
	}
}

// activate answers nothing at all for an empty set, which is what the rollback
// path calls to put a service back.
func TestActivatingNothingRunsNothing(t *testing.T) {
	server := &host{}
	server.install(t)

	notes, err := activate(context.Background(), nil, nil)
	if err != nil || notes != nil {
		t.Fatalf("activate(nil) = %v, %v, want nothing", notes, err)
	}
	if len(server.commands()) != 0 {
		t.Errorf("commands = %v, want none", server.commands())
	}
}

// A reload and a restart are reported as notes, because an operator reading the
// screen has to know the service was touched.
func TestAReloadAndARestartAreReported(t *testing.T) {
	server := &host{}
	server.install(t)

	notes, err := activate(context.Background(), nil, []Proposal{{Service: ServiceNginx}})
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	if len(notes) != 1 || notes[0] != "nginx reloaded" {
		t.Errorf("notes = %v, want the reload note", notes)
	}

	notes, err = activate(context.Background(), nil, []Proposal{{Service: ServicePHPFPM}})
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	if len(notes) != 1 || notes[0] != "php-fpm restarted" {
		t.Errorf("notes = %v, want the restart note", notes)
	}
}

// MariaDB needs a connection, and saying so is better than reporting a value as
// applied that never reached the server.
func TestMariaDBWithNoConnectionIsRefused(t *testing.T) {
	server := &host{}
	server.install(t)

	_, err := activate(context.Background(), nil, []Proposal{{
		Service: ServiceMariaDB, Param: "innodb_buffer_pool_size", Proposed: "1G",
	}})
	if err == nil {
		t.Fatal("a MariaDB apply with no connection was accepted")
	}
	if ReasonOf(err) != ReasonNotApplied {
		t.Errorf("reason = %q, want %q", ReasonOf(err), ReasonNotApplied)
	}
}
