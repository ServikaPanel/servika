package optimize

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"servika/internal/config"
)

// Refusal reasons, returned beside the English message because the screen
// renders twelve languages.
const (
	ReasonNothingChosen  = "optimize_nothing_chosen"
	ReasonUnknownID      = "optimize_unknown_parameter"
	ReasonNotMeasured    = "optimize_host_not_measured"
	ReasonNotDefined     = "optimize_directive_not_defined"
	ReasonValidateFailed = "optimize_configuration_refused"
	ReasonNotApplied     = "optimize_value_not_applied"
	ReasonUnknownBackup  = "optimize_backup_not_found"
	ReasonAlreadyRevert  = "optimize_already_reverted"
)

// Refusal carries a reason code beside the message.
type Refusal struct {
	Reason  string
	Message string
}

func (r *Refusal) Error() string { return r.Message }

func refuse(reason, format string, args ...any) error {
	return &Refusal{Reason: reason, Message: fmt.Sprintf(format, args...)}
}

// ReasonOf returns the stable reason code of a refusal, or "" for anything else.
func ReasonOf(err error) string {
	var refusal *Refusal
	if errors.As(err, &refusal) {
		return refusal.Reason
	}
	return ""
}

const commandTimeout = 90 * time.Second

// run executes a fixed binary with separate arguments. Nothing a request
// carries reaches argv here: every command is built from the specs table.
func run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	// #nosec G204 -- fixed binary, arguments built from the compile-time specs
	// table and validated paths; no request input reaches argv.
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// knownTarget reports whether a path is one of the files this package tunes.
//
// Every write here goes through it. The paths all come from the compile-time
// specs table today, so nothing can currently fail this; the check is what
// makes that a PROPERTY of the package rather than a fact about its current
// callers. A revert reads its path out of a database row, and a row is exactly
// the kind of thing that outlives the code that wrote it.
func knownTarget(path string) bool {
	// The sysctl drop-in was renamed to sort last (see propose.go). A revert of a
	// row written under the OLD name must still restore it, and that path is no
	// longer in the specs table, so it is accepted here for the same reason the
	// check exists: a row outlives the code that wrote it.
	if path == sysctlOldPath {
		return true
	}
	for _, item := range specs {
		if item.file == path {
			return true
		}
	}
	return false
}

// backupName turns a target path into a flat file name with no separator in it,
// so the result can only ever land directly in the backup directory.
//
// The timestamp is for a human reading the directory; the RANDOM suffix is what
// actually makes the name unique. A clock is not enough: two calls inside one
// tick of the platform's nanosecond resolution produce the same name, and the
// second apply would then overwrite the copy the first one needs to undo
// itself. That is not a rare-enough failure to accept, because the copy is the
// only thing standing between a bad parameter and a hand-edited server.
func backupName(path string) string {
	flat := strings.ReplaceAll(strings.TrimPrefix(path, "/"), "/", "_")
	flat = strings.ReplaceAll(flat, string(filepath.Separator), "_")
	var unique [8]byte
	// crypto/rand.Read is documented never to return an error and to always
	// fill its buffer, crashing the program irrecoverably if the operating
	// system fails it, so there is no error path to add here.
	_, _ = rand.Read(unique[:])
	return fmt.Sprintf("%s.%s.%s.bak", flat,
		time.Now().UTC().Format("20060102-150405"), hex.EncodeToString(unique[:]))
}

// backupFile copies a file before it is edited and returns the copy's path.
//
// The copy is what a revert restores, so it is taken BEFORE the edit and its
// path is recorded with the row. Reconstructing the old content from the row's
// old_value would only put back the parameters the panel knows about, losing
// whatever else the operator had in the same file.
//
// A file that does not exist yet gets no backup and an empty path, and the
// revert of such a row is a DELETION. That case is only reachable for the
// panel's own drop-ins, which the panel creates.
func backupFile(path string) (string, error) {
	if !knownTarget(path) {
		return "", fmt.Errorf("%s is not a file this package tunes", path)
	}
	content, err := os.ReadFile(path) // #nosec G304 -- knownTarget restricted path to the compile-time specs table.
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	dir := config.TuningBackupDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := backupName(path)
	if name != filepath.Base(name) {
		return "", fmt.Errorf("refusing to write a backup named %q", name)
	}
	backup := filepath.Join(dir, name)
	// #nosec G703 -- name carries no separator (asserted above) and dir is the
	// panel's own backup directory, so the result cannot leave it.
	if err := os.WriteFile(backup, content, 0o600); err != nil {
		return "", err
	}
	return backup, nil
}

// writeFileAs writes content preserving the mode of the file it replaces.
func writeFileAs(path, content string) error {
	if !knownTarget(path) {
		return fmt.Errorf("%s is not a file this package tunes", path)
	}
	mode := os.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	// #nosec G306 G703 -- knownTarget restricted path to the compile-time specs
	// table; a configuration file its daemon must read, whose existing mode is
	// preserved, and no secret is written here.
	return os.WriteFile(path, []byte(content), mode)
}

// restore puts a backup back, or removes the file when there was none.
func restore(path, backup string) error {
	if !knownTarget(path) {
		return fmt.Errorf("%s is not a file this package tunes", path)
	}
	if backup == "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	content, err := os.ReadFile(backup) // #nosec G304 -- path produced by backupFile under the panel's own backup directory.
	if err != nil {
		return err
	}
	return writeFileAs(path, string(content))
}

// Applied is one parameter that was written, with the row that can undo it.
type Applied struct {
	ID       string `json:"id"`
	Service  string `json:"service"`
	Param    string `json:"param"`
	Old      string `json:"old"`
	New      string `json:"new"`
	BackupID int64  `json:"backup_id"`
}

// Result is what an apply did.
type Result struct {
	Applied []Applied `json:"applied"`
	// Notes carry anything the operator should know that did not stop the
	// apply: a service that was reloaded, a value that needs a restart.
	Notes []string `json:"notes"`
}

// Apply writes the chosen proposals, validates each file with the service's own
// checker, and makes the values live.
//
// The order per file is COPY, edit, validate, activate. A validation failure
// puts the copy back before anything is activated, because a file that its
// daemon refuses is one the next unrelated reload will also refuse, which turns
// one bad parameter into an outage on every site.
func Apply(ctx context.Context, db *sql.DB, chosen []string, actorUID int64) (Result, error) {
	var result Result
	if len(chosen) == 0 {
		return result, refuse(ReasonNothingChosen, "no parameter was chosen")
	}

	facts := Measure()
	if facts.MemoryMB <= 0 || facts.CPUs <= 0 {
		return result, refuse(ReasonNotMeasured, "the host's memory and CPU count could not be read")
	}
	current, _ := Current(ctx, db)
	proposals := Expand(Compute(facts, current), chosen)
	if len(proposals) == 0 {
		return result, refuse(ReasonUnknownID, "none of the chosen parameters is currently proposed")
	}

	// One file may carry several parameters, and they are written together.
	byFile := map[string][]Proposal{}
	var order []string
	for _, proposal := range proposals {
		if _, seen := byFile[proposal.File]; !seen {
			order = append(order, proposal.File)
		}
		byFile[proposal.File] = append(byFile[proposal.File], proposal)
	}

	for _, path := range order {
		applied, notes, err := applyFile(ctx, db, path, byFile[path], actorUID)
		result.Applied = append(result.Applied, applied...)
		result.Notes = append(result.Notes, notes...)
		if err != nil {
			return result, err
		}
	}
	return result, nil
}

// applyFile writes every parameter that lives in one file.
func applyFile(ctx context.Context, db *sql.DB, path string, proposals []Proposal, actorUID int64) ([]Applied, []string, error) {
	existing, err := os.ReadFile(path) // #nosec G304 -- path comes from the compile-time specs table.
	if err != nil && !os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("read %s: %w", path, err)
	}

	values := map[string]string{}
	for _, proposal := range proposals {
		values[proposal.Param] = proposal.Proposed
	}

	var edited string
	switch proposals[0].Service {
	case ServiceNginx:
		edited = string(existing)
		for _, proposal := range proposals {
			edited, err = SetNginxDirective(edited, proposal.Param, proposal.Proposed)
			if err != nil {
				return nil, nil, refuse(ReasonNotDefined, "%s: %v", path, err)
			}
		}
	case ServicePHPFPM:
		edited, err = SetPoolValues(string(existing), values)
		if err != nil {
			return nil, nil, refuse(ReasonNotDefined, "%s: %v", path, err)
		}
	case ServiceMariaDB:
		edited = MergeDropIn(string(existing), "[mysqld]", values)
	case ServiceSysctl:
		edited = MergeDropIn(string(existing), "", values)
	default:
		return nil, nil, fmt.Errorf("unknown service %q", proposals[0].Service)
	}

	backup, err := backupFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("back up %s: %w", path, err)
	}
	if err := writeFileAs(path, edited); err != nil {
		return nil, nil, fmt.Errorf("write %s: %w", path, err)
	}

	if err := validate(ctx, proposals[0].Service); err != nil {
		if restoreErr := restore(path, backup); restoreErr != nil {
			return nil, nil, fmt.Errorf("%w (and the backup could not be put back: %v)", err, restoreErr)
		}
		return nil, nil, err
	}

	notes, err := activate(ctx, db, proposals)
	if err != nil {
		if restoreErr := restore(path, backup); restoreErr != nil {
			return nil, nil, fmt.Errorf("%w (and the backup could not be put back: %v)", err, restoreErr)
		}
		// The file is back; put the service back with it.
		_ = validate(ctx, proposals[0].Service)
		_, _ = activate(ctx, db, nil)
		return nil, nil, err
	}

	var applied []Applied
	for _, proposal := range proposals {
		id, err := recordBackup(ctx, db, proposal, path, backup, actorUID)
		if err != nil {
			return applied, notes, fmt.Errorf("record %s: %w", proposal.ID, err)
		}
		applied = append(applied, Applied{
			ID: proposal.ID, Service: proposal.Service, Param: proposal.Param,
			Old: proposal.Current, New: proposal.Proposed, BackupID: id,
		})
	}

	// The sysctl drop-in was renamed to sort last. Remove the pre-rename file so
	// one setting never lives in two drop-ins. It runs only AFTER the new file is
	// fully written, validated, activated and recorded, so a rolled-back apply
	// never loses the old values first; a pre-rename row stays revertable because
	// its restore recreates the file from the backup copy, which is untouched.
	if proposals[0].Service == ServiceSysctl && path == sysctlPath {
		_ = os.Remove(sysctlOldPath)
	}
	return applied, notes, nil
}

// validate asks the service's own checker whether the file it now has is one it
// will accept. php-fpm and nginx both refuse at the next START rather than at
// the write, so without this the screen would report success and the service
// would not come back.
func validate(ctx context.Context, service string) error {
	switch service {
	case ServiceNginx:
		if out, err := run(ctx, "nginx", "-t"); err != nil {
			return refuse(ReasonValidateFailed, "nginx refused the configuration: %s", tail(out))
		}
	case ServicePHPFPM:
		out, err := run(ctx, "php-fpm", "-t")
		// php-fpm reports a pool it will not accept on stderr and, depending on
		// the build, still exits 0. The text is the signal.
		if err != nil || strings.Contains(out, "ERROR") || strings.Contains(out, "ALERT") {
			return refuse(ReasonValidateFailed, "php-fpm refused the pool: %s", tail(out))
		}
	}
	// The MariaDB drop-in and the sysctl drop-in are proved by activation
	// itself: SET GLOBAL and "sysctl -w" both report a value the kernel or the
	// server actually took, which is a stronger check than a parser.
	return nil
}

// activate makes the written values live.
func activate(ctx context.Context, db *sql.DB, proposals []Proposal) ([]string, error) {
	if len(proposals) == 0 {
		return nil, nil
	}
	var notes []string
	switch proposals[0].Service {
	case ServiceNginx:
		if out, err := run(ctx, "systemctl", "reload", "nginx"); err != nil {
			return nil, refuse(ReasonValidateFailed, "nginx would not reload: %s", tail(out))
		}
		notes = append(notes, "nginx reloaded")
	case ServicePHPFPM:
		if out, err := run(ctx, "systemctl", "restart", "php-fpm"); err != nil {
			return nil, refuse(ReasonValidateFailed, "php-fpm would not restart: %s", tail(out))
		}
		notes = append(notes, "php-fpm restarted")
	case ServiceSysctl:
		for _, proposal := range proposals {
			if out, err := run(ctx, "sysctl", "-w", proposal.Param+"="+proposal.Proposed); err != nil {
				return nil, refuse(ReasonNotApplied, "the kernel refused %s: %s", proposal.Param, tail(out))
			}
		}
	case ServiceMariaDB:
		if err := applyMariaDB(ctx, db, proposals); err != nil {
			return nil, err
		}
	}
	return notes, nil
}

// applyMariaDB sets each value on the running server and READS IT BACK.
//
// The read-back is the whole point. Measured on 10.11: a SET GLOBAL for a
// buffer pool larger than the server can allocate returns SUCCESS, changes
// nothing, and reports the refusal only as
//
//	Warning 1292  Truncated incorrect innodb_buffer_pool_size value: '268435456'
//
// A caller that trusted the exit status would write a row saying the parameter
// was applied, and the screen would show the new value while the server ran on
// the old one. That is worse than a failure, because nothing later contradicts
// it.
//
// The drop-in is already written when this runs, so a value that takes effect
// now also survives a restart. MariaDB is never RESTARTED here: internal/dbremote
// is the one place in the panel that does that, because bind-address has no
// dynamic equivalent. Every parameter offered on this screen does.
func applyMariaDB(ctx context.Context, db *sql.DB, proposals []Proposal) error {
	if db == nil {
		return refuse(ReasonNotApplied, "no database connection")
	}
	for _, proposal := range proposals {
		// The FILE takes "4096M" and SET GLOBAL does NOT: measured on 10.11,
		//
		//	SET GLOBAL innodb_log_file_size = '128M'
		//	ERROR 1232 (42000): Incorrect argument type to variable
		//
		// so the same value goes into the drop-in with its suffix, where it is
		// readable, and onto the wire in bytes, where it is accepted.
		numeric, ok := sizeValue(proposal.Proposed)
		if !ok {
			return refuse(ReasonNotApplied, "%s is not a number this can set: %q", proposal.Param, proposal.Proposed)
		}
		// The name is a compile-time constant from specs, never request input;
		// the value is bound.
		// #nosec G202 -- interpolated identifier comes from the specs table.
		statement := "SET GLOBAL " + proposal.Param + " = ?"
		if _, err := db.ExecContext(ctx, statement, numeric); err != nil {
			return refuse(ReasonNotApplied, "MariaDB refused %s: %v", proposal.Param, err)
		}
	}

	after, err := readMariaDBValues(ctx, db)
	if err != nil {
		return fmt.Errorf("read back MariaDB variables: %w", err)
	}
	for _, proposal := range proposals {
		if !sameValue(after[proposal.Param], proposal.Proposed) {
			return refuse(ReasonNotApplied,
				"MariaDB reported success for %s but is still running on %q rather than %q",
				proposal.Param, after[proposal.Param], proposal.Proposed)
		}
	}
	return nil
}

func recordBackup(ctx context.Context, db *sql.DB, proposal Proposal, path, backup string, actorUID int64) (int64, error) {
	var actor any
	if actorUID > 0 {
		actor = actorUID
	}
	result, err := db.ExecContext(ctx,
		`INSERT INTO optimize_backups
		   (service, param, target_path, backup_path, old_value, new_value, actor_uid)
		 VALUES (?,?,?,?,?,?,?)`,
		proposal.Service, proposal.Param, path, backup,
		proposal.Current, proposal.Proposed, actor)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func tail(out string) string {
	out = strings.TrimSpace(out)
	lines := strings.Split(out, "\n")
	if len(lines) > 4 {
		lines = lines[len(lines)-4:]
	}
	return strings.Join(lines, "; ")
}
