package panelport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The files that hold the two ports.
//
// Each is overridable so a test can point the package somewhere harmless, and
// each has the production default the installer actually writes.
// Each is a FUNCTION rather than a package variable read once at init, which
// is the idiom internal/config already uses. A value fixed at init cannot be
// retargeted, and the one thing that has to be exercised outside a live panel
// is exactly the code that rewrites these files.
func envPath() string { return envOr("SERVIKA_ENV_FILE", "/etc/servika/env") }

func panelVhostPath() string { return envOr("SERVIKA_PANEL_VHOST", "/etc/nginx/conf.d/_panel.conf") }

// The custom panel domain vhost is OPTIONAL: it exists only when an operator
// set a panel hostname. It carries its own copy of both ports, so a change that
// skipped it would leave the custom domain proxying to a port nothing answers
// on, and only for the operator who bothered to set one up.
func panelDomainVhostPath() string {
	return envOr("SERVIKA_PANEL_DOMAIN_VHOST", "/etc/nginx/conf.d/_panel_domain.conf")
}

func backupDir() string {
	return envOr("SERVIKA_PANEL_PORT_BACKUP_DIR", "/var/lib/servika/panel-port-backups")
}

func outcomePath() string {
	return envOr("SERVIKA_PANEL_PORT_OUTCOME", "/var/lib/servika/panel-port-outcome.json")
}

func helperPath() string {
	return envOr("SERVIKA_PANEL_PORT_HELPER", "/usr/local/sbin/servika-panel-port")
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

// keptBackups is how many generations of each file survive.
//
// Five, because the interesting case is not "restore the newest": it is an
// operator who moved the port three times chasing a conflict and wants the file
// from before any of it.
const keptBackups = 5

const commandTimeout = 60 * time.Second

func run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	// #nosec G204 -- fixed binary; every argument is a constant or a validated
	// port number rendered by this package.
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// Ports is what the server is running on right now.
type Ports struct {
	Backend     int    `json:"backend"`
	BackendHost string `json:"backend_host"`
	External    int    `json:"external"`
}

// Current reads both ports out of the files that hold them.
//
// It never reads them from the panel's own table. A stored value that drifted
// from the file would send an operator to a port nothing answers on, which on
// this screen is the whole failure being guarded against.
func Current() (Ports, error) {
	var ports Ports

	envText, err := os.ReadFile(envPath()) // #nosec G304 -- fixed path, overridable only by the operator's own environment.
	if err != nil {
		return ports, refuse(ReasonUnreadable, "%s could not be read: %v", envPath(), err)
	}
	host, port, err := ParseListen(ReadEnvListen(string(envText)))
	if err != nil {
		return ports, refuse(ReasonNotFound, "%s does not set SERVIKA_LISTEN to an address with a port", envPath())
	}
	ports.BackendHost, ports.Backend = host, port

	vhostText, err := os.ReadFile(panelVhostPath()) // #nosec G304 -- fixed path.
	if err != nil {
		return ports, refuse(ReasonUnreadable, "%s could not be read: %v", panelVhostPath(), err)
	}
	ports.External = ReadNginxListenPort(string(vhostText))
	if ports.External == 0 {
		return ports, refuse(ReasonNotFound, "%s has no default_server listen line", panelVhostPath())
	}
	return ports, nil
}

// backupOne copies a file and returns the copy's path, pruning old generations.
//
// The name carries a random suffix rather than only a timestamp: two backups
// taken inside one tick of the platform's clock resolution would otherwise
// share a name, and the second would overwrite the copy the first one needs.
// That was measured in internal/optimize and is the same mistake here.
func backupOne(path string) (string, error) {
	content, err := os.ReadFile(path) // #nosec G304 -- one of the fixed paths above.
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(backupDir(), 0o700); err != nil {
		return "", err
	}
	var unique [6]byte
	// crypto/rand.Read is documented never to return an error and to always
	// fill its buffer, so there is no error path to add here.
	_, _ = rand.Read(unique[:])
	flat := strings.ReplaceAll(strings.TrimPrefix(path, "/"), "/", "_")
	name := fmt.Sprintf("%s.%s.%s.bak", flat,
		time.Now().UTC().Format("20060102-150405"), hex.EncodeToString(unique[:]))
	if name != filepath.Base(name) {
		return "", fmt.Errorf("refusing to write a backup named %q", name)
	}
	backup := filepath.Join(backupDir(), name)
	// #nosec G703 -- name carries no separator (asserted above) and backupDir() is
	// the panel's own directory, so the result cannot leave it.
	if err := os.WriteFile(backup, content, 0o600); err != nil {
		return "", err
	}
	pruneBackups(flat)
	return backup, nil
}

// pruneBackups keeps the newest generations of one file and deletes the rest.
// A failure here is not fatal: an extra copy on disk is harmless, and refusing
// the port change over it would be refusing the thing that was asked for.
func pruneBackups(prefix string) {
	entries, err := os.ReadDir(backupDir())
	if err != nil {
		return
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), prefix+".") {
			names = append(names, entry.Name())
		}
	}
	if len(names) <= keptBackups {
		return
	}
	// The timestamp is the second field and sorts lexicographically, so plain
	// string order is newest-last.
	sort.Strings(names)
	for _, name := range names[:len(names)-keptBackups] {
		_ = os.Remove(filepath.Join(backupDir(), name))
	}
}

// changeSet is one file that was rewritten, with the copy that undoes it.
type changeSet struct {
	Path   string `json:"path"`
	Backup string `json:"backup"`
}

// knownTarget reports whether a path is one of the three files this package
// rewrites.
//
// Every write goes through it. The paths all come from this package's own
// constants today, so nothing can currently fail it; the check is what makes
// that a PROPERTY rather than a fact about the current callers. A rollback
// reads its paths out of a change set that a detached helper also holds on
// disk, and anything on disk outlives the code that wrote it.
func knownTarget(path string) bool {
	return path == envPath() || path == panelVhostPath() || path == panelDomainVhostPath()
}

// writeFilePreservingMode replaces a file, keeping the mode it had.
func writeFilePreservingMode(path, content string) error {
	if !knownTarget(path) {
		return fmt.Errorf("%s is not a file this package manages", path)
	}
	mode := os.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	// #nosec G306 G703 -- knownTarget restricted path to this package's own
	// three files; a configuration file its daemon must read, whose existing
	// mode is preserved, and no secret is introduced by this write.
	return os.WriteFile(path, []byte(content), mode)
}

// restoreAll puts every backup back. It reports the FIRST failure and keeps
// going, because a half-restored server is worse than a fully restored one and
// stopping at the first problem guarantees the half.
func restoreAll(changes []changeSet) error {
	var failures []string
	for _, change := range changes {
		if change.Backup == "" {
			continue
		}
		content, err := os.ReadFile(change.Backup) // #nosec G304 -- path produced by backupOne under the panel's own directory.
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", change.Path, err))
			continue
		}
		if err := writeFilePreservingMode(change.Path, string(content)); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", change.Path, err))
		}
	}
	if len(failures) > 0 {
		return refuse(ReasonRollbackFailed, "could not put back: %s", strings.Join(failures, "; "))
	}
	return nil
}

// Outcome is what the detached helper leaves behind.
//
// The helper cannot write to the panel's database: doing so would put the DSN
// on a root script's disk for the sake of one row. It writes this file instead,
// and the panel folds it into panel_port_history when it comes back up.
type Outcome struct {
	HistoryID   int64  `json:"history_id"`
	Kind        string `json:"kind"`
	OldPort     int    `json:"old_port"`
	NewPort     int    `json:"new_port"`
	State       string `json:"state"` // running | succeeded | rolled_back | rollback_failed
	Error       string `json:"error,omitempty"`
	FinishedUTC string `json:"finished_utc,omitempty"`
}

// Outcome states.
const (
	StateRunning        = "running"
	StateSucceeded      = "succeeded"
	StateRolledBack     = "rolled_back"
	StateRollbackFailed = "rollback_failed"
)

// ReadOutcome returns what the last detached change reported, if anything.
func ReadOutcome() (Outcome, bool) {
	raw, err := os.ReadFile(outcomePath()) // #nosec G304 -- fixed path.
	if err != nil {
		return Outcome{}, false
	}
	var outcome Outcome
	if err := json.Unmarshal(raw, &outcome); err != nil {
		return Outcome{}, false
	}
	return outcome, true
}

// WriteOutcome records what a change is doing or did.
func WriteOutcome(outcome Outcome) error {
	raw, err := json.Marshal(outcome)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outcomePath()), 0o700); err != nil {
		return err
	}
	return os.WriteFile(outcomePath(), raw, 0o600)
}

// ClearOutcome removes the record once the panel has folded it into the table.
func ClearOutcome() {
	if err := os.Remove(outcomePath()); err != nil && !os.IsNotExist(err) {
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		complain("clear panel port outcome: %v", err)
	}
}
