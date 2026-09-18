package platform

// The installation catalog: what can be put on this server, and what is being
// put on it right now.
//
// An installation runs ASYNCHRONOUSLY. The HTTP request answers with a job id
// immediately and progress is polled from the job's log, because a package like
// SQL Express can take fifteen minutes and no HTTP client waits that long.
//
// THE TIER IS SHOWN TO THE OPERATOR AS IT IS. "proven" means a path that has
// been seen to work; "experimental" means one that has not been tried across
// the fleet; "undecided" means it CANNOT be installed, because putting an
// install button next to a problem nobody has solved would be a lie.
//
// This file carries no build tag: the catalog, the job model and the
// single-flight rule are all OS-independent and are measured on every build.
// Detecting what is installed and running an installer live in
// catalog_windows.go.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Tiers, shown to the operator verbatim.
const (
	TierProven       = "proven"
	TierExperimental = "experimental"
	TierUndecided    = "undecided"
)

// Job states.
const (
	JobRunning = "running"
	JobDone    = "done"
	JobFailed  = "failed"
	JobCut     = "cut"     // an agent restart cut the installation short
	JobPartial = "partial" // the steps passed but the result needs more configuration
)

const (
	// logLines is how many lines one job keeps. The install log is for watching
	// a run, not an archive, so the oldest lines are dropped past this.
	logLines = 500
)

// ErrInstallRunning means the single-flight rule refused a second installation.
var ErrInstallRunning = errors.New("another installation is running")

// ErrNotInstallable means the item cannot be installed as things stand: it is
// unknown, already installed, or undecided.
var ErrNotInstallable = errors.New("that cannot be installed")

// ErrPartialInstall means the installer's steps ran WITHOUT error but the
// result is NOT complete and needs more configuration. A job carrying this is
// marked partial rather than done, so nothing reports a readiness that is not
// there.
var ErrPartialInstall = errors.New("the installation is partial and needs more configuration")

// ErrInstallPending means the agent restarted before a previous installation
// finished and its marker is still on disk. New installations are refused until
// an operator clears it.
var ErrInstallPending = errors.New("a previous installation was left half-finished")

// Item is one installable piece of software. Capability is the discovery bit
// expected to light up afterwards, and it is used to detect installation too.
type Item struct {
	Key        string
	Name       string
	Summary    string
	Tier       string
	TimeToRun  string
	Capability Capability
}

// catalog is everything this agent can install.
//
// The order is the order the operator sees, and it is deliberate: the web
// server first, then the pieces a site needs, then the databases, then the
// tools. An item whose tier is TierUndecided is listed so the operator knows it
// exists and is NOT offered, because hiding it would only make someone install
// it by hand.
var catalog = []Item{
	{Key: "iis", Name: "IIS", Summary: "The web server, with the management tools and the URL rewrite prerequisites", Tier: TierProven, TimeToRun: "2-4 minutes", Capability: CapSite},
	{Key: "urlrewrite", Name: "URL Rewrite", Summary: "The IIS module a framework's clean URLs need", Tier: TierProven, TimeToRun: "1 minute"},
	{Key: "dotnet", Name: ".NET Hosting Bundle", Summary: "Runs an ASP.NET Core site behind IIS", Tier: TierProven, TimeToRun: "2-3 minutes", Capability: CapDotNet},
	{Key: "ssl", Name: "win-acme", Summary: "Issues and renews a free Let's Encrypt certificate", Tier: TierProven, TimeToRun: "1 minute", Capability: CapSSL},
	{Key: "ftp", Name: "FTP Server", Summary: "The IIS FTP service, for file transfer over FTPS", Tier: TierProven, TimeToRun: "1-2 minutes", Capability: CapFTP},
	{Key: "dns", Name: "DNS Server", Summary: "The Windows DNS role, for hosting a zone on this machine", Tier: TierExperimental, TimeToRun: "2-3 minutes", Capability: CapDNS},
	{Key: "quota", Name: "File Server Resource Manager", Summary: "Enforces a disk quota per site; without it a plan's disk limit is not applied", Tier: TierProven, TimeToRun: "2-3 minutes", Capability: CapQuota},
	{Key: "mssql", Name: "SQL Server Express", Summary: "The database engine, with sqlcmd for managing it", Tier: TierProven, TimeToRun: "10-15 minutes", Capability: CapMSSQL},
	{Key: "mysql", Name: "MySQL", Summary: "The database engine; the agent does not keep its administrator password, so it is managed by hand afterwards", Tier: TierExperimental, TimeToRun: "5-8 minutes", Capability: CapMySQL},
	{Key: "pgsql", Name: "PostgreSQL", Summary: "The database engine; the agent does not keep its administrator password, so it is managed by hand afterwards", Tier: TierExperimental, TimeToRun: "5-8 minutes", Capability: CapPostgreSQL},
	{Key: "phpmyadmin", Name: "phpMyAdmin", Summary: "The web interface for MySQL; needs PHP and MySQL first", Tier: TierExperimental, TimeToRun: "2 minutes"},
	{Key: "node", Name: "Node.js LTS", Summary: "The runtime an application written in JavaScript needs", Tier: TierProven, TimeToRun: "2-3 minutes"},
	{Key: "git", Name: "Git", Summary: "Deploys a site from a repository", Tier: TierProven, TimeToRun: "1-2 minutes"},
	{Key: "redis", Name: "Memurai", Summary: "The Redis-compatible cache for Windows; there is no official Redis build for this platform", Tier: TierExperimental, TimeToRun: "1-2 minutes"},
}

// Catalog returns the catalog rows with what is installed marked.
func Catalog(installed func(Item) bool) []Entry { return entriesFor(catalog, installed) }

// Entry is one row of the catalog answer. The capability bit is an internal
// detail and is deliberately NOT carried out of here.
type Entry struct {
	Key         string
	Name        string
	Summary     string
	Tier        string
	TimeToRun   string
	Installed   bool
	Installable bool
}

// entriesFor shapes the catalog for an answer, asking the caller which items
// are installed. Taking that as a function is what makes this testable without
// a Windows host.
func entriesFor(items []Item, installed func(Item) bool) []Entry {
	entries := make([]Entry, 0, len(items))
	for _, item := range items {
		on := installed(item)
		entries = append(entries, Entry{
			Key:         item.Key,
			Name:        item.Name,
			Summary:     item.Summary,
			Tier:        item.Tier,
			TimeToRun:   item.TimeToRun,
			Installed:   on,
			Installable: !on && item.Tier != TierUndecided,
		})
	}
	return entries
}

// findItem returns the catalog item with the given key.
func findItem(items []Item, key string) (Item, bool) {
	for _, item := range items {
		if item.Key == key {
			return item, true
		}
	}
	return Item{}, false
}

// Progress is the machine-readable side of a running job, alongside the text
// log, so the panel can draw a live bar.
//
// There are two stages. While downloading, the byte counts are real and a
// percentage, speed and estimate can be computed when the length is known.
// While installing, the duration GENUINELY cannot be estimated, so Percent is
// -1 for unknown. Showing an invented estimate would be the same mistake as
// reporting a success that did not happen.
type Progress struct {
	Stage       string `json:"stage"` // "downloading" | "installing" | ""
	Label       string `json:"label"`
	BytesDone   int64  `json:"bytes_done"`
	BytesTotal  int64  `json:"bytes_total"` // 0 when unknown
	Percent     int    `json:"percent"`     // 0..100, or -1 for unknown
	BytesPerSec int64  `json:"bytes_per_sec"`
	SecondsLeft int    `json:"seconds_left"` // -1 when unknown
}

// Job is the live record of one installation run.
type Job struct {
	ID      string
	Key     string
	Started time.Time

	// mu guards everything below: the installer goroutine writes and the HTTP
	// side reads.
	mu       sync.Mutex
	state    string
	log      []string
	progress Progress
	// secret carries a one-off sensitive output, such as a generated superuser
	// password. It is NEVER written to the log: a log stays in the scrollback
	// and would show the value again on every visit. The panel shows this once,
	// in its own field.
	secret string
}

// setProgress records the structured progress.
func (j *Job) setProgress(p Progress) {
	j.mu.Lock()
	j.progress = p
	j.mu.Unlock()
}

// setSecret records a one-off sensitive output.
func (j *Job) setSecret(value string) {
	j.mu.Lock()
	j.secret = value
	j.mu.Unlock()
}

// Logf appends one timestamped line, dropping the oldest past the ceiling.
func (j *Job) Logf(format string, args ...any) {
	line := time.Now().Format("15:04:05") + " " + fmt.Sprintf(format, args...)
	j.mu.Lock()
	defer j.mu.Unlock()
	j.log = append(j.log, line)
	if len(j.log) > logLines {
		// Copied into a fresh slice so the dropped head's memory is returned.
		j.log = append([]string(nil), j.log[len(j.log)-logLines:]...)
	}
}

// setState records the job's outcome.
func (j *Job) setState(state string) {
	j.mu.Lock()
	j.state = state
	j.mu.Unlock()
}

// JobView is a snapshot a caller can hold safely.
type JobView struct {
	ID       string
	Key      string
	State    string
	Finished bool
	Log      []string
	Progress Progress
	Secret   string // one-off sensitive output; never in the log
}

// view copies the job's current state.
func (j *Job) view() JobView {
	j.mu.Lock()
	defer j.mu.Unlock()
	return JobView{
		ID:       j.ID,
		Key:      j.Key,
		State:    j.state,
		Finished: j.state != JobRunning,
		Log:      append([]string(nil), j.log...),
		Progress: j.progress,
		Secret:   j.secret,
	}
}

// marker is what is written to disk while an installation runs.
type marker struct {
	ID      string    `json:"id"`
	Key     string    `json:"key"`
	Started time.Time `json:"started"`
}

// Installer runs at most one installation at a time and survives a restart
// knowing it did.
//
// ONE AT A TIME, AND THE LOCK IS ON DISK AS WELL AS IN MEMORY. Two dism or MSI
// installations at once deadlock the Windows Installer and CBS and can leave
// the system half-installed. An in-memory flag alone is not enough: on Windows
// a child installer does NOT die when its parent does, so an agent restart
// leaves msiexec running while the flag resets, the operator tries again, and
// two installations collide. So a marker is written when a run starts and
// removed when it ends; a marker found at startup means the previous run was
// cut short and new runs are refused until an operator clears it.
//
// A second request is never QUEUED. It is refused outright, so the operator
// knows what is happening instead of waiting in a hidden line.
type Installer struct {
	MarkerPath string

	mu       sync.Mutex
	jobs     map[string]*Job
	activeID string
	pending  *marker
}

// NewInstaller creates one with its marker at the given path.
func NewInstaller(markerPath string) *Installer {
	return &Installer{MarkerPath: markerPath, jobs: map[string]*Job{}}
}

// writeMarker records that a run is in progress.
func (in *Installer) writeMarker(id, key string) {
	b, err := json.Marshal(marker{ID: id, Key: key, Started: time.Now()})
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(in.MarkerPath), 0o755)
	_ = os.WriteFile(in.MarkerPath, b, 0o644)
}

// clearMarker removes it.
func (in *Installer) clearMarker() { _ = os.Remove(in.MarkerPath) }

// LoadPending runs at agent startup.
//
// A marker on disk means the previous installation was cut short. The job is
// recreated in the "cut" state so the panel does not sit at 0 of 1 for ever,
// and the pending record is filled so Start refuses. THE MARKER IS NOT REMOVED
// HERE: an operator clears it deliberately, after making sure no installer is
// still running.
func (in *Installer) LoadPending() {
	b, err := os.ReadFile(in.MarkerPath)
	if err != nil {
		return
	}
	var m marker
	if json.Unmarshal(b, &m) != nil || m.Key == "" {
		m.Key = "unknown" // A corrupt marker still counts as pending.
	}
	in.mu.Lock()
	in.pending = &m
	if m.ID != "" {
		job := &Job{ID: m.ID, Key: m.Key, Started: m.Started, state: JobCut}
		in.jobs[m.ID] = job
		in.mu.Unlock()
		job.Logf("the agent restarted and this installation was CUT SHORT; make sure no installer is still running, then clear the lock")
		return
	}
	in.mu.Unlock()
}

// Pending reports whether an installation was left half-finished, and for what.
func (in *Installer) Pending() (bool, string) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.pending == nil {
		return false, ""
	}
	return true, in.pending.Key
}

// ClearPending is the operator's acknowledgement: it drops the marker and lets
// installations start again.
func (in *Installer) ClearPending() {
	in.mu.Lock()
	in.pending = nil
	in.mu.Unlock()
	in.clearMarker()
}

// JobStatus returns a snapshot of one job.
func (in *Installer) JobStatus(id string) (JobView, bool) {
	in.mu.Lock()
	job := in.jobs[id]
	in.mu.Unlock()
	if job == nil {
		return JobView{}, false
	}
	return job.view(), true
}

// claim takes the single-flight slot for a new job, or reports why it cannot.
func (in *Installer) claim(id, key string) (*Job, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.pending != nil {
		return nil, fmt.Errorf("a previous installation (%s) was left half-finished; make sure no installer is running and clear the lock: %w", in.pending.Key, ErrInstallPending)
	}
	if in.activeID != "" {
		return nil, fmt.Errorf("the job %q is running: %w", in.activeID, ErrInstallRunning)
	}
	job := &Job{ID: id, Key: key, Started: time.Now(), state: JobRunning}
	in.jobs[id] = job
	in.activeID = id
	return job, nil
}

// release frees the single-flight slot.
func (in *Installer) release() {
	in.mu.Lock()
	in.activeID = ""
	in.mu.Unlock()
}

// outcomeOf turns an installer's error into the job state it deserves.
func outcomeOf(err error) string {
	switch {
	case err == nil:
		return JobDone
	case errors.Is(err, ErrPartialInstall):
		return JobPartial
	}
	return JobFailed
}

// run performs one installation and settles the job.
//
// A PANIC INSIDE AN INSTALLER MUST NOT TAKE THE AGENT DOWN. One item's
// installation failing should not stop the running sites or the agent's own
// API, so a panic is caught and turned into a failed job. The cleanup then runs
// in EVERY case, because a missed release would hold the single-flight lock
// closed for ever.
func (in *Installer) run(job *Job, item Item, install func(*Job) error, afterEach func()) {
	defer func() {
		in.release()
		in.clearMarker()
	}()
	err := runGuarded(job, item, install)
	switch {
	case err == nil:
		job.Logf("installation finished: %s", item.Name)
	case errors.Is(err, ErrPartialInstall):
		job.Logf("INSTALLATION PARTIAL: %v", err)
	default:
		job.Logf("INSTALLATION FAILED: %v", err)
	}
	if afterEach != nil {
		afterEach()
	}
	// The state changes LAST, so a client that sees "finished" already has the
	// closing log lines in front of it.
	job.setState(outcomeOf(err))
}

// runGuarded calls the installer with a panic guard.
func runGuarded(job *Job, item Item, install func(*Job) error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("the installer panicked and was isolated: %v", r)
			job.Logf("INSTALLER PANIC - isolated, the agent is still up: %v", r)
		}
	}()
	job.Logf("installation started: %s [%s]", item.Name, item.Tier)
	return install(job)
}

// logWriter turns a command's output into log lines as they arrive.
//
// Only one goroutine writes to a running command's pipes, so the partial-line
// buffer needs no lock of its own.
type logWriter struct {
	job  *Job
	rest []byte
}

func (w *logWriter) Write(p []byte) (int, error) {
	w.rest = append(w.rest, p...)
	for {
		at := bytes.IndexByte(w.rest, '\n')
		if at < 0 {
			break
		}
		line := strings.TrimSpace(strings.TrimRight(string(w.rest[:at]), "\r"))
		w.rest = w.rest[at+1:]
		if line != "" {
			w.job.Logf("  %s", line)
		}
	}
	return len(p), nil
}

// flush writes the last partial line once the command has ended.
func (w *logWriter) flush() {
	if line := strings.TrimSpace(string(w.rest)); line != "" {
		w.job.Logf("  %s", line)
	}
	w.rest = nil
}
