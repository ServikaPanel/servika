package antivirus

// The real-time watcher.
//
// It answers "-av-watch" on this same binary, exactly as the scan worker and the
// port reporter do, and for the same reason: a second binary would carry a
// second copy of the rule set, and an update that installed one and failed on
// the other would leave a watcher enforcing rules the panel no longer ships.
//
// It differs from the scan worker in ONE respect that is worth stating plainly,
// because that worker deliberately carries no database connection: the worker
// hands its findings back to its parent through a file, and a long-running
// watcher has no parent to hand anything to. So this one opens the database,
// reads the settings and writes its own findings. It still answers before
// config.Load, because watching files is not a reason to need the JWT secret,
// which is the same argument the port reporter makes.
//
// What it does NOT do is decide anything new. The rules, the thresholds, the
// containment sequence and the owner resolution are the ones the sweep already
// uses.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"servika/internal/avsettings"
	"servika/internal/chains"
	"servika/internal/config"
	"servika/internal/db"
)

const watchFlag = "av-watch"

// settingsRefresh is how often the watcher re-reads av_settings.
//
// A threshold or a layer changed on the settings screen has to reach a process
// that may have been running for weeks, and restarting the watcher to apply one
// is a window in which nothing is watched at all.
const settingsRefresh = time.Minute

// RunWatcherIfAsked answers "-av-watch" and reports whether it did.
func RunWatcherIfAsked() bool {
	if len(os.Args) < 2 || (os.Args[1] != "-"+watchFlag && os.Args[1] != "--"+watchFlag) {
		return false
	}
	if err := runWatcher(); err != nil {
		fmt.Fprintf(os.Stderr, "antivirus watcher: %v\n", err)
		os.Exit(1)
	}
	return true
}

// errWatchDisabled ends the watcher with a zero exit status, so systemd's
// Restart=on-failure does not bring it straight back.
var errWatchDisabled = errors.New("real-time watching is off in the antivirus settings")

func runWatcher() error {
	dsn := strings.TrimSpace(os.Getenv("SERVIKA_DB_DSN"))
	if dsn == "" {
		return errors.New("SERVIKA_DB_DSN is required")
	}
	handle, err := db.Open(dsn)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer func() { _ = handle.Close() }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// The signed rule package the panel last verified, if there is one. The
	// watcher does not fetch: its unit is sandboxed for reading tenant trees,
	// and the panel is the only process that writes this file. A failure leaves
	// the built-in set running, so it is reported and not fatal.
	if err := LoadRulesFromDisk(); err != nil && !errors.Is(err, ErrRuleKeyAbsent) && !os.IsNotExist(err) {
		log.Printf("antivirus watcher: packaged rules not in use: %v", err)
	}

	w, err := newWatcher(ctx, handle)
	if err != nil {
		if errors.Is(err, errWatchDisabled) {
			log.Print("antivirus watcher: real-time watching is off in the antivirus settings")
			return nil
		}
		return err
	}
	if err := w.run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		if errors.Is(err, errWatchDisabled) {
			log.Print("antivirus watcher: real-time watching is off in the antivirus settings")
			return nil
		}
		return err
	}
	return nil
}

type watcher struct {
	db    *sql.DB
	owner *ownerLookup

	mu       sync.Mutex
	settings avsettings.Settings

	// cgroup is read once from this process's own /proc/self/cgroup, so what is
	// recorded is what the kernel put the watcher in rather than what the unit
	// asked for. This is the same distinction av_scans.confined exists for.
	cgroup string
}

func newWatcher(ctx context.Context, handle *sql.DB) (*watcher, error) {
	settings, err := avsettings.Read(ctx, handle)
	if err != nil {
		return nil, fmt.Errorf("antivirus settings: %w", err)
	}
	if !settings.Realtime {
		return nil, errWatchDisabled
	}
	// The unit hardens the watcher with ProtectSystem=strict and names the
	// quarantine store in ReadWritePaths. That name is the SHIPPED default, and
	// SERVIKA_QUARANTINE_DIR can move the store somewhere the unit does not
	// name, where every containment would fail one at a time with nothing
	// saying why. Ask once, at startup, where it can be answered plainly.
	reportQuarantineWritable()

	return &watcher{
		db:       handle,
		owner:    newOwnerLookup(handle),
		settings: settings,
		cgroup:   selfCgroup(),
	}, nil
}

// reportQuarantineWritable logs whether the watcher can actually write to the
// quarantine store. It does NOT refuse: detection is worth having even when
// containment is not available, and a watcher that refused to start would take
// the detection away too.
func reportQuarantineWritable() {
	dir := config.QuarantineDir()
	// #nosec G301 -- the quarantine store holds files taken out of a tenant tree; 0700 root keeps every tenant out of it.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Printf("antivirus watcher: the quarantine store %s cannot be created, "+
			"so containment will fail: %v", dir, err)
		return
	}
	probe, err := os.CreateTemp(dir, ".writable-")
	if err != nil {
		log.Printf("antivirus watcher: the quarantine store %s is not writable, "+
			"so containment will fail. Under ProtectSystem=strict the unit must "+
			"name this path in ReadWritePaths: %v", dir, err)
		return
	}
	name := probe.Name()
	_ = probe.Close()
	_ = os.Remove(name)
}

func (w *watcher) current() avsettings.Settings {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.settings
}

// refresh re-reads the settings. A read that FAILS keeps the settings the
// watcher already has: a database hiccup must not silently turn a detection
// layer off, which is the opposite of what a watcher exists to do.
func (w *watcher) refresh(ctx context.Context) error {
	settings, err := avsettings.Read(ctx, w.db)
	if err != nil {
		log.Printf("antivirus watcher: settings could not be re-read, keeping the current ones: %v", err)
		return nil
	}
	if !settings.Realtime {
		return errWatchDisabled
	}
	w.mu.Lock()
	w.settings = settings
	w.mu.Unlock()
	return nil
}

// watchable reports whether a path is worth opening at all.
//
// Only what a server EXECUTES or serves is inspected. Watching every file turns
// a WordPress cache directory into an event storm, and a webshell cannot be a
// .jpg because nothing executes it; a .jpg.php is caught by the double
// extension rule, which reads the path rather than the content.
func watchable(path string) bool {
	if base := filepath.Base(path); base == ".htaccess" || base == ".user.ini" {
		return true
	}
	return readLimitFor(strings.ToLower(filepath.Ext(path))) > 0
}

// inspect reads a file the kernel has just told us was closed after writing,
// and records a finding when it clears the threshold.
//
// The content comes from the fanotify event's OWN descriptor rather than from a
// second open by path. The path is in a directory a tenant writes to, so
// re-opening it means resolving every component again as root, and the file
// that answers is not necessarily the one the event was about. The descriptor
// is the object itself and cannot be swapped.
func (w *watcher) inspect(ctx context.Context, path string, read func(limit int64) ([]byte, error)) {
	settings := w.current()
	if avsettings.PathExcluded(settings.ExcludedList(), path) {
		return
	}
	ext := strings.ToLower(filepath.Ext(path))
	limit := readLimitFor(ext)
	if !settings.RuleEngine {
		limit = 0
	}

	// Location rules are judged against the TENANT HOME.
	//
	// What the root decides is the HIDDEN-directory rule, and it decides it in
	// one direction only: a root that itself sits under a dotted directory
	// leaves nothing dotted in the relative path, so every file under it looks
	// ordinary. The tenant home never contains a dot, which is exactly why it
	// is the root to use. The uploads, cache and well-known rules test the
	// relative path with Contains and would answer the same from any root
	// above the file, so they are not what this choice is about.
	var matches []match
	if settings.LocationHeuristics {
		if user, ok := systemUserFromPath(path); ok {
			matches = locationMatches(homePrefix+user, path)
		}
	}
	if limit == 0 && len(matches) == 0 {
		return
	}
	if limit > 0 {
		body, err := read(limit)
		if err == nil {
			matches = append(matches, evaluate(ext, body)...)
		}
	}
	score, signature, matched, level := verdict(matches, settings.CriticalThreshold)
	if level == "" {
		return
	}
	w.record(ctx, settings, Finding{
		File: path, Signature: signature, Engine: "heuristic",
		Score: score, Level: level, Rules: strings.Join(matched, ", "),
	})
}

// record writes one detection.
//
// Each detection gets its OWN av_scans row, scope 'realtime'. A single row held
// open for the watcher's lifetime would sit at status 'running' for weeks and
// HealRunningScans would mark it failed at the next panel restart, reporting
// every real-time detection as a scan that broke. A finished row per detection
// also carries its own timestamp, which is the thing an operator reads.
func (w *watcher) record(ctx context.Context, settings avsettings.Settings, finding Finding) {
	domainID := w.owner.forPath(finding.File)
	confined := avsettings.Confined(w.cgroup)

	result, err := w.db.ExecContext(ctx,
		`INSERT INTO av_scans (domain_id, scope, status, scanned, infected, engine, confined, source, finished_at)
		 VALUES (?,?,?,?,?,?,?,?,NOW())`,
		domainID, "realtime", "finished", 1, 1, "heuristic", confined, SourceRealtime)
	if err != nil {
		log.Printf("antivirus watcher: the detection could not be recorded: %v", err)
		return
	}
	sid, err := result.LastInsertId()
	if err != nil {
		log.Printf("antivirus watcher: the detection row could not be identified: %v", err)
		return
	}
	if err := insertSweepFinding(w.db, sid, domainID, finding); err != nil {
		log.Printf("antivirus watcher: the finding could not be recorded: %v", err)
		return
	}
	log.Printf("antivirus watcher: %s %s (score %d) %s",
		finding.Level, finding.Signature, finding.Score, finding.File)

	contained := false
	if settings.AutoQuarantine {
		out := (&Handlers{DB: w.db}).autoQuarantine(ctx, sid)
		recordAutoQuarantine(w.db, sid, out)
		contained = out.Taken > 0
	}
	// The alert says whether the file was taken away, because "we found it" and
	// "we found it and it is gone" ask different things of the reader.
	notifyRealtime(ctx, w.db, sid, domainID, contained)

	// Attack-chain event: a malicious file written now is the File Write stage.
	// The correlator joins it with a live process detection into a chain.
	if domainID.Valid && domainID.Int64 > 0 {
		chains.WriteEvent(w.db, domainID.Int64, "file", "file_write", "critical",
			filepath.Base(finding.File), "av_scan", sid)
	}
}
